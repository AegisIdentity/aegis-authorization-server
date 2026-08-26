package io.aegis.authorizationserver.delegation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.aegis.commons.audit.DelegationChain;
import io.aegis.commons.audit.DelegationHop;
import io.aegis.commons.audit.PrincipalType;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * RFC 8693 {@code act} claim mapping.
 *
 * <p>The invariant: {@code sub} never changes down a delegation chain while {@code act} nests, with
 * the <b>nearest</b> actor outermost. Aegis's {@link DelegationChain} is stored root-first, so this
 * class owns the (easy to get backwards) translation between the two orders.
 */
class DelegationClaimsTest {

    private static DelegationHop hop(String principal, PrincipalType type, String... scopes) {
        return new DelegationHop(principal, type, null, Instant.now(), Set.of(scopes));
    }

    private static DelegationChain aliceToResearcher() {
        return DelegationChain.of(
                hop("user:alice@acme", PrincipalType.HUMAN, "files:read"),
                hop("agent:planner", PrincipalType.AGENT, "files:read"),
                hop("agent:researcher", PrincipalType.AGENT, "files:read"));
    }

    @Test
    void subject_is_the_root_of_the_chain_never_the_acting_agent() {
        assertThat(DelegationClaims.subjectOf(aliceToResearcher())).isEqualTo("user:alice@acme");
    }

    @Test
    void act_nests_with_the_nearest_actor_outermost() {
        Map<String, Object> act = DelegationClaims.toActClaim(aliceToResearcher());

        assertThat(act.get("sub")).isEqualTo("agent:researcher");

        @SuppressWarnings("unchecked")
        Map<String, Object> inner = (Map<String, Object>) act.get("act");
        assertThat(inner.get("sub")).isEqualTo("agent:planner");
        assertThat(inner.get("act")).isNull();   // the human is `sub`, not an actor
    }

    @Test
    void a_chain_with_only_a_human_has_no_act_claim() {
        DelegationChain justAlice = DelegationChain.of(hop("user:alice@acme", PrincipalType.HUMAN, "files:read"));
        assertThat(DelegationClaims.toActClaim(justAlice)).isNull();
    }

    @Test
    void an_empty_chain_has_no_act_claim_and_no_subject() {
        assertThat(DelegationClaims.toActClaim(DelegationChain.empty())).isNull();
        assertThat(DelegationClaims.subjectOf(DelegationChain.empty())).isNull();
    }

    @Test
    void round_trips_a_chain_through_claims_without_reordering_it() {
        DelegationChain original = aliceToResearcher();
        DelegationChain restored = DelegationClaims.fromClaims(
                DelegationClaims.subjectOf(original), DelegationClaims.toActClaim(original));

        assertThat(restored.depth()).isEqualTo(3);
        assertThat(restored.root()).get().extracting(DelegationHop::principal).isEqualTo("user:alice@acme");
        assertThat(restored.effective()).get().extracting(DelegationHop::principal).isEqualTo("agent:researcher");
        assertThat(restored.hops().get(1).principal()).isEqualTo("agent:planner");
    }

    @Test
    void appending_a_hop_grows_the_actor_chain_and_leaves_the_subject_alone() {
        DelegationChain extended = aliceToResearcher()
                .append(hop("agent:summarizer", PrincipalType.AGENT, "files:read"));

        assertThat(DelegationClaims.subjectOf(extended)).isEqualTo("user:alice@acme");
        assertThat(DelegationClaims.toActClaim(extended).get("sub")).isEqualTo("agent:summarizer");
    }

    // --- may_act -------------------------------------------------------------------------------

    @Test
    void may_act_names_the_party_authorized_to_exchange_this_token() {
        assertThat(DelegationClaims.toMayActClaim("agent:planner"))
                .containsEntry("sub", "agent:planner");
    }

    @Test
    void may_act_permits_the_named_actor() {
        Map<String, Object> mayAct = DelegationClaims.toMayActClaim("agent:planner");
        assertThat(DelegationClaims.mayAct(mayAct, "agent:planner")).isTrue();
    }

    @Test
    void may_act_refuses_an_actor_it_does_not_name() {
        Map<String, Object> mayAct = DelegationClaims.toMayActClaim("agent:planner");
        assertThat(DelegationClaims.mayAct(mayAct, "agent:impostor")).isFalse();
    }

    @Test
    void an_absent_may_act_claim_does_not_restrict_exchange() {
        // RFC 8693: may_act is an OPTIONAL pre-authorization. Absent means "unconstrained by this
        // mechanism", NOT "deny" — the actual authority check is scope narrowing plus client policy.
        // Treating absent as deny would break every ordinary exchange.
        assertThat(DelegationClaims.mayAct(null, "agent:anyone")).isTrue();
    }

    @Test
    void a_malformed_act_claim_is_rejected_rather_than_partially_parsed() {
        assertThatThrownBy(() -> DelegationClaims.fromClaims("user:alice", Map.of("no-sub", "x")))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
