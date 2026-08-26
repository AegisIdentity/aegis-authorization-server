package io.aegis.authorizationserver.delegation;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * The anti-delegation-laundering control (THREAT-MODEL, agent STRIDE "E").
 *
 * <p>Delegation laundering is the agent-native privilege-escalation primitive: a low-privilege agent
 * delegates to a high-privilege one and gets back a result it could never have obtained directly.
 * The invariant that defeats it is enforced here, at the exchange, rather than detected afterwards.
 */
class ScopeNarrowingTest {

    @Test
    void an_equal_scope_set_is_permitted() {
        assertThat(ScopeNarrowing.check(Set.of("files:read"), Set.of("files:read")).permitted()).isTrue();
    }

    @Test
    void a_narrower_scope_set_is_permitted() {
        assertThat(ScopeNarrowing.check(Set.of("files:read", "files:write"), Set.of("files:read")).permitted())
                .isTrue();
    }

    @Test
    void requesting_no_scopes_is_permitted() {
        assertThat(ScopeNarrowing.check(Set.of("files:read"), Set.of()).permitted()).isTrue();
    }

    @Test
    void a_wider_scope_set_is_refused_and_names_the_escalated_scopes() {
        ScopeNarrowing.Result result =
                ScopeNarrowing.check(Set.of("files:read"), Set.of("files:read", "admin:all"));

        assertThat(result.permitted()).isFalse();
        // Naming the offending scopes rather than returning a bare false is what lets the audit
        // event and the alert say what was actually attempted.
        assertThat(result.escalated()).containsExactly("admin:all");
    }

    @Test
    void an_entirely_different_scope_set_is_refused() {
        ScopeNarrowing.Result result = ScopeNarrowing.check(Set.of("files:read"), Set.of("payments:charge"));
        assertThat(result.permitted()).isFalse();
        assertThat(result.escalated()).containsExactly("payments:charge");
    }

    @Test
    void an_empty_subject_scope_set_can_only_yield_an_empty_request() {
        // A token with no scopes cannot confer any. This is the degenerate case that a naive
        // "if subject scopes are empty, skip the check" implementation gets catastrophically wrong.
        assertThat(ScopeNarrowing.check(Set.of(), Set.of()).permitted()).isTrue();
        assertThat(ScopeNarrowing.check(Set.of(), Set.of("files:read")).permitted()).isFalse();
    }

    @Test
    void null_inputs_are_treated_as_empty_not_as_unrestricted() {
        assertThat(ScopeNarrowing.check(null, Set.of("files:read")).permitted()).isFalse();
        assertThat(ScopeNarrowing.check(Set.of("files:read"), null).permitted()).isTrue();
    }
}
