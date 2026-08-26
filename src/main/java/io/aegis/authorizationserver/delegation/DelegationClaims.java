package io.aegis.authorizationserver.delegation;

import io.aegis.commons.audit.DelegationChain;
import io.aegis.commons.audit.DelegationHop;
import io.aegis.commons.audit.PrincipalType;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Translates between Aegis's {@link DelegationChain} and RFC 8693's {@code act} / {@code may_act}
 * claims.
 *
 * <p><b>The two orders are opposites, which is the whole reason this class exists.</b> A
 * {@code DelegationChain} is stored <em>root-first</em> ({@code hops[0]} is the human). The
 * {@code act} claim nests with the <em>nearest</em> actor outermost. Doing this translation inline
 * at each call site is how the chain ends up silently reversed, and a reversed chain attributes an
 * action to the wrong principal — which is worse than having no chain at all.
 *
 * <p>Throughout, {@code sub} is the root of the chain and never changes; only the actor chain grows.
 */
public final class DelegationClaims {

    private static final String SUB = "sub";
    private static final String ACT = "act";

    private DelegationClaims() {
    }

    /** The root, accountable principal — what belongs in {@code sub}. */
    public static String subjectOf(DelegationChain chain) {
        return chain == null ? null : chain.root().map(DelegationHop::principal).orElse(null);
    }

    /**
     * Build the nested {@code act} claim, or {@code null} when there are no actors beyond the
     * subject (a human acting directly has no {@code act} claim at all).
     */
    public static Map<String, Object> toActClaim(DelegationChain chain) {
        if (chain == null || chain.depth() < 2) {
            return null;
        }
        Map<String, Object> act = null;
        // Walk actors root-side first, wrapping each time, so the LAST actor ends up outermost.
        for (DelegationHop hop : chain.hops().subList(1, chain.depth())) {
            Map<String, Object> next = new LinkedHashMap<>();
            next.put(SUB, hop.principal());
            if (act != null) {
                next.put(ACT, act);
            }
            act = next;
        }
        return act;
    }

    /** Rebuild a chain from a token's {@code sub} and {@code act} claims. */
    public static DelegationChain fromClaims(String subject, Map<String, Object> actClaim) {
        List<DelegationHop> hops = new ArrayList<>();
        if (subject != null && !subject.isBlank()) {
            hops.add(new DelegationHop(subject, PrincipalType.HUMAN, null, Instant.now(), Set.of()));
        }

        // Unwrap outward-in, collecting nearest-first, then reverse to restore root-first order.
        List<String> actors = new ArrayList<>();
        Map<String, Object> current = actClaim;
        while (current != null) {
            Object sub = current.get(SUB);
            if (!(sub instanceof String principal) || principal.isBlank()) {
                throw new IllegalArgumentException("malformed act claim: missing 'sub'");
            }
            actors.add(principal);
            Object nested = current.get(ACT);
            current = nested instanceof Map<?, ?> map ? castClaims(map) : null;
        }
        for (int i = actors.size() - 1; i >= 0; i--) {
            hops.add(new DelegationHop(actors.get(i), PrincipalType.AGENT, null, Instant.now(), Set.of()));
        }
        return new DelegationChain(hops);
    }

    /** Build a {@code may_act} claim pre-authorizing {@code principal} to exchange the token. */
    public static Map<String, Object> toMayActClaim(String principal) {
        Map<String, Object> mayAct = new LinkedHashMap<>();
        mayAct.put(SUB, principal);
        return mayAct;
    }

    /**
     * Whether {@code actor} is permitted by a {@code may_act} claim.
     *
     * <p>An <b>absent</b> {@code may_act} does not restrict the exchange. RFC 8693 defines it as an
     * optional pre-authorization, so absent means "unconstrained by this mechanism", not "deny" —
     * the real authority checks are scope narrowing and client policy. Reading absent as deny would
     * break every ordinary exchange, and reading present-but-mismatched as allow would make the
     * claim decorative.
     */
    public static boolean mayAct(Map<String, Object> mayActClaim, String actor) {
        if (mayActClaim == null || mayActClaim.isEmpty()) {
            return true;
        }
        return mayActClaim.get(SUB) instanceof String allowed && allowed.equals(actor);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castClaims(Map<?, ?> map) {
        return (Map<String, Object>) map;
    }
}
