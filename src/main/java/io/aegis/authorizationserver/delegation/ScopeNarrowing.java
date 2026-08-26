package io.aegis.authorizationserver.delegation;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Enforces that authority only ever <b>narrows</b> across a token exchange.
 *
 * <p>This is the control that defeats <b>delegation laundering</b> — the agent-native
 * privilege-escalation primitive, in which a low-privilege agent delegates to a high-privilege one
 * and receives back a result it could never have obtained directly. Because the escalation happens
 * through an entirely legitimate-looking exchange, it must be refused at the exchange itself; there
 * is no later point at which the request looks wrong.
 */
public final class ScopeNarrowing {

    private ScopeNarrowing() {
    }

    /**
     * @param subjectScopes   scopes carried by the subject token being exchanged
     * @param requestedScopes scopes requested for the new token
     */
    public static Result check(Set<String> subjectScopes, Set<String> requestedScopes) {
        Set<String> held = subjectScopes == null ? Set.of() : subjectScopes;
        Set<String> wanted = requestedScopes == null ? Set.of() : requestedScopes;

        Set<String> escalated = new LinkedHashSet<>(wanted);
        escalated.removeAll(held);
        return new Result(escalated.isEmpty(), Set.copyOf(escalated));
    }

    /**
     * @param permitted whether the request stayed within the subject token's authority
     * @param escalated the scopes that exceeded it — named rather than merely counted, so the audit
     *                  event and the resulting alert can say what was attempted
     */
    public record Result(boolean permitted, Set<String> escalated) {
    }
}
