package io.aegis.authorizationserver.delegation;

/**
 * Outcome of validating an {@link IdJag} on the redeeming side.
 *
 * <p>Typed rather than boolean so the failure reason reaches the audit event: a wrong audience is a
 * possible attack and should be alerted on, while an expired grant is routine and should simply be
 * re-fetched.
 */
public enum IdJagValidation {
    VALID,
    EXPIRED,
    NOT_YET_VALID,
    WRONG_AUDIENCE
}
