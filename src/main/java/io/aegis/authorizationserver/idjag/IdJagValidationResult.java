package io.aegis.authorizationserver.idjag;

/**
 * Outcome of validating a presented ID-JAG.
 *
 * <p>Typed so the failure reason reaches the audit event. {@link #WRONG_AUDIENCE} and
 * {@link #UNTRUSTED_ISSUER} are possible attacks and deserve an alert; {@link #EXPIRED} is routine
 * and simply means the client should fetch a new grant.
 */
public enum IdJagValidationResult {
    VALID,
    /** Minted for a different resource — the confused-deputy case. */
    WRONG_AUDIENCE,
    /** Signed by an IdP this server does not accept grants from. */
    UNTRUSTED_ISSUER,
    /** Not an ID-JAG at all — e.g. an access token being replayed at the token endpoint. */
    NOT_AN_ID_JAG,
    EXPIRED,
    NOT_YET_VALID,
    /** No subject, so there is nobody to link to a local account. */
    NO_SUBJECT
}
