package io.aegis.authorizationserver.idjag;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Validates a presented Identity Assertion JWT Authorization Grant.
 *
 * <p>Signature verification happens <em>before</em> this, in a {@code JwtDecoder}. What is left is
 * everything a valid signature does not prove — and that is most of what matters. A signature proves
 * only that <em>someone</em> signed the token; it says nothing about whether we accept grants from
 * that issuer, whether the grant was minted for us, whether it is still live, or whether it is even
 * an ID-JAG rather than an ordinary access token being replayed.
 */
public class IdJagAssertionValidator {

    /** The registered ID-JAG token type. */
    public static final String ID_JAG_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id-jag";

    private final Set<String> trustedIssuers;

    /**
     * @param trustedIssuers issuers this server accepts grants from. <b>Empty means trust nothing</b>
     *                       — without an allow-list, any IdP whose signing key we happen to be able
     *                       to fetch could mint grants for our resources.
     */
    public IdJagAssertionValidator(Set<String> trustedIssuers) {
        this.trustedIssuers = trustedIssuers == null ? Set.of() : Set.copyOf(trustedIssuers);
    }

    public IdJagValidationResult validate(Jwt assertion, String expectedResource, Instant now) {
        String issuer = assertion.getClaimAsString("iss");
        if (issuer == null || !trustedIssuers.contains(issuer)) {
            return IdJagValidationResult.UNTRUSTED_ISSUER;
        }

        // Checked explicitly so an ordinary access token audienced to this resource cannot be
        // presented at the token endpoint and swapped for a fresh one — a token-laundering
        // primitive that costs nothing to close and is invisible if you forget.
        if (!ID_JAG_TOKEN_TYPE.equals(assertion.getClaimAsString("token_type"))) {
            return IdJagValidationResult.NOT_AN_ID_JAG;
        }

        List<String> audience = assertion.getAudience();
        if (audience == null || !audience.contains(expectedResource)) {
            return IdJagValidationResult.WRONG_AUDIENCE;
        }

        Instant issuedAt = assertion.getIssuedAt();
        if (issuedAt != null && now.isBefore(issuedAt)) {
            return IdJagValidationResult.NOT_YET_VALID;
        }

        Instant expiresAt = assertion.getExpiresAt();
        // A missing exp is treated as expired, never as "never expires" — that is how a short-lived
        // grant quietly becomes a permanent key.
        if (expiresAt == null || !now.isBefore(expiresAt)) {
            return IdJagValidationResult.EXPIRED;
        }

        String subject = assertion.getSubject();
        if (subject == null || subject.isBlank()) {
            return IdJagValidationResult.NO_SUBJECT;
        }

        return IdJagValidationResult.VALID;
    }
}
