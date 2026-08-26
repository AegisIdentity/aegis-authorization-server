package io.aegis.authorizationserver.delegation;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * An <b>Identity Assertion JWT Authorization Grant</b> — the token at the centre of MCP's
 * Enterprise-Managed Authorization extension.
 *
 * <p>The flow: a user signs in once at the enterprise IdP; the client exchanges that ID token for an
 * ID-JAG via RFC 8693 — <em>and the IdP evaluates tenant policy at that moment</em>; the client then
 * redeems the ID-JAG at the MCP authorization server via RFC 7523 for an access token. The user is
 * never redirected to the MCP server's own consent screen.
 *
 * <p>Why this matters commercially as well as technically: policy is evaluated <b>before any token
 * exists</b>, and revoking a user's access to every MCP server in an estate becomes one
 * control-plane action instead of N per-server revocations. The extension is stable and already
 * adopted by Okta, Microsoft Entra and Auth0.
 *
 * <p>Aegis plays both roles — issuer (enterprise IdP) and redeemer (MCP authorization server) —
 * because tenants need each independently.
 *
 * @param audience the <b>MCP resource</b> this grant is minted for (RFC 8707), never the client
 */
public record IdJag(
        String issuer,
        String subject,
        String clientId,
        String audience,
        String scope,
        Instant issuedAt,
        Instant expiresAt) {

    /** Registered token type URN identifying an ID-JAG. */
    public static final String TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id-jag";

    public IdJag {
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("ID-JAG issuer is required");
        }
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("ID-JAG subject is required");
        }
        if (audience == null || audience.isBlank()) {
            throw new IllegalArgumentException("ID-JAG audience (target MCP resource) is required");
        }
        if (issuedAt == null || expiresAt == null || !expiresAt.isAfter(issuedAt)) {
            // A bearer credential for a specific resource with no expiry is never correct.
            throw new IllegalArgumentException("ID-JAG must have a bounded lifetime");
        }
    }

    public static IdJag issue(String issuer, String subject, String clientId, String audience,
                              String scope, Instant now, Duration lifetime) {
        Instant issuedAt = now == null ? Instant.now() : now;
        Duration ttl = lifetime == null ? Duration.ZERO : lifetime;
        return new IdJag(issuer, subject, clientId, audience, scope, issuedAt, issuedAt.plus(ttl));
    }

    /** The claim set an MCP authorization server expects to find. */
    public Map<String, Object> toClaims() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", issuer);
        claims.put("sub", subject);
        claims.put("aud", audience);
        claims.put("client_id", clientId);
        claims.put("scope", scope);
        claims.put("iat", issuedAt.getEpochSecond());
        claims.put("exp", expiresAt.getEpochSecond());
        // Without this an ID-JAG is indistinguishable from an ordinary access token for the same
        // audience, and could be replayed as one.
        claims.put("token_type", TOKEN_TYPE);
        return claims;
    }

    /**
     * Validate this grant as the intended resource.
     *
     * <p>Audience is checked <em>first and exactly</em>: MCP revision {@code 2026-07-28} requires a
     * server to confirm it is the intended audience and forbids accepting or transiting any other
     * token. That check is the confused-deputy defence, and an MCP server is unusually exposed to it
     * because it acts as both a resource server and a client to its own downstream dependencies.
     */
    public IdJagValidation validateFor(String expectedAudience, Instant now) {
        if (!audience.equals(expectedAudience)) {
            return IdJagValidation.WRONG_AUDIENCE;
        }
        if (now.isBefore(issuedAt)) {
            return IdJagValidation.NOT_YET_VALID;
        }
        if (!now.isBefore(expiresAt)) {
            return IdJagValidation.EXPIRED;
        }
        return IdJagValidation.VALID;
    }
}
