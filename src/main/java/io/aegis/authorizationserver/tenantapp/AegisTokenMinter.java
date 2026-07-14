package io.aegis.authorizationserver.tenantapp;

import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import io.aegis.authorizationserver.auth.TenantJwkSource;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.stereotype.Component;

/**
 * Mints Aegis end-user tokens for the tenant-app (embedded) flows — passkey login and native-social
 * exchange — after the user has been authenticated out-of-band (a verified WebAuthn assertion or a
 * verified provider id_token).
 *
 * <p><b>Issuer and key:</b> tokens carry {@code iss = <public-issuer-base>/<tenant>} — the tenant's
 * public issuer as reached through the edge gateway — and are signed with that tenant's own key
 * (the interaction-token endpoint is not a protocol endpoint, so the tenant cannot come from the
 * request's issuer context; it comes from the interaction code). That makes the tokens verifiable
 * two ways: a tenant's own backend runs standard OIDC discovery against the public issuer
 * ({@code /{tenant}/.well-known/openid-configuration} → {@code /{tenant}/oauth2/jwks}), and Aegis's
 * resource servers validate via the in-network aggregate JWKS + issuer allowlist.
 *
 * <p>Scope is deliberately end-user only ({@code openid profile}) — these flows authenticate a customer,
 * not an admin. Refresh tokens are a documented follow-up; today the app re-runs the (fast) passkey /
 * social ceremony to renew.
 */
@Component
public class AegisTokenMinter {

    private final TenantJwkSource jwkSource;
    private final String publicIssuerBase;
    private final Duration accessTtl = Duration.ofMinutes(10);

    public AegisTokenMinter(TenantJwkSource jwkSource,
                            @Value("${aegis.public-issuer-base:http://localhost:9000}") String publicIssuerBase) {
        this.jwkSource = jwkSource;
        this.publicIssuerBase = publicIssuerBase.replaceAll("/$", "");
    }

    /** An OAuth2 token response body for the interaction-code exchange. */
    public record Tokens(String accessToken, String idToken, String tokenType, long expiresIn, String scope) {
    }

    public Tokens mint(String tenant, String subject, String clientId, String amr) {
        Instant now = Instant.now();
        Instant exp = now.plus(accessTtl);
        String scope = "openid profile";
        String issuer = publicIssuerBase + "/" + tenant;
        // Sign with the tenant's own key — the same key /{tenant}/oauth2/jwks publishes — so external
        // validators resolving the per-tenant issuer verify the signature cleanly.
        JwtEncoder encoder = new NimbusJwtEncoder(new ImmutableJWKSet<>(jwkSource.jwkSetFor(tenant)));

        JwtClaimsSet accessClaims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(subject)
                .audience(List.of(clientId))
                .issuedAt(now)
                .expiresAt(exp)
                .id(UUID.randomUUID().toString())
                .claim("tenant", tenant)
                .claim("scope", scope)
                .claim("client_id", clientId)
                .build();
        String accessToken = encode(encoder, accessClaims);

        JwtClaimsSet idClaims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject(subject)
                .audience(List.of(clientId))
                .issuedAt(now)
                .expiresAt(exp)
                .claim("tenant", tenant)
                .claim("azp", clientId)
                .claim("auth_time", now.getEpochSecond())
                // Authentication Methods References: how the user actually authenticated (RFC 8176).
                .claim("amr", List.of(amr))
                .build();
        String idToken = encode(encoder, idClaims);

        return new Tokens(accessToken, idToken, "Bearer", accessTtl.getSeconds(), scope);
    }

    private static String encode(JwtEncoder encoder, JwtClaimsSet claims) {
        return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(() -> "RS256").build(), claims))
                .getTokenValue();
    }
}
