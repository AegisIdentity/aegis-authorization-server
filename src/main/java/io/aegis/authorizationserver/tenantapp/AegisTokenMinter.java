package io.aegis.authorizationserver.tenantapp;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

/**
 * Mints Aegis end-user tokens for the tenant-app (embedded) flows — passkey login and native-social
 * exchange — after the user has been authenticated out-of-band (a verified WebAuthn assertion or a
 * verified provider id_token). Signed with the AS's own key over the shared {@code JWKSource}, so every
 * Aegis resource server validates them exactly like tokens from the standard authorization_code flow.
 *
 * <p>Scope is deliberately end-user only ({@code openid profile}) — these flows authenticate a customer,
 * not an admin. Refresh tokens are a documented follow-up; today the app re-runs the (fast) passkey /
 * social ceremony to renew.
 */
@Component
public class AegisTokenMinter {

    private final JwtEncoder jwtEncoder;
    private final String issuer;
    private final Duration accessTtl = Duration.ofMinutes(10);

    public AegisTokenMinter(JwtEncoder jwtEncoder,
                            @Value("${aegis.issuer:http://localhost:9000}") String issuer) {
        this.jwtEncoder = jwtEncoder;
        this.issuer = issuer;
    }

    /** An OAuth2 token response body for the interaction-code exchange. */
    public record Tokens(String accessToken, String idToken, String tokenType, long expiresIn, String scope) {
    }

    public Tokens mint(String tenant, String subject, String clientId, String amr) {
        Instant now = Instant.now();
        Instant exp = now.plus(accessTtl);
        String scope = "openid profile";

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
        String accessToken = encode(accessClaims);

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
        String idToken = encode(idClaims);

        return new Tokens(accessToken, idToken, "Bearer", accessTtl.getSeconds(), scope);
    }

    private String encode(JwtClaimsSet claims) {
        return jwtEncoder.encode(JwtEncoderParameters.from(JwsHeader.with(() -> "RS256").build(), claims))
                .getTokenValue();
    }
}
