package io.aegis.authorizationserver.auth;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

/**
 * Mints (and caches) the authorization-server's own short-lived <em>service JWT</em> for calling other
 * Aegis services: signed with the AS's key over the same {@code JWKSource} that signs user tokens, so
 * downstream services validate it against the AS JWKS like any bearer token — no static shared secret.
 *
 * <p>Scopes are the union of what the AS needs to act as a trusted internal caller:
 * {@code identity:users:authenticate} (verify passwords), {@code identity:users:provision} (JIT-create
 * federated users), and {@code idp:resolve} (read provider config from the broker).
 */
@Component
public class ServiceTokenProvider {

    private static final String SERVICE_SCOPES =
            "identity:users:authenticate identity:users:provision idp:resolve";

    private final JwtEncoder jwtEncoder;
    private final String issuer;

    private volatile String cachedToken;
    private volatile Instant cachedExpiry;

    public ServiceTokenProvider(JwtEncoder jwtEncoder,
                                @Value("${aegis.issuer:http://localhost:9000}") String issuer) {
        this.jwtEncoder = jwtEncoder;
        this.issuer = issuer;
    }

    public synchronized String token() {
        Instant now = Instant.now();
        if (cachedToken != null && cachedExpiry != null && cachedExpiry.isAfter(now.plusSeconds(30))) {
            return cachedToken;
        }
        Instant expiry = now.plus(Duration.ofMinutes(5));
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .subject("aegis-authorization-server")
                .audience(List.of("aegis-internal"))
                .issuedAt(now)
                .expiresAt(expiry)
                .claim("scope", SERVICE_SCOPES)
                .build();
        cachedToken = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        cachedExpiry = expiry;
        return cachedToken;
    }
}
