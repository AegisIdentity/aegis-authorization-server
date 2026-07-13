package io.aegis.authorizationserver.auth;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

/**
 * Verifies resource-owner credentials against {@code identity-service} (the credential store).
 *
 * <p>Auth here: the AS mints a short-lived <em>service JWT</em> signed with its own key
 * ({@link JwtEncoder} over the same JWKSource that signs user tokens), carrying the
 * {@code identity:users:authenticate} scope. identity-service validates it against the AS's JWKS like
 * any other bearer token — no circular call to the token endpoint, no static shared secret.
 */
@Component
public class IdentityClient {

    private static final Logger log = LoggerFactory.getLogger(IdentityClient.class);

    private final JwtEncoder jwtEncoder;
    private final String issuer;
    private final RestClient restClient;

    private volatile String cachedToken;
    private volatile Instant cachedExpiry;

    public IdentityClient(JwtEncoder jwtEncoder,
                          @Value("${aegis.issuer:http://localhost:9000}") String issuer,
                          @Value("${aegis.identity-service.base-url:http://localhost:9102}") String baseUrl) {
        this.jwtEncoder = jwtEncoder;
        this.issuer = issuer;
        this.restClient = RestClient.builder().baseUrl(baseUrl).build();
    }

    /** Returns the authenticated principal on success, or empty on any failure. */
    public Optional<AegisUserPrincipal> authenticate(String tenantId, String username, String password) {
        try {
            AuthResult result = restClient.post()
                    .uri("/api/v1/users:authenticate")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + serviceToken())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("tenantId", tenantId, "username", username, "password", password))
                    .retrieve()
                    .body(AuthResult.class);
            if (result != null && "SUCCESS".equals(result.outcome())) {
                return Optional.of(new AegisUserPrincipal(tenantId, result.userId(), username));
            }
            log.warn("Login denied: identity-service outcome={} for org={} user={}",
                    result == null ? "null" : result.outcome(), tenantId, username);
        } catch (RestClientResponseException ex) {
            log.warn("Login could not be verified: identity-service returned HTTP {} for org={} user={}. "
                    + "A 401 here usually means the AS→identity service token was rejected — restart "
                    + "identity-service so it re-fetches the AS JWKS. Body: {}",
                    ex.getStatusCode(), tenantId, username, ex.getResponseBodyAsString());
        } catch (Exception ex) {
            log.warn("Login could not be verified: identity-service unreachable for org={} user={}: {}",
                    tenantId, username, ex.toString());
        }
        return Optional.empty();
    }

    private record AuthResult(String outcome, String userId) {
    }

    private synchronized String serviceToken() {
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
                .claim("scope", "identity:users:authenticate")
                .build();
        cachedToken = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
        cachedExpiry = expiry;
        return cachedToken;
    }
}
