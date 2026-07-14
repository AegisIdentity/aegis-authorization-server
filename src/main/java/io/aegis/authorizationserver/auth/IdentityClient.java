package io.aegis.authorizationserver.auth;

import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

/**
 * Verifies resource-owner credentials against {@code identity-service} (the credential store) and
 * JIT-provisions federated users. Authenticates to identity-service with the AS's own service JWT
 * ({@link ServiceTokenProvider}) — no circular call to the token endpoint, no static shared secret.
 */
@Component
public class IdentityClient {

    private static final Logger log = LoggerFactory.getLogger(IdentityClient.class);

    private final ServiceTokenProvider serviceToken;
    private final RestClient restClient;

    public IdentityClient(ServiceTokenProvider serviceToken,
                          @Value("${aegis.identity-service.base-url:http://localhost:9102}") String baseUrl) {
        this.serviceToken = serviceToken;
        this.restClient = RestClient.builder().baseUrl(baseUrl).build();
    }

    /**
     * The result of a successful credential check: the principal plus whether the user's tenant
     * requires MFA (so the login flow can decide on a step-up challenge before issuing tokens).
     */
    public record AuthOutcome(AegisUserPrincipal principal, boolean mfaRequired) {
    }

    /** Returns the authenticated outcome on success, or empty on any failure. */
    public Optional<AuthOutcome> authenticate(String tenantId, String username, String password) {
        try {
            AuthResult result = restClient.post()
                    .uri("/api/v1/users:authenticate")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + serviceToken.token())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("tenantId", tenantId, "username", username, "password", password))
                    .retrieve()
                    .body(AuthResult.class);
            if (result != null && "SUCCESS".equals(result.outcome())) {
                return Optional.of(new AuthOutcome(
                        new AegisUserPrincipal(tenantId, result.userId(), username), result.mfaRequired()));
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

    /**
     * JIT-provisions (find-or-create by email) a user for a federated login and returns the resulting
     * principal. Throws on failure — a federated login must not proceed without a real Aegis user.
     */
    public AegisUserPrincipal provisionFederated(String tenantId, String email, String preferredUsername) {
        ProvisionResult result = restClient.post()
                .uri("/api/v1/users:provision")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + serviceToken.token())
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("tenantId", tenantId, "email", email,
                        "username", preferredUsername == null ? "" : preferredUsername))
                .retrieve()
                .body(ProvisionResult.class);
        if (result == null || result.id() == null) {
            throw new IllegalStateException("identity-service returned no user for provisioning");
        }
        return new AegisUserPrincipal(tenantId, result.id(), result.username());
    }

    private record AuthResult(String outcome, String userId, boolean mfaRequired) {
    }

    private record ProvisionResult(String id, String tenantId, String username, String email, String status) {
    }
}
