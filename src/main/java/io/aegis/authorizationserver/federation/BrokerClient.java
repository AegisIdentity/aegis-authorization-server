package io.aegis.authorizationserver.federation;

import io.aegis.authorizationserver.auth.ServiceTokenProvider;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Reads per-tenant identity-provider configuration from {@code social-broker-service} so the AS can
 * build federated client registrations and render the login page's SSO buttons. Authenticates with the
 * AS service JWT ({@code idp:resolve} scope).
 */
@Component
public class BrokerClient {

    private static final Logger log = LoggerFactory.getLogger(BrokerClient.class);

    private final ServiceTokenProvider serviceToken;
    private final RestClient restClient;

    public BrokerClient(ServiceTokenProvider serviceToken,
                        @Value("${aegis.social-broker.base-url:http://localhost:9105}") String baseUrl) {
        this.serviceToken = serviceToken;
        this.restClient = RestClient.builder().baseUrl(baseUrl).build();
    }

    /** Enabled providers for a tenant (for the login page). Returns empty on any error — the login page
     * must still render password login even if the broker is unreachable. */
    public List<ProviderSummary> listEnabled(String tenant) {
        try {
            List<ProviderSummary> result = restClient.get()
                    .uri(uri -> uri.path("/internal/identity-providers").queryParam("tenant", tenant).build())
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + serviceToken.token())
                    .retrieve()
                    .body(new ParameterizedTypeReference<List<ProviderSummary>>() {
                    });
            return result == null ? List.of() : result;
        } catch (Exception ex) {
            log.warn("Could not list identity providers for tenant={}: {}", tenant, ex.toString());
            return List.of();
        }
    }

    /** Full config (incl. client secret) for one enabled provider. Returns null if not found/disabled. */
    public ProviderConfig resolve(String tenant, String alias) {
        try {
            return restClient.get()
                    .uri(uri -> uri.path("/internal/identity-providers/resolve")
                            .queryParam("tenant", tenant).queryParam("alias", alias).build())
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + serviceToken.token())
                    .retrieve()
                    .body(ProviderConfig.class);
        } catch (Exception ex) {
            log.warn("Could not resolve provider tenant={} alias={}: {}", tenant, alias, ex.toString());
            return null;
        }
    }

    public record ProviderSummary(String alias, String providerKey, String protocol, String displayName) {
    }

    public record ProviderConfig(
            String alias, String providerKey, String protocol, String displayName,
            String clientId, String clientSecret, String issuerUri, String authorizationUri,
            String tokenUri, String userInfoUri, String jwkSetUri, String scopes,
            String userNameAttribute, String samlMetadataUrl, String samlEntityId) {
    }
}
