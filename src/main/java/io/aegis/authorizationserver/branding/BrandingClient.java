package io.aegis.authorizationserver.branding;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Reads a tenant's public sign-in branding from identity-service so the login page can render it.
 * Falls back to Aegis defaults on any error (the login page must always render).
 */
@Component
public class BrandingClient {

    private static final Logger log = LoggerFactory.getLogger(BrandingClient.class);

    private final RestClient restClient;

    public BrandingClient(
            @Value("${aegis.identity-service.base-url:http://localhost:9102}") String baseUrl) {
        this.restClient = RestClient.builder().baseUrl(baseUrl).build();
    }

    public Branding forTenant(String tenant) {
        if (tenant == null || tenant.isBlank()) {
            return Branding.DEFAULT;
        }
        try {
            Branding branding = restClient.get()
                    .uri("/api/v1/branding/{tenant}", tenant)
                    .retrieve()
                    .body(Branding.class);
            return branding == null ? Branding.DEFAULT : branding;
        } catch (Exception ex) {
            log.warn("Could not load branding for tenant={}: {}", tenant, ex.toString());
            return Branding.DEFAULT;
        }
    }

    public record Branding(String tenant, String productName, String signInHeading,
                           String signInSubtitle, String primaryColor) {

        public static final Branding DEFAULT = new Branding(null, "Aegis Identity",
                "One secure front door for every app.",
                "Sign in once and Aegis handles password, passkey, MFA, social, and SAML for your whole organization.",
                "#3b5bdb");
    }
}
