package io.aegis.authorizationserver.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import java.util.List;

/** Payloads for the OAuth-client ("applications") admin API. */
public final class ApplicationDtos {

    private ApplicationDtos() {
    }

    public record ApplicationSummary(
            String id,
            String name,
            String clientId,
            String type,
            List<String> grantTypes,
            List<String> scopes,
            List<String> redirectUris,
            String status) {
    }

    /** Registers an OIDC application (authorization_code + PKCE public client) for browser/mobile login. */
    public record CreateApplicationRequest(
            @NotBlank String name,
            @NotBlank String redirectUri) {
    }

    /**
     * Registers a service (machine-to-machine) application: a confidential {@code client_credentials}
     * client the tenant's backend uses to call the management APIs. The requested {@code scopes} are
     * validated against an allowlist server-side.
     */
    public record CreateServiceApplicationRequest(
            @NotBlank String name,
            @NotEmpty List<String> scopes) {
    }

    /**
     * The result of creating a service application. The {@code clientSecret} is returned <em>once</em>,
     * in plaintext, at creation time and is never retrievable again (only its hash is stored).
     */
    public record ServiceApplicationCreated(
            String id,
            String name,
            String clientId,
            String clientSecret,
            String tenant,
            List<String> scopes) {
    }
}
