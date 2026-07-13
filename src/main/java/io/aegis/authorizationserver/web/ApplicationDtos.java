package io.aegis.authorizationserver.web;

import jakarta.validation.constraints.NotBlank;
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
            List<String> redirectUris,
            String status) {
    }

    /** Registers an OIDC application (authorization_code + PKCE public client). */
    public record CreateApplicationRequest(
            @NotBlank String name,
            @NotBlank String redirectUri) {
    }
}
