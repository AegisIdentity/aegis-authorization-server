package io.aegis.authorizationserver.auth;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Jackson mix-in that lets the Authorization Server persist and re-read {@link TenantWebAuthenticationDetails}.
 *
 * <p>The interactive-login {@code Authentication} is stored inside a saved {@code OAuth2Authorization},
 * and its {@code details} are these web details. {@code ProviderManager} copies the request's details
 * onto the authenticated token, so this custom {@code WebAuthenticationDetails} subclass ends up in the
 * persisted graph and must be reconstructable — otherwise the token-endpoint read-back fails with
 * "no Creators" → HTTP 500. This maps the serialized {@code remoteAddress}/{@code sessionId}/{@code tenant}
 * to the reconstruction constructor; the type is added to the mapper's polymorphic-type allowlist in
 * {@code AuthorizationServerConfig#authorizationService}.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class TenantWebAuthenticationDetailsMixin {

    @JsonCreator
    TenantWebAuthenticationDetailsMixin(
            @JsonProperty("remoteAddress") String remoteAddress,
            @JsonProperty("sessionId") String sessionId,
            @JsonProperty("tenant") String tenant) {
    }
}
