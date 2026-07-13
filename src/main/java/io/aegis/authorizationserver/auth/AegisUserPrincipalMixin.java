package io.aegis.authorizationserver.auth;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Jackson mix-in that lets the Authorization Server persist and re-read the {@link AegisUserPrincipal}
 * stored inside a saved {@code OAuth2Authorization} (the interactive-login principal of an
 * authorization_code grant).
 *
 * <p>Without it, the JDBC authorization store's Jackson mapper cannot reconstruct the record on
 * read-back at the token endpoint — surfacing as an {@code InvalidTypeIdException} → HTTP 500 right
 * after a successful login. This mix-in supplies the canonical constructor as the JSON creator; the
 * type itself is added to the mapper's polymorphic-type allowlist in
 * {@code AuthorizationServerConfig#authorizationService}.
 *
 * <p>{@code name} is excluded: {@code getName()} is a derived accessor that just returns
 * {@code username}, so persisting it would be redundant and it has no constructor parameter.
 */
@JsonIgnoreProperties(value = {"name"}, ignoreUnknown = true)
public abstract class AegisUserPrincipalMixin {

    @JsonCreator
    AegisUserPrincipalMixin(
            @JsonProperty("tenantId") String tenantId,
            @JsonProperty("userId") String userId,
            @JsonProperty("username") String username) {
    }
}
