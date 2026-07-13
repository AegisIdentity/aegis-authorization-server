package io.aegis.authorizationserver.federation;

import io.aegis.authorizationserver.federation.BrokerClient.ProviderConfig;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Resolves a per-tenant federated {@link ClientRegistration} on demand from the broker. The
 * {@code registrationId} is {@code <tenant>__<alias>} — encoded into the "Sign in with X" links so the
 * OAuth2 login filters can look up the tenant's provider config at authorization-request and callback
 * time. OIDC providers (Google/Entra/Apple/generic) are built via discovery from their issuer; OAuth2
 * providers (GitHub) are built from explicit endpoints. SAML is handled separately (Phase 3).
 */
@Component
public class BrokerClientRegistrationRepository implements ClientRegistrationRepository {

    static final String SEPARATOR = "__";
    private static final String REDIRECT_URI = "{baseUrl}/login/oauth2/code/{registrationId}";

    private final BrokerClient broker;

    public BrokerClientRegistrationRepository(BrokerClient broker) {
        this.broker = broker;
    }

    public static String registrationId(String tenant, String alias) {
        return tenant + SEPARATOR + alias;
    }

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        int i = registrationId == null ? -1 : registrationId.indexOf(SEPARATOR);
        if (i < 0) {
            return null;
        }
        String tenant = registrationId.substring(0, i);
        String alias = registrationId.substring(i + SEPARATOR.length());
        ProviderConfig c = broker.resolve(tenant, alias);
        if (c == null) {
            return null;
        }
        return switch (c.protocol()) {
            case "OIDC" -> oidc(registrationId, c);
            case "OAUTH2" -> oauth2(registrationId, c);
            default -> null; // SAML: not an OAuth2 client registration
        };
    }

    private ClientRegistration oidc(String registrationId, ProviderConfig c) {
        // Discovery from the issuer fills authorization/token/userinfo/jwks endpoints.
        return ClientRegistrations.fromIssuerLocation(c.issuerUri())
                .registrationId(registrationId)
                .clientId(c.clientId())
                .clientSecret(c.clientSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .redirectUri(REDIRECT_URI)
                .scope(scopes(c.scopes()))
                .clientName(c.displayName())
                .build();
    }

    private ClientRegistration oauth2(String registrationId, ProviderConfig c) {
        return ClientRegistration.withRegistrationId(registrationId)
                .clientId(c.clientId())
                .clientSecret(c.clientSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(REDIRECT_URI)
                .scope(scopes(c.scopes()))
                .authorizationUri(c.authorizationUri())
                .tokenUri(c.tokenUri())
                .userInfoUri(c.userInfoUri())
                .userNameAttributeName(StringUtils.hasText(c.userNameAttribute()) ? c.userNameAttribute() : "id")
                .clientName(c.displayName())
                .build();
    }

    private static String[] scopes(String scopes) {
        if (!StringUtils.hasText(scopes)) {
            return new String[] {"openid"};
        }
        return scopes.trim().split("\\s+");
    }
}
