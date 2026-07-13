package io.aegis.authorizationserver.federation;

import io.aegis.authorizationserver.federation.BrokerClient.ProviderConfig;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.stereotype.Component;

/**
 * Resolves a per-tenant SAML {@link RelyingPartyRegistration} on demand from the broker. The
 * {@code registrationId} is {@code <tenant>__<alias>} (same scheme as OIDC), encoded into the SAML
 * "Sign in with X" links and the ACS/metadata URLs. The asserting party (IdP) is built by fetching the
 * tenant's configured IdP metadata; the SP entity id and ACS are templated from the request base URL.
 *
 * <p>SP request-signing / assertion-decryption credentials are not attached here (dev): the AuthnRequest
 * is unsigned, which works with IdPs that accept it. Production attaches a KMS-backed SP credential
 * (noted as follow-up).
 */
@Component
public class BrokerRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository {

    private static final String ENTITY_ID = "{baseUrl}/saml2/service-provider-metadata/{registrationId}";
    private static final String ACS = "{baseUrl}/login/saml2/sso/{registrationId}";

    private final BrokerClient broker;

    public BrokerRelyingPartyRegistrationRepository(BrokerClient broker) {
        this.broker = broker;
    }

    @Override
    public RelyingPartyRegistration findByRegistrationId(String registrationId) {
        int i = registrationId == null ? -1 : registrationId.indexOf(BrokerClientRegistrationRepository.SEPARATOR);
        if (i < 0) {
            return null;
        }
        String tenant = registrationId.substring(0, i);
        String alias = registrationId.substring(i + BrokerClientRegistrationRepository.SEPARATOR.length());
        ProviderConfig c = broker.resolve(tenant, alias);
        if (c == null || !"SAML".equals(c.protocol()) || c.samlMetadataUrl() == null) {
            return null;
        }
        // Discovery from the IdP metadata fills the SSO endpoints + the IdP verification certificate.
        return RelyingPartyRegistrations.fromMetadataLocation(c.samlMetadataUrl())
                .registrationId(registrationId)
                .entityId(ENTITY_ID)
                .assertionConsumerServiceLocation(ACS)
                .build();
    }
}
