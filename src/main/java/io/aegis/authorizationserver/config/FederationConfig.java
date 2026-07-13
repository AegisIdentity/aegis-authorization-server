package io.aegis.authorizationserver.config;

import io.aegis.authorizationserver.federation.FederatedLoginSuccessHandler;
import io.aegis.authorizationserver.federation.FederatedSessionEstablisher;
import io.aegis.authorizationserver.federation.Saml2LoginSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * Wiring for federated ("Sign in with …") login. The client/relying-party registration repositories are
 * the dynamic broker-backed ones (@Components). Here we add the OAuth2 authorized-client store and the
 * success handlers (OAuth2 + SAML) that JIT-provision the external user and resume the authorize flow.
 */
@Configuration(proxyBeanMethods = false)
public class FederationConfig {

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(ClientRegistrationRepository repo) {
        return new InMemoryOAuth2AuthorizedClientService(repo);
    }

    @Bean
    public FederatedLoginSuccessHandler federatedLoginSuccessHandler(FederatedSessionEstablisher establisher) {
        return new FederatedLoginSuccessHandler(establisher);
    }

    @Bean
    public Saml2LoginSuccessHandler saml2LoginSuccessHandler(FederatedSessionEstablisher establisher) {
        return new Saml2LoginSuccessHandler(establisher);
    }
}
