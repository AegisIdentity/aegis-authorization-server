package io.aegis.authorizationserver.config;

import io.aegis.authorizationserver.auth.IdentityClient;
import io.aegis.authorizationserver.federation.FederatedLoginSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * Wiring for federated ("Sign in with …") login. The {@code ClientRegistrationRepository} is the
 * dynamic {@code BrokerClientRegistrationRepository} (a @Component). Here we add the authorized-client
 * store and the success handler that JIT-provisions the external user and resumes the authorize flow.
 */
@Configuration(proxyBeanMethods = false)
public class FederationConfig {

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService(ClientRegistrationRepository repo) {
        return new InMemoryOAuth2AuthorizedClientService(repo);
    }

    @Bean
    public FederatedLoginSuccessHandler federatedLoginSuccessHandler(IdentityClient identityClient) {
        return new FederatedLoginSuccessHandler(identityClient);
    }
}
