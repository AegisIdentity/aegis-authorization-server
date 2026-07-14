package io.aegis.authorizationserver.config;

import io.aegis.authorizationserver.auth.IdentityAuthenticationProvider;
import io.aegis.authorizationserver.auth.MfaStepUp;
import io.aegis.authorizationserver.auth.MfaStepUpAuthenticationSuccessHandler;
import io.aegis.authorizationserver.auth.TenantAuthenticationDetailsSource;
import io.aegis.authorizationserver.federation.FederatedLoginSuccessHandler;
import io.aegis.authorizationserver.federation.Saml2LoginSuccessHandler;
import org.springframework.security.config.Customizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

/**
 * Everything that is not an OAuth2 protocol endpoint: the interactive login page and actuator.
 *
 * <p>Login is <strong>tenant-scoped and delegated to {@code identity-service}</strong>: the form
 * collects Organization + Username + Password, and {@link IdentityAuthenticationProvider} verifies
 * the credentials against that tenant's directory. There is no local user store here.
 */
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(
            HttpSecurity http,
            IdentityAuthenticationProvider identityAuthenticationProvider,
            TenantAuthenticationDetailsSource tenantAuthenticationDetailsSource,
            FederatedLoginSuccessHandler federatedLoginSuccessHandler,
            Saml2LoginSuccessHandler saml2LoginSuccessHandler,
            MfaStepUp mfaStepUp) throws Exception {
        http
                .headers(headers -> headers
                        // Strict CSP, but deliberately WITHOUT `form-action`: this is an OAuth
                        // authorization server, so the login POST legitimately redirects (via
                        // /oauth2/authorize) to a client's redirect_uri on another origin.
                        .contentSecurityPolicy(csp -> csp.policyDirectives(
                                "default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'"))
                        .frameOptions(frame -> frame.deny())
                        .referrerPolicy(ref -> ref.policy(
                                ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                        .permissionsPolicyHeader(pp -> pp.policy(
                                "geolocation=(), camera=(), microphone=()")))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login", "/login/theme.css", "/error", "/actuator/health",
                                "/webjars/**", "/assets/**", "/favicon.ico").permitAll()
                        // /mfa is reachable only once the password factor has authenticated the session.
                        .anyRequest().authenticated())
                .authenticationProvider(identityAuthenticationProvider)
                .formLogin(form -> form
                        .loginPage("/login")
                        .authenticationDetailsSource(tenantAuthenticationDetailsSource)
                        // After the password factor, decide on a second-factor step-up: if needed, the
                        // handler arms the pending state and routes to /mfa instead of resuming authorize.
                        .successHandler(new MfaStepUpAuthenticationSuccessHandler(mfaStepUp))
                        .permitAll())
                // "Sign in with <provider>": the tenant's registered social/OIDC providers. The client
                // registration is resolved per-tenant from the broker (BrokerClientRegistrationRepository);
                // on success the external identity is JIT-provisioned and swapped for an Aegis principal
                // before the authorize flow resumes.
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .successHandler(federatedLoginSuccessHandler))
                // "Sign in with <SAML IdP>": per-tenant relying-party registrations resolved from the
                // broker (BrokerRelyingPartyRegistrationRepository). On success the SAML assertion is
                // mapped + JIT-provisioned like OIDC. saml2Metadata publishes the SP metadata at
                // /saml2/service-provider-metadata/{registrationId} for registering with the IdP.
                .saml2Login(saml2 -> saml2
                        .loginPage("/login")
                        .successHandler(saml2LoginSuccessHandler))
                .saml2Metadata(Customizer.withDefaults());
        return http.build();
    }
}
