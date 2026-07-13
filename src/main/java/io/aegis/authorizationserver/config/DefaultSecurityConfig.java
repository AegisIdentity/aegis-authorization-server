package io.aegis.authorizationserver.config;

import io.aegis.authorizationserver.auth.IdentityAuthenticationProvider;
import io.aegis.authorizationserver.auth.TenantAuthenticationDetailsSource;
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
            TenantAuthenticationDetailsSource tenantAuthenticationDetailsSource) throws Exception {
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
                        .requestMatchers("/login", "/error", "/actuator/health",
                                "/webjars/**", "/assets/**", "/favicon.ico").permitAll()
                        .anyRequest().authenticated())
                .authenticationProvider(identityAuthenticationProvider)
                .formLogin(form -> form
                        .loginPage("/login")
                        .authenticationDetailsSource(tenantAuthenticationDetailsSource)
                        .permitAll());
        return http.build();
    }
}
