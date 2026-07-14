package io.aegis.authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Resource-server chain for the AS's own admin REST API ({@code /api/**}) — used to manage OAuth
 * clients ("applications"). Ordered ahead of the OIDC protocol and login chains. Stateless, JWT-
 * validated, and scope-gated ({@code applications:admin}). Reached only via the edge gateway (which
 * strips Origin), so no CORS is configured here.
 */
@Configuration(proxyBeanMethods = false)
public class ApiSecurityConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 10)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                // Scoped to the applications admin API only (was /api/**), so the tenant-app OAuth surface
                // (/api/v1/webauthn, /social, /oauth/interaction) can have its own permissive-CORS chain.
                .securityMatcher("/api/v1/applications/**", "/api/v1/applications")
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().hasAuthority("SCOPE_applications:admin"))
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }
}
