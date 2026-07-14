package io.aegis.authorizationserver.config;

import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * Security for the <strong>tenant-app (embedded) surface</strong> — the endpoints a tenant's own web or
 * mobile app calls directly to do passkey login, native-social exchange, and the interaction-code token
 * swap. Ordered ahead of the applications-admin, OIDC, and login chains.
 *
 * <p>These are OAuth-style endpoints: bearer/code-based, never cookie-authenticated. So CORS is
 * deliberately permissive ({@code *}, credentials disabled) — the same posture as a public token
 * endpoint — which lets any tenant's app origin call them without a per-origin allowlist, while the real
 * security lives in the signed WebAuthn assertion, the verified provider id_token, and the single-use
 * PKCE interaction code. Registration (enrolling a passkey for a signed-in user) still requires the
 * user's bearer token; the login/social/token exchanges are public by design.
 */
@Configuration(proxyBeanMethods = false)
public class TenantAppSecurityConfig {

    static final String[] PATHS = {"/api/v1/webauthn/**", "/api/v1/social/**", "/api/v1/oauth/interaction/**"};

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain tenantAppSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher(PATHS)
                .cors(cors -> cors.configurationSource(tenantAppCorsSource()))
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**").permitAll()
                        // Enrolling a passkey acts on a signed-in user — requires their token.
                        .requestMatchers("/api/v1/webauthn/register/**").authenticated()
                        // Passwordless login, native-social exchange, and the token swap are public: they
                        // authenticate the user via the assertion / provider token / interaction code.
                        .anyRequest().permitAll())
                // Bearer validation for the authenticated register endpoints.
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }

    private CorsConfigurationSource tenantAppCorsSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(List.of("*"));
        config.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(false); // no cookies — bearer/code only
        config.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        for (String path : PATHS) {
            source.registerCorsConfiguration(path, config);
        }
        return source;
    }
}
