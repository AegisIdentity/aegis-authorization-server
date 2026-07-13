package io.aegis.authorizationserver.config;

import io.aegis.commons.security.SecurityHardening;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Everything that is not an OAuth2 protocol endpoint: the interactive login page and actuator.
 * Applies the shared hardening headers (CSP etc.) from {@code aegis-security-commons}.
 */
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        SecurityHardening.applyHardeningHeaders(http);
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/login", "/error", "/actuator/health",
                                "/webjars/**", "/assets/**", "/favicon.ico").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form.loginPage("/login").permitAll());
        return http.build();
    }

    /**
     * DEV ONLY resource-owner store. In production this bean is replaced by a
     * {@code UserDetailsService} / {@code AuthenticationProvider} that verifies credentials against
     * {@code identity-service} (Argon2id, per-tenant policy) — see ARCHITECTURE.md §6.1.
     */
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails devUser = User.withUsername("dev-user")
                .password(passwordEncoder.encode("dev-only-change-me"))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(devUser);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
