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
            MfaStepUp mfaStepUp,
            org.springframework.security.web.savedrequest.RequestCache authorizeRequestCache) throws Exception {
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
                                "/webjars/**", "/assets/**", "/favicon.ico", "/.well-known/**").permitAll()
                        // Aggregate JWKS (public keys of every tenant) — fetched in-network by the
                        // resource servers' split-horizon decoders. Public keys only.
                        .requestMatchers("/internal/jwks").permitAll()
                        // Passwordless passkey sign-in: pre-authentication ceremony endpoints.
                        .requestMatchers("/login/webauthn/options", "/login/webauthn/verify").permitAll()
                        // /mfa is reachable only once the password factor has authenticated the session.
                        .anyRequest().authenticated())
                // Only ever save the authorization request for post-login resume. Without this, browser
                // probe requests (favicon, /.well-known/appspecific/com.chrome.devtools.json, …) that hit a
                // protected path get cached as "the saved request" and are replayed after login — landing
                // the user on a 404 instead of resuming /oauth2/authorize.
                .requestCache(rc -> rc.requestCache(authorizeRequestCache))
                // The passkey endpoints are pre-auth JSON and self-protecting: the assertion is signed by
                // the authenticator over a single-use, server-issued challenge, so a forged cross-site POST
                // cannot succeed. Exempt them from CSRF (which assumes an ambient authenticated session).
                .csrf(csrf -> csrf.ignoringRequestMatchers("/login/webauthn/**"))
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

    /**
     * A request cache that only ever saves the OAuth2 authorization request, so the post-login resume
     * (both the built-in success handlers and the passkey/MFA controllers) always lands back on
     * {@code /oauth2/authorize} — never on an unrelated browser probe that happened to hit a protected
     * path first. Shared by both security filter chains.
     */
    @Bean
    public org.springframework.security.web.savedrequest.RequestCache authorizeRequestCache() {
        var cache = new org.springframework.security.web.savedrequest.HttpSessionRequestCache();
        cache.setRequestMatcher(request -> request.getRequestURI().contains("/oauth2/authorize"));
        return cache;
    }
}
