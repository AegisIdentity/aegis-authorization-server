package io.aegis.authorizationserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.http.MediaType;

/**
 * OAuth2/OIDC protocol configuration (Spring Authorization Server 7.1).
 *
 * <p>The protocol endpoints ({@code /oauth2/authorize}, {@code /oauth2/token}, {@code /oauth2/jwks},
 * {@code /.well-known/openid-configuration}, {@code /userinfo}, ...) are served by the highest-order
 * filter chain here. Persistence is JDBC (Postgres) using the schemas that ship with the AS jar.
 *
 * <p><b>Signing key (dev vs prod):</b> this config generates an RSA keypair at startup for local dev
 * and tests. That is deliberately <em>not</em> production behaviour — regenerating on restart
 * invalidates every previously issued token. In production the {@code JWKSource} is backed by
 * per-tenant keys unwrapped from KMS / Key Vault (see ARCHITECTURE.md §7 / ADR-0007).
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    /** Filter chain for the OAuth2/OIDC protocol endpoints. */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // Spring Security 7.1: apply the configurer via HttpSecurity.with(...). The supporting beans
        // (RegisteredClientRepository, OAuth2AuthorizationService, AuthorizationServerSettings,
        // JWKSource, OAuth2TokenCustomizer) are resolved from the context automatically.
        OAuth2AuthorizationServerConfigurer configurer = new OAuth2AuthorizationServerConfigurer();
        RequestMatcher endpointsMatcher = configurer.getEndpointsMatcher();

        http
                .securityMatcher(endpointsMatcher)
                // Allow the SPA (console/portal) to fetch discovery/JWKS and do the PKCE token
                // exchange cross-origin. Without this, oidc-client-ts's metadata fetch is CORS-blocked
                // and sign-in silently never redirects.
                .cors(Customizer.withDefaults())
                .with(configurer, authorizationServer -> authorizationServer
                        .oidc(Customizer.withDefaults()))
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
                // Redirect browsers to the login page; API/token calls still get protocol errors.
                .exceptionHandling(exceptions -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                // Accept our own tokens on protocol endpoints that require them (e.g. userinfo).
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));
        return http.build();
    }

    /**
     * CORS for the OIDC endpoints so a browser SPA (the console/portal) can fetch discovery + JWKS
     * and perform the PKCE code exchange cross-origin. A public client's token exchange needs no
     * cookies, so credentials stay off. Origins are configurable via {@code aegis.spa.origins}.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource(
            @Value("${aegis.spa.origins:http://localhost:5173,http://localhost:3000}") List<String> origins) {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOrigins(origins);
        cfg.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        cfg.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        cfg.setAllowCredentials(false);
        cfg.setMaxAge(Duration.ofHours(1));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Only the endpoints the SPA actually FETCHES cross-origin. /oauth2/authorize and /login are
        // browser navigations (not fetch) — CORS-processing them wrongly rejects the post-login
        // redirect, whose Origin is the AS's own host, as an "Invalid CORS request".
        for (String path : List.of("/.well-known/**", "/oauth2/jwks", "/oauth2/token",
                "/oauth2/revoke", "/oauth2/introspect", "/userinfo", "/connect/userinfo")) {
            source.registerCorsConfiguration(path, cfg);
        }
        return source;
    }

    /** Registered clients, persisted in Postgres. */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    /**
     * Seeds/updates dev clients after the schema scripts have run (ApplicationRunner executes after
     * the DataSource is initialized, which the repository-constructor path would race). The clients
     * use <em>stable ids</em>, so {@code save} upserts by id — this keeps their config (scopes,
     * redirect URIs) current across restarts even when the Postgres volume persists.
     */
    @Bean
    public org.springframework.boot.ApplicationRunner devClientSeeder(RegisteredClientRepository repository) {
        return args -> {
            repository.save(devSpaClient());
            repository.save(devMachineClient());
        };
    }

    /** Public SPA / native client: authorization_code + PKCE, no client secret. */
    private RegisteredClient devSpaClient() {
        return RegisteredClient.withId("aegis-dev-spa")
                .clientId("aegis-dev-spa")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:8081/login/oauth2/code/aegis")
                // aegis-admin-console (SPA) — the OIDC PKCE client for the console/portal.
                // 5173 = Vite dev server; 3000 = the containerized nginx build in docker-compose.
                .redirectUri("http://localhost:5173/callback")
                .redirectUri("http://localhost:3000/callback")
                .postLogoutRedirectUri("http://localhost:5173/signin")
                .postLogoutRedirectUri("http://localhost:3000/signin")
                .postLogoutRedirectUri("http://127.0.0.1:8081/")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("read")
                // Scopes the admin console needs to call the management APIs on the admin's behalf.
                // (Broad for a dev console; production would gate these by the user's admin role.)
                .scope("identity:users:read")
                .scope("identity:users:write")
                .scope("identity:groups:read")
                .scope("identity:groups:write")
                .scope("tenant:read")
                .scope("tenant:admin")
                .scope("applications:admin")
                .clientSettings(ClientSettings.builder()
                        // First-party console: skip the consent screen for a smooth admin UX.
                        .requireAuthorizationConsent(false)
                        .requireProofKey(true) // PKCE mandatory
                        .setting("tenant", "dev")
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(10))
                        .refreshTokenTimeToLive(Duration.ofDays(7))
                        .reuseRefreshTokens(false) // rotate refresh tokens
                        .build())
                .build();
    }

    /** Confidential machine-to-machine client: client_credentials (host-to-host). */
    private RegisteredClient devMachineClient() {
        return RegisteredClient.withId("aegis-dev-m2m")
                .clientId("aegis-dev-m2m")
                // {noop} for local dev only; production stores a hashed secret via a real encoder.
                .clientSecret("{noop}dev-only-change-me")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("identity:users:read")
                .scope("tenant:read")
                .clientSettings(ClientSettings.builder().setting("tenant", "dev").build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(5))
                        .build())
                .build();
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
                                                           RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, clients);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate,
                                                                         RegisteredClientRepository clients) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, clients);
    }

    /**
     * Stamps a {@code tenant} claim onto issued access + id tokens, sourced from the client's
     * registered tenant. This is what makes tokens tenant-scoped for downstream resource servers.
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return context -> {
            Object tenant = context.getRegisteredClient().getClientSettings().getSetting("tenant");
            if (tenant != null) {
                context.getClaims().claim("tenant", tenant.toString());
            }
        };
    }

    /** Dev/test JWK source — see class javadoc for the production KMS-backed path. */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsaKey();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static RSAKey generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            keyPair = generator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("unable to generate RSA signing key", ex);
        }
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(
            @Value("${aegis.issuer:http://localhost:9000}") String issuer) {
        // Single issuer for v1. Per-tenant issuers (https://host/t/{tenantId}) are enabled by
        // multipleIssuersAllowed(true) + tenant-aware client/key resolution — see ARCHITECTURE.md §5.
        return AuthorizationServerSettings.builder()
                .issuer(issuer)
                .build();
    }
}
