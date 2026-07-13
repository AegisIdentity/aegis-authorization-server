package io.aegis.authorizationserver.service;

import io.aegis.authorizationserver.web.ApplicationDtos.ApplicationSummary;
import io.aegis.authorizationserver.web.ApplicationDtos.ServiceApplicationCreated;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

/**
 * Manages OAuth2 registered clients ("applications"). Create uses the AS's
 * {@link RegisteredClientRepository}; list and delete use {@link JdbcTemplate} directly, since the
 * JDBC repository exposes neither a list-all nor a delete.
 */
@Service
public class ApplicationAdminService {

    /**
     * The scopes a tenant may grant to its own service (M2M) clients — i.e. the management-API surface
     * a tenant's backend is allowed to call on its own data. Deliberately excludes
     * {@code applications:admin} (managing OAuth clients) to prevent a service client minting more
     * privileged clients.
     */
    static final Set<String> GRANTABLE_SERVICE_SCOPES = Set.of(
            "identity:users:read", "identity:users:write",
            "identity:groups:read", "identity:groups:write",
            "tenant:read");

    private static final SecureRandom RANDOM = new SecureRandom();

    private final JdbcTemplate jdbcTemplate;
    private final RegisteredClientRepository clients;
    private final PasswordEncoder secretEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    public ApplicationAdminService(JdbcTemplate jdbcTemplate, RegisteredClientRepository clients) {
        this.jdbcTemplate = jdbcTemplate;
        this.clients = clients;
    }

    @Transactional(readOnly = true)
    public List<ApplicationSummary> list() {
        return jdbcTemplate.query("""
                SELECT id, client_id, client_name, authorization_grant_types,
                       client_authentication_methods, redirect_uris, scopes
                FROM oauth2_registered_client ORDER BY client_name""",
                (rs, i) -> {
                    List<String> grants = csv(rs.getString("authorization_grant_types"));
                    String type = grants.contains("client_credentials") ? "SERVICE" : "OIDC";
                    return new ApplicationSummary(
                            rs.getString("id"),
                            rs.getString("client_name"),
                            rs.getString("client_id"),
                            type,
                            grants,
                            csv(rs.getString("scopes")),
                            csv(rs.getString("redirect_uris")),
                            "ACTIVE");
                });
    }

    @Transactional
    public ApplicationSummary createOidc(String name, String redirectUri) {
        String clientId = slug(name) + "-" + UUID.randomUUID().toString().substring(0, 6);
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientName(name)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(redirectUri)
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)                 // PKCE mandatory for public clients
                        .requireAuthorizationConsent(false)
                        .build())
                .build();
        clients.save(client);
        return new ApplicationSummary(client.getId(), name, clientId, "OIDC",
                List.of("authorization_code", "refresh_token"),
                List.of(OidcScopes.OPENID, OidcScopes.PROFILE), List.of(redirectUri), "ACTIVE");
    }

    /**
     * Registers a confidential {@code client_credentials} client for the given tenant. The client
     * secret is generated here, stored only as a hash, and returned in plaintext exactly once. Tokens
     * minted by this client carry the tenant's claim (via the client's {@code tenant} setting), so a
     * tenant's backend can only ever act on its own data.
     */
    @Transactional
    public ServiceApplicationCreated createService(String tenant, String name, List<String> requestedScopes) {
        if (tenant == null || tenant.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "tenant is required");
        }
        Set<String> scopes = new LinkedHashSet<>(requestedScopes);
        Set<String> forbidden = new LinkedHashSet<>(scopes);
        forbidden.removeAll(GRANTABLE_SERVICE_SCOPES);
        if (!forbidden.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "unsupported scope(s): " + String.join(", ", forbidden)
                            + ". Allowed: " + String.join(", ", GRANTABLE_SERVICE_SCOPES));
        }

        String clientId = slug(name) + "-svc-" + UUID.randomUUID().toString().substring(0, 6);
        String secret = generateSecret();

        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientName(name)
                .clientSecret(secretEncoder.encode(secret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .clientSettings(ClientSettings.builder().setting("tenant", tenant).build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        .build());
        scopes.forEach(builder::scope);
        RegisteredClient client = builder.build();
        clients.save(client);

        return new ServiceApplicationCreated(client.getId(), name, clientId, secret, tenant,
                List.copyOf(scopes));
    }

    @Transactional
    public void delete(String id) {
        jdbcTemplate.update("DELETE FROM oauth2_registered_client WHERE id = ?", id);
    }

    /** 32 bytes of entropy, URL-safe, no padding. */
    private static String generateSecret() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static List<String> csv(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        return Arrays.stream(value.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }

    private static String slug(String name) {
        String s = name.toLowerCase().replaceAll("[^a-z0-9]+", "-").replaceAll("(^-|-$)", "");
        return s.isEmpty() ? "app" : s;
    }
}
