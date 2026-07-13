package io.aegis.authorizationserver.service;

import io.aegis.authorizationserver.web.ApplicationDtos.ApplicationSummary;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Manages OAuth2 registered clients ("applications"). Create uses the AS's
 * {@link RegisteredClientRepository}; list and delete use {@link JdbcTemplate} directly, since the
 * JDBC repository exposes neither a list-all nor a delete.
 */
@Service
public class ApplicationAdminService {

    private final JdbcTemplate jdbcTemplate;
    private final RegisteredClientRepository clients;

    public ApplicationAdminService(JdbcTemplate jdbcTemplate, RegisteredClientRepository clients) {
        this.jdbcTemplate = jdbcTemplate;
        this.clients = clients;
    }

    @Transactional(readOnly = true)
    public List<ApplicationSummary> list() {
        return jdbcTemplate.query("""
                SELECT id, client_id, client_name, authorization_grant_types,
                       client_authentication_methods, redirect_uris
                FROM oauth2_registered_client ORDER BY client_name""",
                (rs, i) -> new ApplicationSummary(
                        rs.getString("id"),
                        rs.getString("client_name"),
                        rs.getString("client_id"),
                        "OIDC",
                        csv(rs.getString("authorization_grant_types")),
                        csv(rs.getString("redirect_uris")),
                        "ACTIVE"));
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
                List.of("authorization_code", "refresh_token"), List.of(redirectUri), "ACTIVE");
    }

    @Transactional
    public void delete(String id) {
        jdbcTemplate.update("DELETE FROM oauth2_registered_client WHERE id = ?", id);
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
