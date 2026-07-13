package io.aegis.authorizationserver;

import static io.aegis.commons.testing.AegisJwtTest.jwtForTenant;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Integration tests for the core OAuth2/OIDC behaviours, against a real Postgres. Focused on the
 * cases that catch real misconfiguration: discovery/JWKS well-formedness, machine-to-machine token
 * issuance, and rejection of an unregistered client.
 *
 * <p>MockMvc is built manually from the context (Boot 4 relocated {@code @AutoConfigureMockMvc});
 * {@code springSecurity()} wires the security filter chain into the MockMvc pipeline.
 */
@SpringBootTest
@Import(TestcontainersConfig.class)
class AuthorizationServerFlowsIT {

    @Autowired
    WebApplicationContext context;

    @Autowired
    org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository clients;

    MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    private static String basic(String clientId, String secret) {
        String creds = clientId + ":" + secret;
        return "Basic " + Base64.getEncoder().encodeToString(creds.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void openid_configuration_is_published_and_well_formed() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").exists())
                .andExpect(jsonPath("$.jwks_uri").exists())
                .andExpect(jsonPath("$.token_endpoint").exists())
                .andExpect(jsonPath("$.authorization_endpoint").exists());
    }

    @Test
    void spa_client_is_registered_with_the_console_scopes_and_redirect_uris() {
        // Guards the "invalid_scope" sign-in failure: the console requests these scopes, so the
        // aegis-dev-spa client must be registered for them (and for the console's redirect URIs).
        var spa = clients.findByClientId("aegis-dev-spa");
        org.assertj.core.api.Assertions.assertThat(spa).isNotNull();
        org.assertj.core.api.Assertions.assertThat(spa.getScopes())
                .contains("openid", "profile", "identity:users:read", "identity:users:write",
                        "tenant:read", "tenant:admin");
        org.assertj.core.api.Assertions.assertThat(spa.getRedirectUris())
                .contains("http://localhost:3000/callback", "http://localhost:5173/callback");
    }

    @Test
    void login_page_csp_does_not_restrict_form_action() throws Exception {
        // Regression: an OAuth login POST redirects to the client redirect_uri (another origin), so
        // `form-action 'self'` in the login CSP would make the browser block sign-in (403 at /login).
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Security-Policy", org.hamcrest.Matchers.allOf(
                        org.hamcrest.Matchers.containsString("default-src 'self'"),
                        org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("form-action")))));
    }

    @Test
    void discovery_allows_cors_from_the_spa_origin() throws Exception {
        // The browser SPA fetches discovery cross-origin before it can start sign-in; without this
        // header the fetch is blocked and sign-in silently never redirects.
        mockMvc.perform(get("/.well-known/openid-configuration")
                        .header("Origin", "http://localhost:5173"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"));
    }

    @Test
    void authorize_is_not_cors_restricted_for_navigations() throws Exception {
        // Regression: the post-login redirect to /oauth2/authorize carries the AS's own Origin; CORS
        // must NOT reject it ("Invalid CORS request"). CORS only covers the fetched endpoints.
        var result = mockMvc.perform(get("/oauth2/authorize")
                        .header("Origin", "http://authorization-server:9000")
                        .param("response_type", "code")
                        .param("client_id", "aegis-dev-spa")
                        .param("redirect_uri", "http://localhost:3000/callback")
                        .param("scope", "openid")
                        .param("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                        .param("code_challenge_method", "S256"))
                .andReturn();
        org.assertj.core.api.Assertions.assertThat(result.getResponse().getStatus())
                .as("must not be a 403 CORS rejection").isNotEqualTo(403);
        org.assertj.core.api.Assertions.assertThat(result.getResponse().getContentAsString())
                .doesNotContain("Invalid CORS request");
    }

    @Test
    void jwks_endpoint_exposes_a_signing_key() throws Exception {
        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].kid").exists());
    }

    @Test
    void client_credentials_grant_issues_a_scoped_access_token() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", basic("aegis-dev-m2m", "dev-only-change-me"))
                        .param("grant_type", "client_credentials")
                        .param("scope", "identity:users:read")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.token_type").value("Bearer"));
    }

    @Test
    void applications_api_lists_and_creates_clients_and_is_scope_gated() throws Exception {
        // no token -> 401; wrong scope -> 403
        mockMvc.perform(get("/api/v1/applications")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/v1/applications")
                        .with(jwtForTenant("t", "admin", "identity:users:read")))
                .andExpect(status().isForbidden());

        // correct scope: the list includes the seeded dev clients
        mockMvc.perform(get("/api/v1/applications")
                        .with(jwtForTenant("t", "admin", "applications:admin")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.clientId=='aegis-dev-spa')]").exists());

        // create an OIDC application
        mockMvc.perform(post("/api/v1/applications").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Acme Portal\",\"redirectUri\":\"https://acme.example/callback\"}")
                        .with(jwtForTenant("t", "admin", "applications:admin")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("Acme Portal"))
                .andExpect(jsonPath("$.clientId").exists());
    }

    @Test
    void unregistered_client_is_rejected_at_the_token_endpoint() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", basic("does-not-exist", "whatever"))
                        .param("grant_type", "client_credentials")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void unauthenticated_authorize_request_is_denied_and_issues_no_code() throws Exception {
        // Security property: an unauthenticated caller must never receive an authorization code.
        // (In a full servlet deployment a browser is redirected 302 -> /login; under MockMvc the
        // endpoint denies with 4xx. Either way, no code is issued — that is what we assert. The
        // browser login redirect itself is verified against the running compose stack.)
        var result = mockMvc.perform(get("/oauth2/authorize")
                        .header("Accept", MediaType.TEXT_HTML_VALUE)
                        .param("response_type", "code")
                        .param("client_id", "aegis-dev-spa")
                        .param("redirect_uri", "http://127.0.0.1:8081/login/oauth2/code/aegis")
                        .param("scope", "openid")
                        .param("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                        .param("code_challenge_method", "S256"))
                .andReturn();

        int status = result.getResponse().getStatus();
        org.assertj.core.api.Assertions.assertThat(status)
                .as("unauthenticated authorize must not succeed (2xx)").isGreaterThanOrEqualTo(300);
        String location = result.getResponse().getHeader("Location");
        if (location != null) {
            org.assertj.core.api.Assertions.assertThat(location)
                    .as("no authorization code may leak to the redirect_uri").doesNotContain("code=");
        }
    }
}
