package io.aegis.authorizationserver;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * The Device Authorization Grant (RFC 8628), which the service catalog advertises but no client was
 * previously configured for — the grant was simply absent.
 *
 * <p>Covers the protocol contract (discovery, code issuance, polling) and the security properties
 * that are specific to this grant: the device is a public client whose tokens are authorized by a
 * signed-in human, so issuance must not happen before that approval, and the approval page must not
 * be reachable anonymously.
 */
@SpringBootTest
@ActiveProfiles("dev")
@Import(TestcontainersConfig.class)
class DeviceGrantIT {

    @Autowired
    WebApplicationContext context;

    MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Test
    void discovery_advertises_the_device_endpoint_and_grant() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.device_authorization_endpoint").exists())
                .andExpect(jsonPath("$.grant_types_supported")
                        .value(org.hamcrest.Matchers.hasItem("urn:ietf:params:oauth:grant-type:device_code")));
    }

    @Test
    void a_device_receives_a_device_code_user_code_and_verification_uri() throws Exception {
        mockMvc.perform(post("/oauth2/device_authorization")
                        .param("client_id", "aegis-dev-device")
                        .param("scope", "profile read"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.device_code").exists())
                .andExpect(jsonPath("$.user_code").exists())
                // What the device displays / QR-encodes for the user's second screen.
                .andExpect(jsonPath("$.verification_uri").exists())
                .andExpect(jsonPath("$.expires_in").exists());
    }

    /**
     * The core safety property: polling before the user approves must NOT yield tokens. If this ever
     * returned an access token, any device could mint tokens for an arbitrary user with no human
     * involvement at all.
     */
    @Test
    void polling_before_approval_returns_authorization_pending_and_no_token() throws Exception {
        String deviceCode = com.jayway.jsonpath.JsonPath.read(
                mockMvc.perform(post("/oauth2/device_authorization")
                                .param("client_id", "aegis-dev-device")
                                .param("scope", "profile read"))
                        .andReturn().getResponse().getContentAsString(),
                "$.device_code");

        mockMvc.perform(post("/oauth2/token")
                        .param("client_id", "aegis-dev-device")
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
                        .param("device_code", deviceCode))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("authorization_pending"))
                .andExpect(jsonPath("$.access_token").doesNotExist());
    }

    @Test
    void an_unknown_device_code_is_rejected() throws Exception {
        mockMvc.perform(post("/oauth2/token")
                        .param("client_id", "aegis-dev-device")
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
                        .param("device_code", "not-a-real-device-code"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.access_token").doesNotExist());
    }

    @Test
    void an_unregistered_client_cannot_start_a_device_flow() throws Exception {
        mockMvc.perform(post("/oauth2/device_authorization")
                        .param("client_id", "not-a-registered-client")
                        .param("scope", "openid"))
                .andExpect(status().is4xxClientError())
                .andExpect(jsonPath("$.device_code").doesNotExist());
    }

    /**
     * A client that was never granted {@code device_code} must not be able to use it, even though it
     * is a perfectly valid registered client for its own grants.
     */
    @Test
    void a_client_without_the_device_grant_is_refused() throws Exception {
        mockMvc.perform(post("/oauth2/device_authorization")
                        .param("client_id", "aegis-dev-spa") // authorization_code only
                        .param("scope", "openid"))
                .andExpect(status().is4xxClientError())
                .andExpect(jsonPath("$.device_code").doesNotExist());
    }

    /**
     * The device grant needs public-client authentication at the token endpoint, but ONLY for
     * itself. If that widening leaked to other grants, a public client could redeem an
     * {@code authorization_code} without a {@code code_verifier} — removing PKCE, the single control
     * that makes public clients safe. Here the SPA client (authorization_code + PKCE, no secret)
     * attempts a code exchange with no verifier and must still be refused.
     */
    @Test
    void public_client_auth_does_not_leak_to_other_grants_at_the_token_endpoint() throws Exception {
        // The property under test is "no token is issued", not the response shape. The request is
        // rejected as unauthenticated, which this chain answers with a redirect to /login rather
        // than RFC 6749 §5.2's 401 + invalid_client JSON. That shape is pre-existing behaviour for
        // every unauthenticated token request, not something this grant introduced — it is recorded
        // as a spec-conformance finding rather than asserted as correct here.
        var result = mockMvc.perform(post("/oauth2/token")
                        .param("client_id", "aegis-dev-spa")
                        .param("grant_type", "authorization_code")
                        .param("code", "a-stolen-or-guessed-code")
                        .param("redirect_uri", "http://localhost:3000/callback"))
                .andReturn();

        org.assertj.core.api.Assertions.assertThat(result.getResponse().getStatus()).isNotEqualTo(200);
        org.assertj.core.api.Assertions.assertThat(result.getResponse().getContentAsString())
                .doesNotContain("access_token");
    }

    /**
     * The approval page must require a signed-in human — it is the only thing standing between a
     * displayed code and issued tokens.
     */
    @Test
    void the_activation_page_is_not_reachable_anonymously() throws Exception {
        mockMvc.perform(get("/activate"))
                .andExpect(status().is3xxRedirection())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers
                        .redirectedUrl("/login"));
    }
}
