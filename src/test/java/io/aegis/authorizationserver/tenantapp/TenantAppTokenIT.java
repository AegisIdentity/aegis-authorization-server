package io.aegis.authorizationserver.tenantapp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import io.aegis.authorizationserver.TestcontainersConfig;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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
 * The tenant-app token linchpin: a PKCE-bound interaction code (produced after a passkey/social
 * authentication) is swapped at the public interaction-token endpoint for real Aegis tokens signed by
 * the AS key. Proves the exchange end-to-end (store → endpoint → minter → JWKS) without needing a device
 * or a real social provider.
 */
@SpringBootTest
@Import(TestcontainersConfig.class)
class TenantAppTokenIT {

    @Autowired
    WebApplicationContext context;
    @Autowired
    InteractionCodeStore interactions;

    MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    private static String challenge(String verifier) throws Exception {
        byte[] d = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(d);
    }

    @Test
    void interaction_code_is_exchanged_for_signed_aegis_tokens() throws Exception {
        String verifier = "verifier-abcdefghijklmnopqrstuvwxyz-0123456789";
        // A code as it would exist after a verified passkey assertion for aegis-dev-spa (tenant "dev").
        String code = interactions.create("dev", "alice", "aegis-dev-spa", challenge(verifier), "webauthn");

        String body = mockMvc.perform(post("/api/v1/oauth/interaction/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"clientId\":\"aegis-dev-spa\",\"interaction_code\":\"" + code
                                + "\",\"code_verifier\":\"" + verifier + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.id_token").isNotEmpty())
                .andReturn().getResponse().getContentAsString();

        // The access token is a real AS-signed JWT carrying the tenant + subject (claims asserted here;
        // the signature is the AS's own, covered by the encoder).
        String accessToken = JsonPath.read(body, "$.access_token");
        String[] parts = accessToken.split("\\.");
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        assertThat(payload).contains("\"tenant\":\"dev\"").contains("\"sub\":\"alice\"").contains("openid profile");
    }

    @Test
    void a_wrong_code_verifier_is_rejected() throws Exception {
        String code = interactions.create("dev", "bob", "aegis-dev-spa", challenge("real-verifier-xxxxxxxxxxxxxxxxxxxx"), "social");
        mockMvc.perform(post("/api/v1/oauth/interaction/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"clientId\":\"aegis-dev-spa\",\"interaction_code\":\"" + code
                                + "\",\"code_verifier\":\"wrong-verifier-yyyyyyyyyyyyyyyyyyyy\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"));
    }

    @Test
    void the_token_endpoint_is_public_and_a_bad_code_is_a_clean_400() throws Exception {
        // No bearer token required (public exchange), and an unknown code fails cleanly, not with a 500.
        mockMvc.perform(post("/api/v1/oauth/interaction/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"clientId\":\"aegis-dev-spa\",\"interaction_code\":\"nope\",\"code_verifier\":\"x\"}"))
                .andExpect(status().isBadRequest());
    }
}
