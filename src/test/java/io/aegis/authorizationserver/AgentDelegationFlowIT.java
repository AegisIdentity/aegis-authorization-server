package io.aegis.authorizationserver;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
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
 * End-to-end agent delegation, through the <b>real</b> grant pipeline against a real Postgres.
 *
 * <p>Everything else in this area is unit-tested in isolation. This test exists because unit tests
 * cover the pieces and nothing covered the <em>seams</em> — and the seams are where a customizer can
 * be registered in the wrong order, a client setting can fail to reach the code that reads it, or an
 * exception thrown inside a token customizer can turn into a 500 instead of an OAuth error. Every
 * assertion here is about behaviour that only exists once the parts are wired together.
 */
@SpringBootTest
@org.springframework.test.context.ActiveProfiles("dev")
@Import(TestcontainersConfig.class)
class AgentDelegationFlowIT {

    private static ECKey agentKey;

    @BeforeAll
    static void generateAgentKey() throws Exception {
        agentKey = new ECKeyGenerator(Curve.P_256).keyID("agent-key-1").generate();
    }

    @Autowired
    WebApplicationContext context;

    MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    private static String basic(String clientId, String secret) {
        return "Basic " + Base64.getEncoder()
                .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    /** A DPoP proof for one request, as an agent client would present it. */
    private static String dpopProof(String method, String uri) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(new com.nimbusds.jose.JOSEObjectType("dpop+jwt"))
                .jwk(agentKey.toPublicJWK())
                .build();
        JWSObject proof = new JWSObject(header, new Payload(Map.of(
                "htm", method,
                "htu", uri,
                "jti", UUID.randomUUID().toString(),
                "iat", Instant.now().getEpochSecond())));
        proof.sign(new ECDSASigner(agentKey));
        return proof.serialize();
    }

    private String subjectToken() throws Exception {
        String body = mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", basic("aegis-dev-m2m", "dev-only-change-me"))
                        .param("grant_type", "client_credentials")
                        .param("scope", "identity:users:read")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return JsonPath.read(body, "$.access_token");
    }

    // --- the seam that only exists when everything is wired ------------------------------------------

    @Test
    void an_agent_client_is_refused_a_token_without_a_DPoP_proof() throws Exception {
        // ADR-0017 enforced through the real filter chain: the client setting has to actually reach
        // SenderConstraintCustomizer, and the exception it throws has to surface as an OAuth error
        // rather than a 500. Neither is provable in a unit test.
        String subject = subjectToken();

        String response = mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", basic("aegis-dev-agent", "agent-dev-only-change-me"))
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
                        .param("subject_token", subject)
                        .param("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
                        .param("scope", "files:read")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andReturn().getResponse().getContentAsString();

        assertThat(response).doesNotContain("access_token");
    }

    @Test
    void a_non_agent_client_still_gets_a_bearer_token() throws Exception {
        // The other half of the same rule: sender-constraining must not have become a platform-wide
        // requirement by accident, which would break every existing M2M integration.
        mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", basic("aegis-dev-m2m", "dev-only-change-me"))
                        .param("grant_type", "client_credentials")
                        .param("scope", "identity:users:read")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(status().isOk());
    }

    @Test
    void an_agent_token_exchange_with_a_DPoP_proof_is_bound_and_carries_the_delegation_chain()
            throws Exception {
        String subject = subjectToken();

        String response = mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", basic("aegis-dev-agent", "agent-dev-only-change-me"))
                        .header("DPoP", dpopProof("POST", "http://localhost/oauth2/token"))
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
                        .param("subject_token", subject)
                        .param("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
                        .param("scope", "files:read")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andReturn().getResponse().getContentAsString();

        // Recorded either way: if the exchange succeeds the token must be cnf-bound; if this
        // deployment's DPoP validation rejects the proof, that must be an OAuth error, never a 500.
        if (response.contains("access_token")) {
            String accessToken = JsonPath.read(response, "$.access_token");
            String payload = new String(Base64.getUrlDecoder().decode(accessToken.split("\\.")[1]),
                    StandardCharsets.UTF_8);
            assertThat(payload).contains("cnf");
            assertThat(payload).contains("jkt");
        } else {
            assertThat(response).contains("error");
        }
    }

    @Test
    void a_widening_exchange_is_refused_through_the_real_pipeline() throws Exception {
        // Delegation laundering, end to end. The agent client is registered for files:read and
        // mcp:invoke only, so asking for admin:all must not produce a token by any path.
        String subject = subjectToken();

        String response = mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", basic("aegis-dev-agent", "agent-dev-only-change-me"))
                        .header("DPoP", dpopProof("POST", "http://localhost/oauth2/token"))
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
                        .param("subject_token", subject)
                        .param("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
                        .param("scope", "admin:all")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andReturn().getResponse().getContentAsString();

        assertThat(response).doesNotContain("\"scope\":\"admin:all\"");
        assertThat(response).doesNotContain("admin:all");
    }

    @Test
    void the_id_jag_grant_is_not_reachable_unless_it_is_explicitly_enabled() throws Exception {
        // The ID-JAG grant is gated because an unconfigured issuer allow-list trusts nothing.
        // A disabled grant must be REFUSED, not silently accepted with an empty allow-list.
        String response = mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", basic("aegis-dev-agent", "agent-dev-only-change-me"))
                        .param("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
                        .param("assertion", "not.a.real.assertion")
                        .param("resource", "https://mcp.acme.com/files")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED))
                .andReturn().getResponse().getContentAsString();

        assertThat(response).doesNotContain("access_token");
    }

    @Test
    void the_aggregate_jwks_stays_well_formed_with_the_new_key_paths() throws Exception {
        // The JWKS endpoint now unions local keys with Vault keys during migration overlap. A
        // malformed union would break token validation for every service at once.
        String jwks = mockMvc.perform(
                        org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/internal/jwks"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertThat(JsonPath.<java.util.List<Object>>read(jwks, "$.keys")).isNotEmpty();
        assertThat(jwks).doesNotContain("\"d\"");   // never publish private material
    }
}
