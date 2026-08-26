package io.aegis.authorizationserver.dpop;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;

/**
 * ADR-0017 — agent tokens must be sender-constrained.
 *
 * <p>A bearer token is a bearer token: whoever holds it may use it. An agent is different in kind
 * from a human in a browser because it processes attacker-influenceable content <em>inside the same
 * context that holds its credentials</em>, so prompt injection can exfiltrate a token through an
 * entirely legitimate-looking tool call. Binding the token to a key the attacker does not have turns
 * that from "silent, durable account takeover" into "a failed request".
 *
 * <p>Spring Security 7.1 verifies a DPoP proof when one is presented, but never <em>requires</em> one
 * and does not write the {@code cnf} claim. Both are supplied here.
 */
class SenderConstraintCustomizerTest {

    private static ECKey clientKey;
    private static ECKey otherKey;

    @BeforeAll
    static void keys() throws Exception {
        clientKey = new ECKeyGenerator(Curve.P_256).keyID("c1").generate();
        otherKey = new ECKeyGenerator(Curve.P_256).keyID("c2").generate();
    }

    private final SenderConstraintCustomizer customizer = new SenderConstraintCustomizer();

    private static RegisteredClient client(boolean dpopRequired) {
        ClientSettings.Builder settings = ClientSettings.builder();
        if (dpopRequired) {
            settings.setting(SenderConstraintCustomizer.DPOP_REQUIRED_SETTING, true);
        }
        return RegisteredClient.withId("c").clientId("agent-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .scope("files:read")
                .clientSettings(settings.build())
                .build();
    }

    /** A DPoP proof as SAS hands it to the token context: a Jwt whose header carries the public JWK. */
    private static Jwt proofWith(ECKey key) {
        return Jwt.withTokenValue("proof")
                .header("typ", "dpop+jwt")
                .header("jwk", key.toPublicJWK().toJSONObject())
                .claim("htm", "POST")
                .claim("htu", "https://login.acme.com/oauth2/token")
                .claim("jti", "proof-1")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
    }

    private static JwtEncodingContext context(RegisteredClient client, Jwt proof) {
        JwtEncodingContext.Builder builder = JwtEncodingContext
                .with(JwsHeader.with(SignatureAlgorithm.RS256), JwtClaimsSet.builder().subject("s"))
                .registeredClient(client)
                .principal(new TestingAuthenticationToken("agent:planner", null))
                .authorizedScopes(Set.of("files:read"))
                .tokenType(OAuth2TokenType.ACCESS_TOKEN);
        if (proof != null) {
            builder.put(OAuth2TokenContext.DPOP_PROOF_KEY, proof);
        }
        return builder.build();
    }

    // --- binding ---------------------------------------------------------------------------------

    @Test
    void a_presented_proof_binds_the_token_to_that_key() throws Exception {
        JwtEncodingContext ctx = context(client(true), proofWith(clientKey));

        customizer.customize(ctx);

        @SuppressWarnings("unchecked")
        Map<String, Object> cnf = (Map<String, Object>) ctx.getClaims().build().getClaims().get("cnf");
        assertThat(cnf.get("jkt")).isEqualTo(clientKey.toPublicJWK().computeThumbprint().toString());
    }

    @Test
    void the_thumbprint_is_the_RFC_7638_thumbprint_not_the_key_id() throws Exception {
        // Binding to a client-chosen kid would let an attacker present any key claiming the same id.
        // The thumbprint is derived from the key material itself, so it cannot be spoofed.
        JwtEncodingContext ctx = context(client(true), proofWith(clientKey));
        customizer.customize(ctx);

        @SuppressWarnings("unchecked")
        Map<String, Object> cnf = (Map<String, Object>) ctx.getClaims().build().getClaims().get("cnf");
        assertThat(cnf.get("jkt")).isNotEqualTo("c1");
        assertThat(cnf.get("jkt")).isEqualTo(clientKey.toPublicJWK().computeThumbprint().toString());
    }

    @Test
    void two_different_keys_produce_two_different_bindings() throws Exception {
        JwtEncodingContext a = context(client(true), proofWith(clientKey));
        JwtEncodingContext b = context(client(true), proofWith(otherKey));
        customizer.customize(a);
        customizer.customize(b);

        assertThat(thumbprint(a)).isNotEqualTo(thumbprint(b));
    }

    @Test
    void an_exchange_re_binds_to_the_key_presenting_it_not_the_original() throws Exception {
        // Each hop of a delegation chain binds to ITS OWN key, so a stolen intermediate token is
        // unusable by the thief even though it was legitimately issued.
        JwtEncodingContext hop = context(client(true), proofWith(otherKey));
        customizer.customize(hop);

        assertThat(thumbprint(hop)).isEqualTo(otherKey.toPublicJWK().computeThumbprint().toString());
    }

    // --- enforcement -----------------------------------------------------------------------------

    @Test
    void a_client_that_requires_dpop_is_refused_a_bearer_token() {
        assertThatThrownBy(() -> customizer.customize(context(client(true), null)))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .hasMessageContaining("DPoP");
    }

    @Test
    void a_client_that_does_not_require_dpop_still_gets_a_bearer_token() {
        // Human interactive sessions may keep using bearer (ADR-0017), so this must not become a
        // platform-wide requirement by accident.
        JwtEncodingContext ctx = context(client(false), null);

        assertThatCode(() -> customizer.customize(ctx)).doesNotThrowAnyException();
        assertThat(ctx.getClaims().build().getClaims()).doesNotContainKey("cnf");
    }

    @Test
    void a_client_that_does_not_require_dpop_is_still_bound_when_it_presents_a_proof() throws Exception {
        // Opportunistic binding: if a client goes to the trouble of proving possession, honour it.
        JwtEncodingContext ctx = context(client(false), proofWith(clientKey));
        customizer.customize(ctx);

        assertThat(thumbprint(ctx)).isEqualTo(clientKey.toPublicJWK().computeThumbprint().toString());
    }

    @Test
    void a_proof_without_a_jwk_header_is_refused_rather_than_silently_unbound() {
        // Failing open here would issue an UNBOUND token to a client that believes it is protected —
        // the worst of both worlds, because nobody would notice.
        Jwt malformed = Jwt.withTokenValue("proof")
                .header("typ", "dpop+jwt")
                .claim("jti", "x")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60))
                .build();

        assertThatThrownBy(() -> customizer.customize(context(client(true), malformed)))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }

    @Test
    void an_unparseable_jwk_header_is_refused() {
        Jwt malformed = Jwt.withTokenValue("proof")
                .header("typ", "dpop+jwt")
                .header("jwk", Map.of("kty", "nonsense"))
                .claim("jti", "x")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60))
                .build();

        assertThatThrownBy(() -> customizer.customize(context(client(true), malformed)))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }

    @Test
    void a_private_key_in_the_proof_header_is_refused() {
        // A proof header must carry the PUBLIC key. A client sending its private key is either
        // catastrophically broken or probing, and binding to it would be nonsense either way.
        Jwt leaky = Jwt.withTokenValue("proof")
                .header("typ", "dpop+jwt")
                .header("jwk", clientKey.toJSONObject())   // includes "d" — the private half
                .claim("jti", "x")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60))
                .build();

        assertThatThrownBy(() -> customizer.customize(context(client(true), leaky)))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }

    @SuppressWarnings("unchecked")
    private static Object thumbprint(JwtEncodingContext ctx) {
        Map<String, Object> cnf = (Map<String, Object>) ctx.getClaims().build().getClaims().get("cnf");
        return cnf == null ? null : cnf.get("jkt");
    }
}
