package io.aegis.authorizationserver.dpop;

import com.nimbusds.jose.jwk.JWK;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

/**
 * Binds access tokens to the key that proved possession, and refuses a bearer token to any client
 * that is required to be sender-constrained (ADR-0017).
 *
 * <p><b>Why agents specifically.</b> A bearer token is a bearer token: whoever holds it may use it.
 * For a human in a browser the exposure surface is well understood. An agent is different in kind —
 * it processes attacker-influenceable content (documents, tool results, web pages) inside the same
 * context that holds its credentials, so prompt injection can exfiltrate a token through an entirely
 * legitimate-looking tool call. Binding the token to a key the attacker never obtains converts the
 * most likely agent compromise from "silent, durable account takeover" into "a failed request".
 *
 * <p><b>What Spring supplies and what it does not.</b> Spring Security 7.1 verifies a DPoP proof when
 * one is presented — the verified proof arrives via {@link OAuth2TokenContext#DPOP_PROOF_KEY} — but it
 * never <em>requires</em> one, and it does not write the {@code cnf} claim that makes the binding
 * visible to a resource server. Both are supplied here.
 *
 * <p>Every token exchange hop re-binds to the key presenting <em>that</em> request, so a stolen
 * intermediate token in a delegation chain is unusable by the thief.
 */
public class SenderConstraintCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    /** Client setting marking a client as required to be sender-constrained. */
    public static final String DPOP_REQUIRED_SETTING = "aegis.dpop.required";

    private static final String INVALID_DPOP_PROOF = "invalid_dpop_proof";

    @Override
    public void customize(JwtEncodingContext context) {
        Object proof = context.get(OAuth2TokenContext.DPOP_PROOF_KEY);

        if (proof == null) {
            if (requiresSenderConstraint(context.getRegisteredClient())) {
                throw new OAuth2AuthenticationException(new OAuth2Error(INVALID_DPOP_PROOF,
                        "this client must present a DPoP proof; bearer tokens are not issued to it",
                        null));
            }
            return; // human/interactive clients may still use bearer
        }

        if (!(proof instanceof Jwt proofJwt)) {
            throw new OAuth2AuthenticationException(new OAuth2Error(INVALID_DPOP_PROOF,
                    "unrecognised DPoP proof representation", null));
        }

        context.getClaims().claim("cnf", confirmation(thumbprintOf(proofJwt)));
    }

    private static Map<String, Object> confirmation(String thumbprint) {
        Map<String, Object> cnf = new LinkedHashMap<>();
        cnf.put("jkt", thumbprint);
        return cnf;
    }

    /**
     * RFC 7638 thumbprint of the proof's public key.
     *
     * <p>Deliberately the thumbprint and not the {@code kid}: a key id is chosen by the client, so
     * binding to it would let an attacker present any key claiming the same id. A thumbprint is
     * derived from the key material itself and cannot be spoofed.
     */
    private static String thumbprintOf(Jwt proof) {
        Object jwkHeader = proof.getHeaders().get("jwk");
        if (!(jwkHeader instanceof Map<?, ?> jwkMap)) {
            // Failing open here would hand an UNBOUND token to a client that believes it is
            // protected — the worst outcome available, because nobody would notice.
            throw new OAuth2AuthenticationException(new OAuth2Error(INVALID_DPOP_PROOF,
                    "DPoP proof carries no jwk header", null));
        }
        try {
            @SuppressWarnings("unchecked")
            JWK jwk = JWK.parse((Map<String, Object>) jwkMap);
            if (jwk.isPrivate()) {
                // A proof header must carry the public key. A client sending its private key is
                // either catastrophically broken or probing; binding to it would be nonsense.
                throw new OAuth2AuthenticationException(new OAuth2Error(INVALID_DPOP_PROOF,
                        "DPoP proof jwk header must contain a public key", null));
            }
            return jwk.computeThumbprint().toString();
        } catch (OAuth2AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            throw new OAuth2AuthenticationException(new OAuth2Error(INVALID_DPOP_PROOF,
                    "DPoP proof jwk header is not a valid JWK", null));
        }
    }

    private static boolean requiresSenderConstraint(RegisteredClient client) {
        if (client == null) {
            return false;
        }
        Object setting = client.getClientSettings().getSetting(DPOP_REQUIRED_SETTING);
        return setting instanceof Boolean required && required;
    }
}
