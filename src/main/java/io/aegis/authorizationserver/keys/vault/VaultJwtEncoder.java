package io.aegis.authorizationserver.keys.vault;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtEncodingException;

/**
 * A {@link JwtEncoder} whose signing key <b>never enters this process</b>.
 *
 * <p>{@code NimbusJwtEncoder} cannot be reused here: it takes a {@code JWKSource}, pulls the private
 * key out of it and signs locally. Under ADR-0015 there is no private key to pull — Transit keys are
 * created {@code exportable=false} — so the JWS is assembled here and only the <em>signing input</em>
 * leaves for Vault.
 *
 * <p>That is precisely the improvement over the KMS scheme this replaces: previously the private key
 * was unwrapped into application memory and cached, so a memory-disclosure bug could yield a tenant's
 * signing key. Now it was never here to disclose.
 *
 * <p>Hand-assembling a JWS is unforgiving — a wrong separator, base64 instead of base64url, or a
 * signature still wrapped in Vault's version envelope all produce a token that looks well-formed and
 * fails verification everywhere. The encoder's test therefore verifies its output against the real
 * public key rather than asserting on the string shape.
 */
public class VaultJwtEncoder implements JwtEncoder {

    private static final String DEFAULT_TENANT = "default";

    private final TenantSigner signer;

    public VaultJwtEncoder(TenantSigner signer) {
        this.signer = signer;
    }

    @Override
    public Jwt encode(JwtEncoderParameters parameters) throws JwtEncodingException {
        var claims = parameters.getClaims();
        var requestedHeaders = parameters.getJwsHeader();

        SignatureAlgorithm algorithm = requestedHeaders == null
                ? SignatureAlgorithm.RS256
                : (SignatureAlgorithm) requestedHeaders.getAlgorithm();
        if (algorithm != SignatureAlgorithm.RS256) {
            // Vault is asked for pkcs1v15 + sha2-256. Emitting any other alg in the header would
            // advertise a signature we did not produce, and the token would never verify.
            throw new JwtEncodingException(
                    "VaultJwtEncoder signs RS256 only, but " + algorithm + " was requested");
        }

        String tenant = tenantFromIssuer(claims.getClaimAsString("iss"));
        String kid = signer.kid(tenant);

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build();
        JWTClaimsSet claimsSet = toNimbus(claims.getClaims());

        Base64URL encodedHeader = header.toBase64URL();
        Base64URL encodedClaims = Base64URL.encode(claimsSet.toString());
        String signingInput = encodedHeader + "." + encodedClaims;

        byte[] signature = signer.sign(tenant, signingInput.getBytes(StandardCharsets.US_ASCII));
        String token = signingInput + "." + Base64URL.encode(signature);

        Map<String, Object> headers = new LinkedHashMap<>();
        headers.put("alg", JWSAlgorithm.RS256.getName());
        headers.put("kid", kid);

        return new Jwt(token, claims.getIssuedAt(), claims.getExpiresAt(), headers, claims.getClaims());
    }

    @SuppressWarnings("unchecked")
    private static JWTClaimsSet toNimbus(Map<String, Object> claims) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
        claims.forEach((name, value) -> {
            switch (name) {
                // Nimbus renders the registered temporal claims as NumericDate only via these
                // setters; passing an Instant through claim() would serialize an ISO string and
                // every verifier would reject the exp/iat.
                case "iat" -> builder.issueTime(Date.from((Instant) value));
                case "exp" -> builder.expirationTime(Date.from((Instant) value));
                case "nbf" -> builder.notBeforeTime(Date.from((Instant) value));
                case "aud" -> builder.audience(value instanceof List<?> list
                        ? list.stream().map(String::valueOf).toList()
                        : List.of(String.valueOf(value)));
                case "iss" -> builder.issuer(String.valueOf(value));
                case "sub" -> builder.subject(String.valueOf(value));
                case "jti" -> builder.jwtID(String.valueOf(value));
                default -> builder.claim(name, value);
            }
        });
        return builder.build();
    }

    /**
     * {@code https://host/acme} → {@code acme}; a root issuer → {@code default}.
     *
     * <p>Signing with another tenant's key would be a cross-tenant token forgery, so the tenant is
     * taken from the issuer the token is actually being minted under — the same rule
     * {@code TenantJwkSource} already applies.
     */
    static String tenantFromIssuer(String issuer) {
        if (issuer == null || issuer.isBlank()) {
            return DEFAULT_TENANT;
        }
        try {
            String path = java.net.URI.create(issuer).getPath();
            if (path == null || path.isBlank() || "/".equals(path)) {
                return DEFAULT_TENANT;
            }
            String[] segments = path.split("/");
            for (int i = segments.length - 1; i >= 0; i--) {
                if (!segments[i].isBlank()) {
                    return segments[i];
                }
            }
            return DEFAULT_TENANT;
        } catch (IllegalArgumentException e) {
            return DEFAULT_TENANT;
        }
    }
}
