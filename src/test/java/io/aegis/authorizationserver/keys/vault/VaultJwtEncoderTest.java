package io.aegis.authorizationserver.keys.vault;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;

/**
 * Signs JWTs whose private key <b>never enters this process</b> (ADR-0015).
 *
 * <p>The single test that matters is {@link #the_token_it_produces_actually_verifies()}. Assembling a
 * JWS by hand is unforgiving: a wrong separator, base64 instead of base64url, a signature that still
 * carries Vault's version envelope — every one of those produces a token that <em>looks</em>
 * perfectly well-formed and fails verification at every resource server in the estate. Verifying the
 * output against the real public key is the only assertion that actually proves the assembly.
 */
class VaultJwtEncoderTest {

    private static KeyPair keyPair;

    @BeforeAll
    static void generateKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
    }

    /**
     * Stands in for Vault: signs locally with a key the encoder never sees, exactly as Vault would.
     * RSASSA-PKCS1-v1_5 over SHA-256, because that is what an {@code RS256} header promises.
     */
    private static TenantSigner signer(String kid) {
        return new TenantSigner() {
            @Override
            public String kid(String tenant) {
                return kid;
            }

            @Override
            public byte[] sign(String tenant, byte[] signingInput) {
                try {
                    Signature rsa = Signature.getInstance("SHA256withRSA");
                    rsa.initSign((RSAPrivateKey) keyPair.getPrivate());
                    rsa.update(signingInput);
                    return rsa.sign();
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
            }
        };
    }

    private static JwtEncoderParameters parameters() {
        return JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256).build(),
                JwtClaimsSet.builder()
                        .issuer("https://login.acme.com/acme")
                        .subject("user:alice@acme")
                        .audience(java.util.List.of("https://mcp.acme.com/files"))
                        .issuedAt(Instant.parse("2026-08-26T10:00:00Z"))
                        .expiresAt(Instant.parse("2026-08-26T10:05:00Z"))
                        .build());
    }

    @Test
    void the_token_it_produces_actually_verifies() throws Exception {
        VaultJwtEncoder encoder = new VaultJwtEncoder(signer("aegis-acme-v2"));

        Jwt jwt = encoder.encode(parameters());
        SignedJWT parsed = SignedJWT.parse(jwt.getTokenValue());

        assertThat(parsed.verify(new RSASSAVerifier((RSAPublicKey) keyPair.getPublic()))).isTrue();
    }

    @Test
    void the_header_carries_the_kid_and_RS256() throws Exception {
        Jwt jwt = new VaultJwtEncoder(signer("aegis-acme-v2")).encode(parameters());
        SignedJWT parsed = SignedJWT.parse(jwt.getTokenValue());

        assertThat(parsed.getHeader().getKeyID()).isEqualTo("aegis-acme-v2");
        assertThat(parsed.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
    }

    @Test
    void the_claims_survive_the_round_trip() throws Exception {
        Jwt jwt = new VaultJwtEncoder(signer("aegis-acme-v2")).encode(parameters());
        SignedJWT parsed = SignedJWT.parse(jwt.getTokenValue());

        assertThat(parsed.getJWTClaimsSet().getIssuer()).isEqualTo("https://login.acme.com/acme");
        assertThat(parsed.getJWTClaimsSet().getSubject()).isEqualTo("user:alice@acme");
        assertThat(parsed.getJWTClaimsSet().getAudience()).containsExactly("https://mcp.acme.com/files");
    }

    @Test
    void the_returned_Jwt_exposes_the_same_claims_spring_will_read() {
        Jwt jwt = new VaultJwtEncoder(signer("aegis-acme-v2")).encode(parameters());

        assertThat(jwt.getSubject()).isEqualTo("user:alice@acme");
        assertThat(jwt.getIssuer().toString()).isEqualTo("https://login.acme.com/acme");
        assertThat(jwt.getHeaders()).containsEntry("kid", "aegis-acme-v2");
    }

    @Test
    void the_tenant_is_derived_from_the_issuer_path_so_the_right_key_signs() {
        // Signing with another tenant's key would be a cross-tenant token forgery, so the tenant the
        // signer is asked for must come from the issuer being minted under.
        String[] seen = new String[1];
        TenantSigner recording = new TenantSigner() {
            @Override
            public String kid(String tenant) {
                seen[0] = tenant;
                return "aegis-" + tenant + "-v1";
            }

            @Override
            public byte[] sign(String tenant, byte[] signingInput) {
                seen[0] = tenant;
                return signer("x").sign(tenant, signingInput);
            }
        };

        new VaultJwtEncoder(recording).encode(parameters());
        assertThat(seen[0]).isEqualTo("acme");
    }

    @Test
    void a_root_issuer_with_no_tenant_path_signs_with_the_default_key() {
        String[] seen = new String[1];
        TenantSigner recording = new TenantSigner() {
            @Override
            public String kid(String tenant) {
                seen[0] = tenant;
                return "aegis-default-v1";
            }

            @Override
            public byte[] sign(String tenant, byte[] signingInput) {
                return signer("x").sign(tenant, signingInput);
            }
        };

        new VaultJwtEncoder(recording).encode(JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS256).build(),
                JwtClaimsSet.builder()
                        .issuer("https://login.acme.com")
                        .subject("s")
                        .issuedAt(Instant.now())
                        .expiresAt(Instant.now().plusSeconds(60))
                        .build()));

        assertThat(seen[0]).isEqualTo("default");
    }

    @Test
    void refuses_an_algorithm_it_cannot_honour() {
        // Vault is asked for pkcs1v15/sha2-256. Emitting an ES256 or RS512 header over an RS256
        // signature would produce a token that never verifies, so it fails here instead.
        assertThatThrownBy(() -> new VaultJwtEncoder(signer("k")).encode(JwtEncoderParameters.from(
                JwsHeader.with(SignatureAlgorithm.RS512).build(),
                JwtClaimsSet.builder().issuer("https://login.acme.com/acme").subject("s")
                        .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build())))
                .isInstanceOf(org.springframework.security.oauth2.jwt.JwtEncodingException.class);
    }
}
