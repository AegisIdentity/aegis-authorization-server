package io.aegis.authorizationserver.tenantapp;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import io.aegis.authorizationserver.auth.TenantJwkSource;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * The tenant-app token contract: minted tokens carry the tenant's PUBLIC issuer
 * ({@code <public-issuer-base>/<tenant>} — the gateway front-door) and are signed with that
 * tenant's own key, so a tenant's backend can validate them via standard OIDC discovery and
 * Aegis resource servers via the aggregate JWKS.
 */
class AegisTokenMinterTest {

    private final TenantJwkSource jwkSource = new TenantJwkSource();
    private final AegisTokenMinter minter = new AegisTokenMinter(jwkSource, "http://localhost:8080/");

    private NimbusJwtDecoder decoderOver(com.nimbusds.jose.jwk.JWKSet keys) {
        return NimbusJwtDecoder.withJwkSource(
                (com.nimbusds.jose.jwk.JWKSelector selector, SecurityContext ctx) ->
                        selector.select(keys))
                .build();
    }

    @Test
    void minted_tokens_carry_the_per_tenant_gateway_issuer_and_are_signed_with_the_tenant_key() {
        AegisTokenMinter.Tokens tokens = minter.mint("acme", "alice", "acme-app", "webauthn");

        // Validates against acme's OWN key — the one /{tenant}/oauth2/jwks publishes.
        Jwt access = decoderOver(jwkSource.jwkSetFor("acme")).decode(tokens.accessToken());
        assertThat(access.getIssuer().toString()).isEqualTo("http://localhost:8080/acme");
        assertThat(access.getSubject()).isEqualTo("alice");
        assertThat(access.getClaimAsString("tenant")).isEqualTo("acme");
        assertThat(access.getAudience()).containsExactly("acme-app");
        assertThat(access.getHeaders().get("kid").toString()).startsWith("aegis-acme-");

        Jwt id = decoderOver(jwkSource.jwkSetFor("acme")).decode(tokens.idToken());
        assertThat(id.getClaimAsString("azp")).isEqualTo("acme-app");
        assertThat(id.getClaimAsStringList("amr")).containsExactly("webauthn");
    }

    @Test
    void minted_tokens_also_validate_against_the_aggregate_jwks_resource_servers_fetch() {
        AegisTokenMinter.Tokens tokens = minter.mint("globex", "bob", "globex-app", "social");

        Jwt access = decoderOver(jwkSource.allKeys()).decode(tokens.accessToken());
        assertThat(access.getIssuer().toString()).isEqualTo("http://localhost:8080/globex");
        assertThat(access.getClaimAsString("scope")).isEqualTo("openid profile");
    }

    @Test
    void a_token_for_tenant_a_does_not_validate_with_tenant_bs_key() {
        AegisTokenMinter.Tokens tokens = minter.mint("acme", "alice", "acme-app", "webauthn");
        com.nimbusds.jose.jwk.JWKSet otherTenantKeys = jwkSource.jwkSetFor("globex");

        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> decoderOver(otherTenantKeys).decode(tokens.accessToken()))
                .isInstanceOf(org.springframework.security.oauth2.jwt.JwtException.class);
    }
}
