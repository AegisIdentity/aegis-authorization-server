package io.aegis.authorizationserver.auth;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.Test;

/**
 * The tenant-key isolation contract: each tenant gets its own stable key with a tenant-prefixed kid,
 * and {@link TenantJwkSource#allKeys()} is the validation-side union of everything generated —
 * what the aggregate JWKS endpoint publishes so resource servers can verify any tenant's tokens.
 */
class TenantJwkSourceTest {

    private final TenantJwkSource source = new TenantJwkSource();

    @Test
    void each_tenant_gets_its_own_stable_key_with_a_tenant_prefixed_kid() {
        JWKSet acme = source.jwkSetFor("acme");
        JWKSet globex = source.jwkSetFor("globex");

        assertThat(acme.getKeys()).hasSize(1);
        assertThat(acme.getKeys().get(0).getKeyID()).startsWith("aegis-acme-");
        assertThat(globex.getKeys().get(0).getKeyID()).startsWith("aegis-globex-");
        // Distinct tenants, distinct keys — the cryptographic isolation the design promises.
        assertThat(acme.getKeys().get(0).getKeyID()).isNotEqualTo(globex.getKeys().get(0).getKeyID());
        // Stable on re-request (compute-if-absent, not regenerate).
        assertThat(source.jwkSetFor("acme").getKeys().get(0).getKeyID())
                .isEqualTo(acme.getKeys().get(0).getKeyID());
    }

    @Test
    void a_blank_or_null_tenant_maps_to_the_default_key() {
        String nullKid = source.jwkSetFor(null).getKeys().get(0).getKeyID();
        String blankKid = source.jwkSetFor(" ").getKeys().get(0).getKeyID();
        assertThat(nullKid).startsWith("aegis-default-").isEqualTo(blankKid);
    }

    @Test
    void allKeys_is_the_union_of_every_generated_key() {
        source.jwkSetFor(null);
        source.jwkSetFor("acme");
        source.jwkSetFor("globex");

        JWKSet all = source.allKeys();

        assertThat(all.getKeys()).hasSize(3);
        assertThat(all.getKeys().stream().map(k -> k.getKeyID()))
                .anyMatch(kid -> kid.startsWith("aegis-default-"))
                .anyMatch(kid -> kid.startsWith("aegis-acme-"))
                .anyMatch(kid -> kid.startsWith("aegis-globex-"));
        // The aggregate endpoint publishes public keys only — the JSON export must carry no private material.
        assertThat(all.toJSONObject(true).toString()).doesNotContain("\"d\"");
    }
}
