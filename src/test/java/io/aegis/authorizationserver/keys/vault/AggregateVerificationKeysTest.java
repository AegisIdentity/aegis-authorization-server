package io.aegis.authorizationserver.keys.vault;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.jwk.JWK;
import io.aegis.authorizationserver.auth.TenantJwkSource;
import io.aegis.authorizationserver.keys.InMemoryTenantKeyStore;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

/**
 * The published JWKS and the AS's own decoder must draw from <b>one</b> source.
 *
 * <p>This is a regression test for a real defect. When they were separate, the AS published a Vault
 * key that downstream services used happily, then rejected tokens signed with that very key at its
 * own {@code /userinfo} — because the decoder still only knew the local key set. The symptom was a
 * bare 401 on an endpoint that had worked minutes earlier, which is a miserable thing to trace back
 * to two lists that quietly disagreed.
 */
class AggregateVerificationKeysTest {

    /** Stands in for "Vault is not configured". */
    private static <T> ObjectProvider<T> absent() {
        return new ObjectProvider<>() {
            @Override
            public T getObject(Object... args) {
                throw new UnsupportedOperationException();
            }

            @Override
            public T getObject() {
                throw new UnsupportedOperationException();
            }

            @Override
            public T getIfAvailable() {
                return null;
            }

            @Override
            public T getIfUnique() {
                return null;
            }
        };
    }

    @Test
    void without_vault_it_returns_the_local_keys() {
        TenantJwkSource local = new TenantJwkSource(new InMemoryTenantKeyStore());
        AggregateVerificationKeys keys = new AggregateVerificationKeys(local, absent());

        List<JWK> all = keys.all();

        assertThat(all).isNotEmpty();
        assertThat(all).allSatisfy(jwk -> assertThat(jwk.getKeyID()).startsWith("aegis-"));
    }

    @Test
    void it_never_exposes_private_material() {
        // This same list is published at /internal/jwks, so a private key here would be published.
        TenantJwkSource local = new TenantJwkSource(new InMemoryTenantKeyStore());
        AggregateVerificationKeys keys = new AggregateVerificationKeys(local, absent());

        assertThat(new com.nimbusds.jose.jwk.JWKSet(keys.all()).toJSONObject(true).toString())
                .doesNotContain("\"d\"");
    }

    @Test
    void the_default_key_exists_even_before_any_token_has_been_minted() {
        // An early-booting resource server must never cache an empty key set — it would then reject
        // every token until its own cache expired.
        TenantJwkSource local = new TenantJwkSource(new InMemoryTenantKeyStore());

        assertThat(new AggregateVerificationKeys(local, absent()).all()).isNotEmpty();
    }

    @Test
    void keys_for_every_known_tenant_are_included() {
        TenantJwkSource local = new TenantJwkSource(new InMemoryTenantKeyStore());
        local.jwkSetFor("acme");
        local.jwkSetFor("globex");

        List<String> kids = new AggregateVerificationKeys(local, absent()).all().stream()
                .map(JWK::getKeyID).toList();

        assertThat(kids).anyMatch(kid -> kid.startsWith("aegis-acme-"));
        assertThat(kids).anyMatch(kid -> kid.startsWith("aegis-globex-"));
        assertThat(kids).anyMatch(kid -> kid.startsWith("aegis-default-"));
    }
}
