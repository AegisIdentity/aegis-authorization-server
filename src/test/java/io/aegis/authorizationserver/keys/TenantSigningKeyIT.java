package io.aegis.authorizationserver.keys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.jwk.RSAKey;
import io.aegis.authorizationserver.TestcontainersConfig;
import io.aegis.authorizationserver.auth.TenantJwkSource;
import io.aegis.commons.crypto.FieldEncryption;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;

/**
 * Proves the durable key path end-to-end against a real Postgres: the schema exists, private key
 * material is genuinely encrypted at rest, and the database itself refuses a second active key for
 * a tenant (the guarantee that makes concurrent creation across replicas safe).
 */
@SpringBootTest
@ActiveProfiles("dev")
@Import(TestcontainersConfig.class)
class TenantSigningKeyIT {

    @Autowired
    TenantKeyStore store;

    @Autowired
    TenantSigningKeyRepository repository;

    @Autowired
    FieldEncryption encryption;

    @Autowired
    TenantJwkSource jwkSource;

    private static String uniqueTenant() {
        return "t" + UUID.randomUUID().toString().substring(0, 8);
    }

    @Test
    void a_created_key_is_persisted_and_reloads_with_its_private_half_intact() throws Exception {
        String tenant = uniqueTenant();

        RSAKey created = store.saveIfAbsent(tenant, generateFor(tenant));
        RSAKey reloaded = store.findActive(tenant).orElseThrow();

        assertThat(reloaded.getKeyID()).isEqualTo(created.getKeyID());
        // The private half must survive the round trip, or the key cannot sign after a restart.
        assertThat(reloaded.toRSAPrivateKey()).isNotNull();
        assertThat(reloaded.toRSAPublicKey()).isEqualTo(created.toRSAPublicKey());
    }

    @Test
    void the_private_key_is_encrypted_at_rest_not_merely_encoded() throws Exception {
        String tenant = uniqueTenant();
        RSAKey created = store.saveIfAbsent(tenant, generateFor(tenant));

        TenantSigningKey row = repository.findByTenantAndActiveTrue(tenant).orElseThrow();
        String storedPrivate = row.getPrivateKeyEncrypted();

        // Ciphertext, not base64 PKCS#8: a database read alone must not yield a usable signing key.
        assertThat(FieldEncryption.isEncrypted(storedPrivate)).isTrue();
        String plainPkcs8 = java.util.Base64.getEncoder()
                .encodeToString(created.toRSAPrivateKey().getEncoded());
        assertThat(storedPrivate).doesNotContain(plainPkcs8);
        // ...and it decrypts back to exactly that under the configured key.
        assertThat(encryption.decrypt(storedPrivate)).isEqualTo(plainPkcs8);
    }

    @Test
    void the_public_half_is_stored_in_the_clear_because_jwks_publishes_it_anyway() {
        String tenant = uniqueTenant();
        store.saveIfAbsent(tenant, generateFor(tenant));

        TenantSigningKey row = repository.findByTenantAndActiveTrue(tenant).orElseThrow();
        assertThat(FieldEncryption.isEncrypted(row.getPublicKey())).isFalse();
    }

    @Test
    void the_database_refuses_a_second_active_key_for_the_same_tenant() {
        String tenant = uniqueTenant();
        store.saveIfAbsent(tenant, generateFor(tenant));

        // Bypass the store's race handling and attempt a raw duplicate insert: the partial unique
        // index is what makes concurrent creation across replicas converge instead of forking.
        RSAKey second = generateFor(tenant);
        TenantSigningKey duplicate = new TenantSigningKey(
                tenant, second.getKeyID(), "cHVibGlj", encryption.encrypt("cHJpdmF0ZQ=="));

        assertThatThrownBy(() -> repository.saveAndFlush(duplicate))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void saveIfAbsent_is_idempotent_and_returns_the_stored_key() {
        String tenant = uniqueTenant();

        RSAKey first = store.saveIfAbsent(tenant, generateFor(tenant));
        RSAKey second = store.saveIfAbsent(tenant, generateFor(tenant));

        assertThat(second.getKeyID()).isEqualTo(first.getKeyID());
        assertThat(repository.findByTenant(tenant)).hasSize(1);
    }

    @Test
    void the_wired_jwk_source_uses_the_durable_store_so_keys_outlive_the_process() {
        String tenant = uniqueTenant();

        String viaSource = jwkSource.jwkSetFor(tenant).getKeys().get(0).getKeyID();

        // A brand-new source over the same store is what a restarted pod sees.
        String afterRestart = new TenantJwkSource(store).jwkSetFor(tenant).getKeys().get(0).getKeyID();

        assertThat(afterRestart).isEqualTo(viaSource);
        assertThat(repository.findByTenantAndActiveTrue(tenant)).isPresent();
    }

    /** Generates a key shaped the way TenantJwkSource does, without reaching into its internals. */
    private static RSAKey generateFor(String tenant) {
        try {
            var generator = java.security.KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            var pair = generator.generateKeyPair();
            return new RSAKey.Builder((java.security.interfaces.RSAPublicKey) pair.getPublic())
                    .privateKey((java.security.interfaces.RSAPrivateKey) pair.getPrivate())
                    .keyID("aegis-" + tenant + "-" + UUID.randomUUID().toString().substring(0, 8))
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
