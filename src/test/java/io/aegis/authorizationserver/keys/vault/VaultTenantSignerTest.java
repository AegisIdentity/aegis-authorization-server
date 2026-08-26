package io.aegis.authorizationserver.keys.vault;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.jwk.JWK;
import io.aegis.commons.tenant.TenantContext;
import io.aegis.commons.vault.TenantVaultPaths;
import io.aegis.commons.vault.VaultClient;
import io.aegis.commons.vault.VaultIsolation;
import io.aegis.commons.vault.VaultTransit;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** The Vault-backed signer: private key never fetched, public material published per version. */
class VaultTenantSignerTest {

    private static String publicPem;

    @BeforeAll
    static void generate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        publicPem = "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pair.getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----";
    }

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    /** Records paths so the tests can assert tenant scoping without a Vault. */
    private static final class RecordingClient implements VaultClient {
        final List<String> paths = new ArrayList<>();
        final Map<String, Map<String, Object>> responses = new LinkedHashMap<>();
        /** When true, a create-key write makes the key readable afterwards, as Vault would. */
        boolean createsKeyOnWrite;
        String publicPem;

        @Override
        public Map<String, Object> read(String path, String namespace) {
            paths.add("READ " + path);
            return responses.getOrDefault(path, Map.of());
        }

        @Override
        public Map<String, Object> write(String path, Map<String, Object> data, String namespace) {
            paths.add("WRITE " + path);
            if (createsKeyOnWrite && path.contains("/transit/keys/") && !path.endsWith("/rotate")) {
                responses.put(path, Map.of("data", Map.of("latest_version", 1,
                        "keys", Map.of("1", Map.of("public_key", publicPem)))));
            }
            return responses.getOrDefault(path, Map.of());
        }

        @Override
        public void delete(String path, String namespace) {
            paths.add("DELETE " + path);
        }
    }

    private RecordingClient client;
    private VaultTenantSigner signer;

    private void setUpWith(int latestVersion) {
        client = new RecordingClient();
        Map<String, Object> keys = new LinkedHashMap<>();
        for (int v = 1; v <= latestVersion; v++) {
            keys.put(String.valueOf(v), Map.of("public_key", publicPem));
        }
        client.responses.put("aegis/transit/keys/acme-token-signing",
                Map.of("data", Map.of("latest_version", latestVersion, "keys", keys)));
        client.responses.put("aegis/transit/sign/acme-token-signing",
                Map.of("data", Map.of("signature",
                        "vault:v" + latestVersion + ":" + Base64.getEncoder().encodeToString("sig".getBytes()))));

        VaultTransit transit = new VaultTransit(client,
                new TenantVaultPaths("aegis", VaultIsolation.PATH), event -> { });
        signer = new VaultTenantSigner(transit, "token-signing");
    }

    @Test
    void the_kid_carries_the_tenant_and_the_key_version() {
        // Rotation must produce a genuinely different kid, or a resource server's JWKS cache cannot
        // tell the new key from the old one.
        setUpWith(2);
        assertThat(signer.kid("acme")).isEqualTo("aegis-acme-v2");
    }

    @Test
    void signing_scopes_the_vault_path_to_the_tenant() {
        setUpWith(1);
        signer.sign("acme", "header.payload".getBytes());

        assertThat(client.paths).contains("WRITE aegis/transit/sign/acme-token-signing");
    }

    @Test
    void signing_restores_the_previous_tenant_binding() {
        // The signer binds TenantContext to reach the tenant's Vault path. Leaving that binding
        // behind on a pooled request thread would be a cross-tenant read.
        setUpWith(1);
        TenantContext.set(io.aegis.commons.tenant.TenantId.of("globex"));

        signer.sign("acme", "x".getBytes());

        assertThat(TenantContext.currentOrThrow().value()).isEqualTo("globex");
    }

    @Test
    void publishes_every_key_version_so_rotation_overlaps_cleanly() {
        setUpWith(3);
        List<JWK> jwks = signer.publicJwks("acme");

        assertThat(jwks).hasSize(3);
        assertThat(jwks).extracting(JWK::getKeyID)
                .containsExactly("aegis-acme-v1", "aegis-acme-v2", "aegis-acme-v3");
    }

    @Test
    void published_keys_carry_no_private_material() {
        // The claim ADR-0015 rests on. A JWK with a private half here would mean the key had been
        // exported into this process after all.
        setUpWith(2);
        assertThat(signer.publicJwks("acme")).allSatisfy(jwk -> assertThat(jwk.isPrivate()).isFalse());
    }

    @Test
    void the_default_tenant_gets_the_default_kid_prefix() {
        client = new RecordingClient();
        client.responses.put("aegis/transit/keys/default-token-signing",
                Map.of("data", Map.of("latest_version", 1,
                        "keys", Map.of("1", Map.of("public_key", publicPem)))));
        VaultTransit transit = new VaultTransit(client,
                new TenantVaultPaths("aegis", VaultIsolation.PATH), event -> { });
        signer = new VaultTenantSigner(transit, "token-signing");

        assertThat(signer.kid("default")).isEqualTo("aegis-default-v1");
    }

    @Test
    void a_tenant_with_no_key_yet_has_one_provisioned_on_first_use() {
        // Tenants are created at runtime, so bootstrap cannot know them all. Mirrors what
        // TenantJwkSource already does for the local key store: create on first use rather than
        // requiring an out-of-band provisioning step for every new tenant.
        RecordingClient c = new RecordingClient();
        // First read returns nothing; after the create, the key exists.
        c.createsKeyOnWrite = true;
        c.publicPem = publicPem;

        VaultTransit transit = new VaultTransit(c,
                new TenantVaultPaths("aegis", VaultIsolation.PATH), event -> { });
        VaultTenantSigner signer = new VaultTenantSigner(transit, "token-signing");

        assertThat(signer.kid("brand-new")).isEqualTo("aegis-brand-new-v1");
        assertThat(c.paths).contains("WRITE aegis/transit/keys/brand-new-token-signing");
    }

    @Test
    void provisioning_is_attempted_only_once_per_lookup() {
        // A tenant whose key genuinely cannot be created must not spin: one create attempt, then a
        // clear failure. Retrying forever would turn a misconfigured policy into a hot loop against
        // Vault on the token path.
        RecordingClient c = new RecordingClient();   // never creates anything
        VaultTransit transit = new VaultTransit(c,
                new TenantVaultPaths("aegis", VaultIsolation.PATH), event -> { });
        VaultTenantSigner signer = new VaultTenantSigner(transit, "token-signing");

        org.assertj.core.api.Assertions.assertThatThrownBy(() -> signer.kid("hopeless"))
                .isInstanceOf(io.aegis.commons.vault.VaultException.class);

        long creates = c.paths.stream().filter(p -> p.startsWith("WRITE aegis/transit/keys/")).count();
        assertThat(creates).isEqualTo(1);
    }

    @Test
    void an_unprovisioned_tenant_fails_loudly_rather_than_signing_with_someone_elses_key() {
        setUpWith(1);
        org.assertj.core.api.Assertions
                .assertThatThrownBy(() -> signer.kid("never-provisioned"))
                .isInstanceOf(io.aegis.commons.vault.VaultException.class);
    }
}
