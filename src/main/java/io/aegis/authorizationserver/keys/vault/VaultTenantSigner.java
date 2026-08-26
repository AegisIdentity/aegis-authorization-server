package io.aegis.authorizationserver.keys.vault;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import io.aegis.commons.tenant.TenantContext;
import io.aegis.commons.tenant.TenantId;
import io.aegis.commons.vault.TransitKeyType;
import io.aegis.commons.vault.VaultException;
import io.aegis.commons.vault.VaultPublicKey;
import io.aegis.commons.vault.VaultTransit;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Signs tenant tokens with Vault Transit (ADR-0015).
 *
 * <p>The private key is never fetched, cached or held — only the signing input leaves this process
 * and only a signature comes back. Public material <em>is</em> cached, because it is not sensitive
 * and JWKS is read on every token validation.
 */
public class VaultTenantSigner implements TenantSigner {

    private static final Logger log = LoggerFactory.getLogger(VaultTenantSigner.class);
    private static final String DEFAULT_TENANT = "default";
    private static final Duration PUBLIC_CACHE_TTL = Duration.ofMinutes(5);

    private final VaultTransit transit;
    private final String keyPurpose;

    /** Public material only — see the class javadoc. Never holds a private key. */
    private final Map<String, CachedKeys> publicCache = new ConcurrentHashMap<>();

    private record CachedKeys(List<VaultPublicKey> versions, long expiresAtMillis) {
    }

    public VaultTenantSigner(VaultTransit transit, String keyPurpose) {
        this.transit = transit;
        this.keyPurpose = keyPurpose;
    }

    @Override
    public String kid(String tenant) {
        List<VaultPublicKey> versions = versions(tenant);
        if (versions.isEmpty()) {
            throw new VaultException("no signing key provisioned for tenant " + tenant);
        }
        return kidFor(tenant, versions.get(versions.size() - 1).version());
    }

    @Override
    public byte[] sign(String tenant, byte[] signingInput) {
        // callAs rather than manual set/clear: the binding must be restored even if Vault throws,
        // because a leaked tenant on a pooled request thread is a cross-tenant read.
        return TenantContext.callAs(TenantId.of(tenant),
                () -> transit.signJws(keyName(), signingInput));
    }

    /**
     * Every published verification key for a tenant, newest last.
     *
     * <p>All versions, not just the newest: overlapping rotation (ADR-0007) means a token signed by
     * version 1 must keep verifying after the key rotates to version 2, so JWKS publishes both until
     * the older tokens expire.
     */
    public List<JWK> publicJwks(String tenant) {
        List<JWK> jwks = new ArrayList<>();
        for (VaultPublicKey version : versions(tenant)) {
            try {
                jwks.add(new RSAKey.Builder(parsePem(version.pem()))
                        .keyID(kidFor(tenant, version.version()))
                        .keyUse(KeyUse.SIGNATURE)
                        .build());
            } catch (Exception e) {
                // One unparseable version must not take down the whole JWKS: the other versions are
                // still valid and tokens signed by them must keep verifying.
                log.warn("vault_public_key_unparseable tenant={} version={}: {}",
                        tenant, version.version(), e.toString());
            }
        }
        return jwks;
    }

    /** Provision a tenant's signing key. Idempotent — Vault ignores a create for an existing key. */
    public void ensureKey(String tenant) {
        TenantContext.runAs(TenantId.of(tenant),
                () -> transit.createKey(keyName(), TransitKeyType.RSA_2048));
        publicCache.remove(tenant);
    }

    /** Rotate, then drop the cache so the new version appears in JWKS before it signs anything. */
    public void rotate(String tenant) {
        TenantContext.runAs(TenantId.of(tenant), () -> transit.rotate(keyName()));
        publicCache.remove(tenant);
    }

    /**
     * Public key versions for a tenant, provisioning the key on first use.
     *
     * <p>Tenants are created at runtime, so no bootstrap step can know them all in advance — the
     * same reason {@code TenantJwkSource} creates a local key on first use rather than requiring
     * out-of-band provisioning. Creation is attempted <b>once</b>: a tenant whose key genuinely
     * cannot be created must fail clearly rather than spin, because this sits on the token path and
     * a retry loop would turn a misconfigured Vault policy into a hot loop against Vault.
     */
    private List<VaultPublicKey> versions(String tenant) {
        CachedKeys cached = publicCache.get(tenant);
        if (cached != null && cached.expiresAtMillis() > System.currentTimeMillis()) {
            return cached.versions();
        }

        List<VaultPublicKey> fresh = TenantContext.callAs(TenantId.of(tenant),
                () -> transit.publicKeyVersions(keyName()));

        if (fresh.isEmpty()) {
            log.info("vault_signing_key_provisioning tenant={}", tenant);
            try {
                TenantContext.runAs(TenantId.of(tenant),
                        () -> transit.createKey(keyName(), TransitKeyType.RSA_2048));
            } catch (RuntimeException e) {
                // Losing the race with another replica is expected and fine — the re-read below
                // finds the winner's key, exactly as the local key store's first-writer-wins does.
                log.debug("vault_signing_key_create_failed tenant={}: {}", tenant, e.toString());
            }
            fresh = TenantContext.callAs(TenantId.of(tenant),
                    () -> transit.publicKeyVersions(keyName()));
        }

        publicCache.put(tenant,
                new CachedKeys(fresh, System.currentTimeMillis() + PUBLIC_CACHE_TTL.toMillis()));
        return fresh;
    }

    /**
     * The Transit key name inside the tenant's own path.
     *
     * <p>The tenant segment of the Vault path is supplied by {@code TenantVaultPaths} from
     * {@code TenantContext}, so this is only the leaf — a tenant string is never concatenated into a
     * path here.
     */
    private String keyName() {
        return keyPurpose;
    }

    /**
     * {@code aegis-<tenant>-v<version>} — carries the key version, so rotation produces a genuinely
     * new {@code kid} and a resource server can tell the two apart in its JWKS cache.
     */
    private static String kidFor(String tenant, int version) {
        String prefix = DEFAULT_TENANT.equals(tenant) ? "aegis-default" : "aegis-" + tenant;
        return prefix + "-v" + version;
    }

    private static RSAPublicKey parsePem(String pem) throws Exception {
        String base64 = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(base64);
        return (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(der));
    }
}
