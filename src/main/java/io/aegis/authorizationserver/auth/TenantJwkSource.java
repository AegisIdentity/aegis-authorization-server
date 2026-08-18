package io.aegis.authorizationserver.auth;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.aegis.authorizationserver.keys.InMemoryTenantKeyStore;
import io.aegis.authorizationserver.keys.TenantKeyStore;
import io.aegis.authorizationserver.keys.TenantSigningKey;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;

/**
 * Tenant-aware signing keys. Each tenant (resolved from the per-request issuer, i.e. the
 * {@code /{tenant}} path prefix under {@code multipleIssuersAllowed}) gets its own RSA key with a
 * distinct {@code kid}. A token minted for tenant A is signed with A's key and therefore cannot be
 * forged for tenant B — the cryptographic isolation that per-tenant issuers alone do not provide.
 *
 * <p><strong>Keys are now durable.</strong> They live in a {@link TenantKeyStore} rather than a
 * per-process map. That closes two defects the previous version had:
 * <ul>
 *   <li>a restart regenerated every key, silently invalidating every token already issued;</li>
 *   <li>with more than one replica — and the Helm chart ships {@code replicaCount: 2} with an HPA to
 *       8 and no session affinity — each pod minted a <em>different</em> key for the same tenant, so
 *       a token signed by one pod failed validation against another pod's JWKS.</li>
 * </ul>
 * With the JPA store the whole cluster converges on one key per tenant and it survives restarts.
 * Because keys are stable now, {@code kid} is stable too — which is what resource-server caches
 * expect. (The old random-suffix-per-boot trick existed only to force those caches to re-fetch after
 * keys were silently regenerated; it is no longer needed, though the suffix is retained so a kid is
 * still globally unique across rotations.)
 *
 * <p>The no-argument constructor keeps the original ephemeral behaviour for unit tests and
 * single-process local runs.
 *
 * <p><strong>Staleness.</strong> Reads are served from a short-TTL snapshot so token validation does
 * not hit the database per request. The TTL bounds how long a replica can miss a key another replica
 * just created (or a rotation another replica just performed); a lookup for a tenant absent from the
 * snapshot always falls through to the store before concluding a key must be generated, so a
 * newly-created key is never duplicated just because the snapshot was stale.
 */
public class TenantJwkSource implements JWKSource<SecurityContext> {

    private static final String DEFAULT_TENANT = TenantSigningKey.DEFAULT_TENANT;
    private static final long DEFAULT_TTL_NANOS = 30_000_000_000L; // 30s

    private final TenantKeyStore store;
    private final long ttlNanos;

    /** Guards key generation so one process does not generate several keys for the same new tenant. */
    private final ReentrantLock generationLock = new ReentrantLock();

    private volatile Map<String, RSAKey> snapshot = Map.of();
    private volatile long snapshotLoadedAt;
    /**
     * Explicit staleness flag rather than a sentinel timestamp. {@link System#nanoTime()} is only
     * meaningful as a <em>difference</em>, and forcing a reload by parking the timestamp at
     * {@code Long.MIN_VALUE} makes {@code now - loadedAt} overflow to a negative value, which then
     * reads as "fresh" and serves the stale map — the opposite of what invalidation asked for.
     */
    private volatile boolean snapshotStale = true;

    /** Ephemeral, process-local keys — unit tests and single-process local runs. */
    public TenantJwkSource() {
        this(new InMemoryTenantKeyStore(), DEFAULT_TTL_NANOS);
    }

    /** Durable keys from the supplied store — the production wiring. */
    public TenantJwkSource(TenantKeyStore store) {
        this(store, DEFAULT_TTL_NANOS);
    }

    TenantJwkSource(TenantKeyStore store, long ttlNanos) {
        this.store = store;
        this.ttlNanos = ttlNanos;
    }

    @Override
    public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) {
        return jwkSelector.select(currentTenantJwkSet());
    }

    /** The JWKSet for the tenant of the current request's issuer (or the default key at the root). */
    public JWKSet currentTenantJwkSet() {
        AuthorizationServerContext asContext = AuthorizationServerContextHolder.getContext();
        String tenant = asContext != null ? tenantFromIssuer(asContext.getIssuer()) : null;
        return jwkSetFor(tenant);
    }

    /**
     * The JWKSet for an explicitly named tenant, created on first use — for flows that know their
     * tenant out-of-band rather than from the request context, e.g. the tenant-app interaction-code
     * minter, which runs outside the protocol chain where no issuer context is set.
     */
    public JWKSet jwkSetFor(String tenant) {
        String key = normalise(tenant);

        RSAKey cached = freshSnapshot().get(key);
        if (cached != null) {
            return new JWKSet(cached);
        }
        return new JWKSet(loadOrCreate(key));
    }

    /**
     * The union of every tenant's active key. For VALIDATION and the aggregate JWKS endpoint only —
     * never wire this into a signer, which must select exactly its own tenant's key (see the class
     * javadoc for why the isolation matters).
     */
    public JWKSet allKeys() {
        return new JWKSet(List.copyOf(freshSnapshot().values()));
    }

    // --- internals ---------------------------------------------------------------------------

    private RSAKey loadOrCreate(String tenant) {
        // Re-check the store directly: the snapshot may simply have been stale.
        Optional<RSAKey> stored = store.findActive(tenant);
        if (stored.isPresent()) {
            invalidate();
            return stored.get();
        }
        generationLock.lock();
        try {
            // Someone may have created it while we waited for the lock.
            Optional<RSAKey> again = store.findActive(tenant);
            if (again.isPresent()) {
                invalidate();
                return again.get();
            }
            // saveIfAbsent returns whichever key is authoritative — ours, or a peer's if it raced us.
            RSAKey authoritative = store.saveIfAbsent(tenant, generate(tenant));
            invalidate();
            return authoritative;
        } finally {
            generationLock.unlock();
        }
    }

    private Map<String, RSAKey> freshSnapshot() {
        long now = System.nanoTime();
        Map<String, RSAKey> current = snapshot;
        if (!snapshotStale && (now - snapshotLoadedAt) <= ttlNanos) {
            return current;
        }
        Map<String, RSAKey> reloaded = new LinkedHashMap<>();
        for (RSAKey key : store.findAllActive()) {
            reloaded.put(tenantOf(key), key);
        }
        Map<String, RSAKey> immutable = Map.copyOf(reloaded);
        this.snapshot = immutable;
        this.snapshotLoadedAt = now;
        this.snapshotStale = false;
        return immutable;
    }

    /** Force the next read to reload from the store. */
    private void invalidate() {
        this.snapshotStale = true;
    }

    /**
     * Recovers the tenant from a kid of the form {@code aegis-<tenant>-<suffix>}. The store is the
     * source of truth for the mapping; this only has to reconstruct the snapshot's index, and the
     * kid format is generated here so the two cannot drift.
     */
    private static String tenantOf(RSAKey key) {
        String kid = key.getKeyID();
        if (kid == null || !kid.startsWith("aegis-")) {
            return DEFAULT_TENANT;
        }
        int lastDash = kid.lastIndexOf('-');
        String middle = lastDash > "aegis-".length() ? kid.substring("aegis-".length(), lastDash) : "";
        return middle.equals("default") || middle.isEmpty() ? DEFAULT_TENANT : middle;
    }

    private static String normalise(String tenant) {
        return (tenant == null || tenant.isBlank()) ? DEFAULT_TENANT : tenant;
    }

    private static RSAKey generate(String tenant) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();
            String prefix = tenant.equals(DEFAULT_TENANT) ? "aegis-default" : "aegis-" + tenant;
            return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey((RSAPrivateKey) keyPair.getPrivate())
                    .keyID(prefix + "-" + UUID.randomUUID().toString().substring(0, 8))
                    .build();
        } catch (Exception ex) {
            throw new IllegalStateException("unable to generate signing key for tenant " + tenant, ex);
        }
    }

    /**
     * Extracts the tenant from an issuer like {@code http://host:port/acme} → {@code acme};
     * returns null for a root issuer with no path.
     */
    static String tenantFromIssuer(String issuer) {
        if (issuer == null || issuer.isBlank()) {
            return null;
        }
        try {
            String path = URI.create(issuer).getPath();
            if (path == null || path.isBlank() || path.equals("/")) {
                return null;
            }
            String[] segments = path.replaceAll("^/", "").split("/");
            return segments.length == 0 ? null : segments[segments.length - 1];
        } catch (Exception ex) {
            return null;
        }
    }
}
