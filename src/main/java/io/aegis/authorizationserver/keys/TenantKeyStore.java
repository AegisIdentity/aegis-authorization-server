package io.aegis.authorizationserver.keys;

import com.nimbusds.jose.jwk.RSAKey;
import java.util.List;
import java.util.Optional;

/**
 * Where a tenant's token-signing key lives.
 *
 * <p>Signing keys were previously generated on demand into a per-process map, which had two
 * consequences the deployment artifacts did not survive: every restart invalidated every token
 * already issued, and — because the Helm chart runs the authorization-server at 2+ replicas behind a
 * Service with no session affinity — each replica minted a <em>different</em> key for the same
 * tenant, so a token signed by one pod failed validation against another pod's JWKS. Persisting the
 * key behind this interface fixes both: all replicas converge on one key per tenant, and it survives
 * restarts.
 *
 * <p>Two implementations exist. {@link InMemoryTenantKeyStore} preserves the original ephemeral
 * behaviour for unit tests and single-process local runs. {@code JpaTenantKeyStore} persists to
 * PostgreSQL with the private material encrypted at rest. A future KMS-backed implementation
 * (ADR-0007) drops in here without touching any caller — that is the point of the seam.
 *
 * <p><strong>Implementations must be safe under concurrent creation.</strong> Two replicas can race
 * to create the first key for a brand-new tenant; {@link #saveIfAbsent} resolves the race by
 * returning the key that actually won, so both pods end up using the same one.
 */
public interface TenantKeyStore {

    /** The tenant's current signing key, or empty if none has been created yet. */
    Optional<RSAKey> findActive(String tenant);

    /**
     * Store {@code generated} as the tenant's active key, unless another writer got there first.
     *
     * @return the key that is now authoritative for this tenant — {@code generated} if this caller
     *         won, otherwise the previously-stored key. Callers must use the returned key, never
     *         assume their own generated one was accepted.
     */
    RSAKey saveIfAbsent(String tenant, RSAKey generated);

    /** Every tenant's active key. Backs the aggregate JWKS used for validation. */
    List<RSAKey> findAllActive();
}
