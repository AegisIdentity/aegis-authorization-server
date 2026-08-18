package io.aegis.authorizationserver.keys;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Persistence for tenant signing keys. Every lookup is tenant-scoped by construction, matching the
 * platform convention that no query reaches across tenants without saying so explicitly.
 */
public interface TenantSigningKeyRepository extends JpaRepository<TenantSigningKey, UUID> {

    /** The tenant's current signing key. At most one row per tenant may be active. */
    Optional<TenantSigningKey> findByTenantAndActiveTrue(String tenant);

    /** Active keys for every tenant — the signing set, and the basis of the aggregate JWKS. */
    List<TenantSigningKey> findByActiveTrue();

    /**
     * Active keys plus recently-retired ones, so tokens signed by a key that has just been rotated
     * out remain verifiable until they expire (ADR-0007's overlap requirement).
     */
    List<TenantSigningKey> findByTenant(String tenant);
}
