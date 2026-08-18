/*
 * Per-tenant token signing keys (ADR-0007).
 *
 * Previously these were generated into a per-process map, so they died on restart and diverged
 * across replicas. Persisting them here makes one key authoritative per tenant for the whole
 * cluster.
 *
 * `CREATE TABLE IF NOT EXISTS` because spring.sql.init.mode=always re-runs this on every startup
 * (same reasoning as the Spring-shipped schemas in this directory).
 *
 * private_key_encrypted holds AES-256-GCM ciphertext ("v1:" prefixed) over the base64 PKCS#8
 * private key. The public half is stored in the clear deliberately — it is published at the JWKS
 * endpoint, so encrypting it would protect nothing.
 */
CREATE TABLE IF NOT EXISTS tenant_signing_key (
    id                    uuid        NOT NULL,
    tenant                varchar(64) NOT NULL,
    kid                   varchar(128) NOT NULL,
    public_key            text        NOT NULL,
    private_key_encrypted text        NOT NULL,
    active                boolean     NOT NULL DEFAULT TRUE,
    created_at            timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retired_at            timestamptz DEFAULT NULL,
    PRIMARY KEY (id)
);

-- A resource server caches verification keys by kid; two different keys sharing one kid would make
-- validation depend on which row was read first.
CREATE UNIQUE INDEX IF NOT EXISTS uk_tenant_signing_key_kid
    ON tenant_signing_key (kid);

/*
 * THE concurrency guarantee. Two replicas can boot at the same moment and both try to create the
 * first key for a new tenant. This partial unique index means exactly one of those inserts can
 * succeed; the loser catches the constraint violation and re-reads the winner's key, so the cluster
 * converges on a single signing key per tenant instead of silently minting tokens under two.
 *
 * It must be PARTIAL (WHERE active) rather than a plain unique(tenant, active): rotation retains
 * superseded keys so their already-issued tokens stay verifiable, and several retired rows per
 * tenant are expected and legal.
 */
CREATE UNIQUE INDEX IF NOT EXISTS uk_tenant_signing_key_one_active_per_tenant
    ON tenant_signing_key (tenant) WHERE active;

-- The aggregate-JWKS read path (every resource server hits it) and the per-tenant signing lookup.
CREATE INDEX IF NOT EXISTS ix_tenant_signing_key_active
    ON tenant_signing_key (active);
