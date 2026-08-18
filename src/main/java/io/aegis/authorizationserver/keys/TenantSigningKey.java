package io.aegis.authorizationserver.keys;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.UUID;

/**
 * A tenant's token-signing key pair, persisted so it survives restarts and is shared by every
 * replica (ADR-0007).
 *
 * <p><strong>Private material is encrypted at rest.</strong> {@link #privateKeyEncrypted} holds the
 * PKCS#8 form of the RSA private key, AES-256-GCM encrypted via the shared
 * {@code io.aegis.commons.crypto.FieldEncryption}. A database read alone therefore does not yield a
 * usable signing key — an attacker needs the field-encryption key as well, which lives in the
 * secret manager and never in the database. This is envelope encryption with a
 * single application-held key-encryption-key; swapping that KEK for a cloud KMS
 * (ADR-0007's end state) changes only how the KEK is obtained, not this schema.
 *
 * <p>The public half is stored unencrypted on purpose: it is published at the JWKS endpoint, so
 * encrypting it would protect nothing while making the aggregate JWKS read more expensive.
 *
 * <p><strong>Rotation with overlap</strong> is modelled by {@link #active}: exactly one row per
 * tenant may be active (enforced by a partial unique index — see the Flyway migration), while
 * superseded rows are retained with {@code active = false} so tokens they signed stay verifiable
 * until they expire. Only active keys sign; the aggregate JWKS may publish retired keys too.
 */
@Entity
@Table(
        name = "tenant_signing_key",
        uniqueConstraints = @UniqueConstraint(name = "uk_tenant_signing_key_kid", columnNames = "kid"))
public class TenantSigningKey {

    /** Sentinel tenant for the root issuer (no {@code /{tenant}} path segment). */
    public static final String DEFAULT_TENANT = "__default__";

    @Id
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @Column(name = "tenant", nullable = false, length = 64)
    private String tenant;

    /** JWK key id. Stable for the life of the key — resource servers cache by this value. */
    @Column(name = "kid", nullable = false, length = 128)
    private String kid;

    /** Base64 X.509 SubjectPublicKeyInfo. Public — published in JWKS, so not encrypted. */
    @Column(name = "public_key", nullable = false, columnDefinition = "text")
    private String publicKey;

    /** {@code v1:}-prefixed AES-GCM ciphertext over the base64 PKCS#8 private key. */
    @Column(name = "private_key_encrypted", nullable = false, columnDefinition = "text")
    private String privateKeyEncrypted;

    @Column(name = "active", nullable = false)
    private boolean active = true;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    /** Set when the key is superseded by a rotation; null while active. */
    @Column(name = "retired_at")
    private Instant retiredAt;

    protected TenantSigningKey() {
        // JPA
    }

    public TenantSigningKey(String tenant, String kid, String publicKey, String privateKeyEncrypted) {
        this.id = UUID.randomUUID();
        this.tenant = tenant;
        this.kid = kid;
        this.publicKey = publicKey;
        this.privateKeyEncrypted = privateKeyEncrypted;
        this.active = true;
        this.createdAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public String getTenant() {
        return tenant;
    }

    public String getKid() {
        return kid;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getPrivateKeyEncrypted() {
        return privateKeyEncrypted;
    }

    public boolean isActive() {
        return active;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getRetiredAt() {
        return retiredAt;
    }

    /** Supersede this key. Retained (not deleted) so its already-issued tokens stay verifiable. */
    public void retire() {
        this.active = false;
        this.retiredAt = Instant.now();
    }

    /**
     * Never let key material reach a log line or an error message.
     */
    @Override
    public String toString() {
        return "TenantSigningKey{tenant=" + tenant + ", kid=" + kid + ", active=" + active + "}";
    }
}
