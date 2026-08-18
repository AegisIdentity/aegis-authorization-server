package io.aegis.authorizationserver.keys;

import com.nimbusds.jose.jwk.RSAKey;
import io.aegis.commons.crypto.FieldEncryption;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * PostgreSQL-backed {@link TenantKeyStore} with the private half encrypted at rest.
 *
 * <p>This is what makes the authorization-server horizontally scalable: every replica reads the same
 * key for a given tenant, and the key outlives the process. Selected automatically whenever JPA is
 * present (see {@code TenantKeyConfig}).
 */
@Transactional
public class JpaTenantKeyStore implements TenantKeyStore {

    private static final Logger log = LoggerFactory.getLogger(JpaTenantKeyStore.class);

    private final TenantSigningKeyRepository repository;
    private final FieldEncryption encryption;

    public JpaTenantKeyStore(TenantSigningKeyRepository repository, FieldEncryption encryption) {
        this.repository = repository;
        this.encryption = encryption;
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<RSAKey> findActive(String tenant) {
        return repository.findByTenantAndActiveTrue(tenant).map(this::toRsaKey);
    }

    /**
     * Insert the generated key, or yield to whoever won the race.
     *
     * <p>Runs in its own transaction ({@code REQUIRES_NEW}) because the insert may legitimately fail
     * on the partial unique index. Letting that violation surface in a caller's transaction would
     * mark it rollback-only, and the subsequent re-read — the whole point of the recovery — would
     * fail too.
     */
    @Override
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public RSAKey saveIfAbsent(String tenant, RSAKey generated) {
        // Fast path: somebody already created it.
        Optional<TenantSigningKey> existing = repository.findByTenantAndActiveTrue(tenant);
        if (existing.isPresent()) {
            return toRsaKey(existing.get());
        }
        TenantSigningKey row = marshal(tenant, generated);
        try {
            repository.saveAndFlush(row); // flush now so the constraint fires here, not at commit
            log.info("created signing key for tenant={} kid={}", tenant, generated.getKeyID());
            return generated;
        } catch (DataIntegrityViolationException race) {
            // Another replica inserted first. Its key is authoritative — adopt it rather than
            // signing with one nobody else can verify.
            log.info("lost signing-key creation race for tenant={} — adopting the stored key", tenant);
            return repository.findByTenantAndActiveTrue(tenant)
                    .map(this::toRsaKey)
                    .orElseThrow(() -> new IllegalStateException(
                            "signing key for tenant " + tenant + " vanished after a write conflict", race));
        }
    }

    @Override
    @Transactional(readOnly = true)
    public List<RSAKey> findAllActive() {
        return repository.findByActiveTrue().stream().map(this::toRsaKey).toList();
    }

    // --- marshalling -------------------------------------------------------------------------

    private RSAKey toRsaKey(TenantSigningKey row) {
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            RSAPublicKey pub = (RSAPublicKey) factory.generatePublic(
                    new X509EncodedKeySpec(Base64.getDecoder().decode(row.getPublicKey())));
            RSAPrivateKey priv = (RSAPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(
                    Base64.getDecoder().decode(encryption.decrypt(row.getPrivateKeyEncrypted()))));
            return new RSAKey.Builder(pub).privateKey(priv).keyID(row.getKid()).build();
        } catch (Exception e) {
            // Deliberately does not echo key material or the underlying cause's data into the message.
            throw new IllegalStateException(
                    "unable to load signing key kid=" + row.getKid() + " for tenant " + row.getTenant(), e);
        }
    }

    /** Encode a generated key into its stored form, encrypting the private half. */
    private TenantSigningKey marshal(String tenant, RSAKey generated) {
        try {
            RSAPublicKey pub = generated.toRSAPublicKey();
            RSAPrivateKey priv = generated.toRSAPrivateKey();
            if (priv == null) {
                throw new IllegalArgumentException("generated key has no private half");
            }
            String publicB64 = Base64.getEncoder().encodeToString(pub.getEncoded());
            String privateB64 = Base64.getEncoder().encodeToString(priv.getEncoded());
            return new TenantSigningKey(
                    tenant, generated.getKeyID(), publicB64, encryption.encrypt(privateB64));
        } catch (Exception e) {
            throw new IllegalStateException("unable to encode signing key for tenant " + tenant, e);
        }
    }
}
