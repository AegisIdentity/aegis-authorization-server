package io.aegis.authorizationserver.keys.kms;

import java.util.Base64;

/**
 * Envelope encryption (ADR-0007): the AES data key that protects tenant signing keys is itself
 * stored <em>wrapped</em> by a cloud KMS customer master key, and unwrapped on demand.
 *
 * <p>What this buys over the static provider: the plaintext data key exists only in process memory,
 * the wrapped form is safe to keep in config/a secret store, and the actual key-encryption-key (the
 * CMK) never leaves KMS — so KMS access can be revoked/rotated centrally, and a leak of the wrapped
 * blob is useless without KMS permission. The CMK also gives audited, IAM-gated key use.
 *
 * <p>The unwrap happens once at startup (the result is cached by the caller for the process
 * lifetime), so the per-request token path never calls KMS.
 */
public final class KmsEnvelopeDataKeyProvider implements DataKeyProvider {

    private final byte[] wrappedKey;
    private final KmsKeyUnwrapper unwrapper;

    /**
     * @param base64WrappedKey the KMS-wrapped data key (the ciphertext blob KMS returned when the
     *                         data key was generated/encrypted under the CMK), base64-encoded
     * @param unwrapper        the KMS adapter that decrypts it
     */
    public KmsEnvelopeDataKeyProvider(String base64WrappedKey, KmsKeyUnwrapper unwrapper) {
        if (base64WrappedKey == null || base64WrappedKey.isBlank()) {
            throw new IllegalArgumentException("wrapped data key must not be blank");
        }
        this.wrappedKey = Base64.getDecoder().decode(base64WrappedKey.trim());
        this.unwrapper = unwrapper;
    }

    @Override
    public byte[] resolveDataKey() {
        byte[] plaintext = unwrapper.unwrap(wrappedKey);
        if (plaintext == null || plaintext.length != 32) {
            throw new IllegalStateException("KMS returned a data key that is not 32 bytes (AES-256)");
        }
        return plaintext;
    }
}
