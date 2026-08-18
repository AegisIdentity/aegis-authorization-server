package io.aegis.authorizationserver.keys.kms;

/**
 * Supplies the 32-byte AES data key that {@code FieldEncryption} uses to protect tenant signing keys
 * at rest.
 *
 * <p>This is the seam between "where the key-encryption-key comes from" and "encrypting the column".
 * Two implementations exist:
 * <ul>
 *   <li>{@link StaticDataKeyProvider} — the key is a base64 value from configuration / a secret
 *       manager (the current dev and non-KMS posture);</li>
 *   <li>{@link KmsEnvelopeDataKeyProvider} — envelope encryption: the data key is stored
 *       <em>wrapped</em> by a cloud KMS customer master key (CMK) and unwrapped on demand via a
 *       {@link KmsKeyUnwrapper}, so the plaintext data key never lives anywhere but process memory
 *       and the CMK never leaves KMS (ADR-0007's end state).</li>
 * </ul>
 *
 * <p>Swapping providers changes only where the key comes from — {@code FieldEncryption} and every
 * caller are untouched, which is the whole point of resolving to raw key bytes here.
 */
public interface DataKeyProvider {

    /**
     * @return exactly 32 bytes (AES-256). The caller should use the value and then zero it; this
     *         provider hands out a fresh array each call so zeroing one copy is safe.
     */
    byte[] resolveDataKey();
}
