package io.aegis.authorizationserver.keys.kms;

/**
 * Unwraps (decrypts) a KMS-wrapped data key using a cloud KMS customer master key.
 *
 * <p>Isolating the single KMS call behind this one-method interface is what keeps the cloud SDK out
 * of the encryption code and makes the envelope logic testable without a live cloud account (a
 * LocalStack-backed {@link AwsKmsKeyUnwrapper} exercises the real AWS SDK path in tests). An Azure
 * Key Vault adapter implements the same interface.
 */
public interface KmsKeyUnwrapper {

    /**
     * @param wrappedKey the KMS ciphertext blob produced when the data key was encrypted under the CMK
     * @return the plaintext 32-byte data key
     */
    byte[] unwrap(byte[] wrappedKey);
}
