package io.aegis.authorizationserver.keys.kms;

import java.util.Base64;

/**
 * A data key held directly as a base64-encoded 32-byte value (from configuration / a secret
 * manager). This is the non-KMS posture — correct for local dev and any deployment that keeps its
 * key-encryption-key in a secret manager rather than a dedicated KMS/HSM.
 */
public final class StaticDataKeyProvider implements DataKeyProvider {

    private final byte[] key;

    public StaticDataKeyProvider(String base64Key) {
        if (base64Key == null || base64Key.isBlank()) {
            throw new IllegalArgumentException("data key must not be blank");
        }
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(base64Key.trim());
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("data key must be valid base64", ex);
        }
        if (decoded.length != 32) {
            throw new IllegalArgumentException("data key must decode to 32 bytes (AES-256)");
        }
        this.key = decoded;
    }

    @Override
    public byte[] resolveDataKey() {
        // Fresh copy each call so a caller zeroing its copy cannot corrupt ours.
        return key.clone();
    }
}
