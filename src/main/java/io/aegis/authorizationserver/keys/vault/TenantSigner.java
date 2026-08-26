package io.aegis.authorizationserver.keys.vault;

/**
 * Signs on behalf of a tenant without ever handing over the key.
 *
 * <p>This is the seam that makes ADR-0015 possible. Every previous key abstraction in this service
 * returns an {@code RSAKey} — which carries the <em>private</em> material — so a Vault-backed
 * implementation of one of those would have to export the private key and defeat the entire point.
 * The interface has to be "sign these bytes", not "give me the key".
 */
public interface TenantSigner {

    /** The {@code kid} to place in the JWS header for this tenant's current key version. */
    String kid(String tenant);

    /** RSASSA-PKCS1-v1_5 over SHA-256 of {@code signingInput}, returning raw signature bytes. */
    byte[] sign(String tenant, byte[] signingInput);
}
