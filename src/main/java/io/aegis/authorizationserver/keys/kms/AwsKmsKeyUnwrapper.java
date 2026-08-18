package io.aegis.authorizationserver.keys.kms;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;

/**
 * AWS KMS implementation of {@link KmsKeyUnwrapper}: unwraps the data key with a single
 * {@code kms:Decrypt} call against the customer master key.
 *
 * <p>The pod's IAM identity (IRSA on EKS) must be granted {@code kms:Decrypt} on the CMK and nothing
 * more — least privilege for the token-signing path. This adapter is intentionally tiny; all the
 * envelope logic lives in {@link KmsEnvelopeDataKeyProvider}, and this class only bridges to the SDK
 * so the rest of the code has no AWS dependency and stays unit-testable.
 *
 * <p>Verified against LocalStack (a real AWS SDK {@code Decrypt} path) in {@code AwsKmsUnwrapIT}, so
 * the SDK wiring is exercised without a cloud account; production points the same client at real KMS.
 */
public final class AwsKmsKeyUnwrapper implements KmsKeyUnwrapper {

    private final KmsClient kmsClient;
    private final String keyId;

    /**
     * @param kmsClient a configured AWS KMS client (region + credentials come from the default
     *                  provider chain / IRSA in production)
     * @param keyId     the CMK id/ARN/alias the data key was wrapped under
     */
    public AwsKmsKeyUnwrapper(KmsClient kmsClient, String keyId) {
        this.kmsClient = kmsClient;
        this.keyId = keyId;
    }

    @Override
    public byte[] unwrap(byte[] wrappedKey) {
        DecryptResponse response = kmsClient.decrypt(DecryptRequest.builder()
                .keyId(keyId)
                .ciphertextBlob(SdkBytes.fromByteArray(wrappedKey))
                .build());
        return response.plaintext().asByteArray();
    }
}
