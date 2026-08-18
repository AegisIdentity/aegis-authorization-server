package io.aegis.authorizationserver.keys.kms;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.aegis.commons.crypto.FieldEncryption;
import java.net.URI;
import java.security.SecureRandom;
import java.util.Base64;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.CreateKeyResponse;
import software.amazon.awssdk.services.kms.model.EncryptRequest;

/**
 * Proves the KMS envelope path with a <em>real</em> AWS SDK {@code Decrypt} call — against
 * LocalStack, so no cloud account is needed. This is what turns "KMS is wired" from a claim into a
 * verified fact: a data key wrapped by a KMS CMK is unwrapped through {@link AwsKmsKeyUnwrapper} and
 * {@link KmsEnvelopeDataKeyProvider}, and the result actually drives {@link FieldEncryption}.
 */
class AwsKmsUnwrapIT {

    @SuppressWarnings("resource")
    private static final LocalStackContainer LOCALSTACK =
            new LocalStackContainer(DockerImageName.parse("localstack/localstack:3.5"))
                    .withServices(LocalStackContainer.Service.KMS);

    private static KmsClient kms;
    private static String keyId;

    @BeforeAll
    static void startKms() {
        LOCALSTACK.start();
        kms = KmsClient.builder()
                .endpointOverride(LOCALSTACK.getEndpoint())
                .region(Region.of(LOCALSTACK.getRegion()))
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(LOCALSTACK.getAccessKey(), LOCALSTACK.getSecretKey())))
                .build();
        CreateKeyResponse key = kms.createKey();
        keyId = key.keyMetadata().keyId();
    }

    @AfterAll
    static void stopKms() {
        if (kms != null) {
            kms.close();
        }
        LOCALSTACK.stop();
    }

    /** Wrap a 32-byte data key under the CMK, then unwrap it via our adapter — must round-trip. */
    @Test
    void the_envelope_provider_unwraps_a_kms_wrapped_data_key() {
        byte[] dataKey = new byte[32];
        new SecureRandom().nextBytes(dataKey);
        String wrapped = wrapUnderCmk(dataKey);

        var provider = new KmsEnvelopeDataKeyProvider(wrapped, new AwsKmsKeyUnwrapper(kms, keyId));
        byte[] unwrapped = provider.resolveDataKey();

        assertThat(unwrapped).isEqualTo(dataKey);
    }

    /** The unwrapped key must actually work as the FieldEncryption key — the end-to-end point. */
    @Test
    void field_encryption_round_trips_under_a_kms_unwrapped_key() {
        byte[] dataKey = new byte[32];
        new SecureRandom().nextBytes(dataKey);
        String wrapped = wrapUnderCmk(dataKey);

        var provider = new KmsEnvelopeDataKeyProvider(wrapped, new AwsKmsKeyUnwrapper(kms, keyId));
        FieldEncryption enc = new FieldEncryption(provider.resolveDataKey());

        String secret = "a-tenant-private-key-blob";
        assertThat(enc.decrypt(enc.encrypt(secret))).isEqualTo(secret);
    }

    /** A CMK returning a non-32-byte plaintext must be rejected, not silently used. */
    @Test
    void a_wrong_sized_kms_result_is_rejected() {
        byte[] shortKey = new byte[16]; // 128-bit, not the AES-256 we require
        String wrapped = wrapUnderCmk(shortKey);

        var provider = new KmsEnvelopeDataKeyProvider(wrapped, new AwsKmsKeyUnwrapper(kms, keyId));
        assertThatThrownBy(provider::resolveDataKey)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("32 bytes");
    }

    private static String wrapUnderCmk(byte[] plaintext) {
        var response = kms.encrypt(EncryptRequest.builder()
                .keyId(keyId)
                .plaintext(SdkBytes.fromByteArray(plaintext))
                .build());
        return Base64.getEncoder().encodeToString(response.ciphertextBlob().asByteArray());
    }
}
