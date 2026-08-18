package io.aegis.authorizationserver.keys.kms;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * Unit-level contract for the data-key providers, without a KMS. The envelope provider is exercised
 * here with a deterministic fake unwrapper so the envelope mechanics are covered fast; the real AWS
 * SDK path is proven separately in {@code AwsKmsUnwrapIT}.
 */
class DataKeyProviderTest {

    private static final byte[] KEY = "0123456789abcdef0123456789abcdef".getBytes();
    private static final String KEY_B64 = Base64.getEncoder().encodeToString(KEY);

    @Test
    void the_static_provider_returns_the_configured_key() {
        assertThat(new StaticDataKeyProvider(KEY_B64).resolveDataKey()).isEqualTo(KEY);
    }

    @Test
    void the_static_provider_hands_out_a_fresh_copy_each_call() {
        StaticDataKeyProvider provider = new StaticDataKeyProvider(KEY_B64);
        byte[] first = provider.resolveDataKey();
        java.util.Arrays.fill(first, (byte) 0); // caller wipes its copy

        assertThat(provider.resolveDataKey()).isEqualTo(KEY); // ours is intact
    }

    @Test
    void the_static_provider_rejects_a_wrong_length_key() {
        assertThatThrownBy(() -> new StaticDataKeyProvider(Base64.getEncoder().encodeToString("short".getBytes())))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32 bytes");
    }

    @Test
    void the_envelope_provider_unwraps_via_the_kms_adapter() {
        // Fake KMS: "unwrap" strips a marker prefix, standing in for a real Decrypt.
        KmsKeyUnwrapper fakeKms = wrapped -> {
            byte[] out = new byte[wrapped.length - 4];
            System.arraycopy(wrapped, 4, out, 0, out.length);
            return out;
        };
        byte[] wrapped = new byte[36];
        System.arraycopy("WRAP".getBytes(), 0, wrapped, 0, 4);
        System.arraycopy(KEY, 0, wrapped, 4, 32);

        var provider = new KmsEnvelopeDataKeyProvider(
                Base64.getEncoder().encodeToString(wrapped), fakeKms);

        assertThat(provider.resolveDataKey()).isEqualTo(KEY);
    }

    @Test
    void the_envelope_provider_rejects_a_non_32_byte_unwrap_result() {
        KmsKeyUnwrapper returnsShort = wrapped -> new byte[16];
        var provider = new KmsEnvelopeDataKeyProvider(
                Base64.getEncoder().encodeToString(new byte[8]), returnsShort);

        assertThatThrownBy(provider::resolveDataKey)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("32 bytes");
    }

    @Test
    void the_envelope_provider_requires_a_wrapped_key() {
        assertThatThrownBy(() -> new KmsEnvelopeDataKeyProvider("  ", w -> w))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
