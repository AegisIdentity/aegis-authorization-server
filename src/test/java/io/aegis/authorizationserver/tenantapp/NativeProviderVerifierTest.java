package io.aegis.authorizationserver.tenantapp;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.aegis.authorizationserver.federation.BrokerClient;
import org.junit.jupiter.api.Test;

/** Native-social id_token verification guards — the account-takeover-relevant failure paths. */
class NativeProviderVerifierTest {

    private final NativeProviderVerifier verifier = new NativeProviderVerifier();

    @Test
    void a_null_provider_is_rejected() {
        assertThatThrownBy(() -> verifier.verify(null, "some.id.token"))
                .isInstanceOf(NativeProviderVerifier.NativeVerificationException.class);
    }

    @Test
    void a_provider_without_jwks_or_issuer_cannot_verify() {
        BrokerClient.ProviderConfig provider = mock(BrokerClient.ProviderConfig.class);
        when(provider.jwkSetUri()).thenReturn(null);
        when(provider.issuerUri()).thenReturn(null);
        assertThatThrownBy(() -> verifier.verify(provider, "some.id.token"))
                .isInstanceOf(NativeProviderVerifier.NativeVerificationException.class);
    }

    @Test
    void an_unverifiable_token_is_rejected() {
        BrokerClient.ProviderConfig provider = mock(BrokerClient.ProviderConfig.class);
        when(provider.jwkSetUri()).thenReturn("http://127.0.0.1:1/jwks"); // unreachable
        when(provider.issuerUri()).thenReturn("https://accounts.example.com");
        assertThatThrownBy(() -> verifier.verify(provider, "not-a-real-jwt"))
                .isInstanceOf(NativeProviderVerifier.NativeVerificationException.class);
    }
}
