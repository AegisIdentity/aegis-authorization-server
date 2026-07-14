package io.aegis.authorizationserver.tenantapp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.aegis.authorizationserver.auth.AegisUserPrincipal;
import io.aegis.authorizationserver.auth.IdentityClient;
import io.aegis.authorizationserver.auth.MfaClient;
import io.aegis.authorizationserver.federation.BrokerClient;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.web.server.ResponseStatusException;

/** Tenant-app controller logic: tenant binding, cross-tenant refusal, native-social JIT, and the exchange. */
class TenantAppAuthControllerTest {

    private final RegisteredClientRepository clients = mock(RegisteredClientRepository.class);
    private final MfaClient mfaClient = mock(MfaClient.class);
    private final BrokerClient broker = mock(BrokerClient.class);
    private final IdentityClient identityClient = mock(IdentityClient.class);
    private final NativeProviderVerifier verifier = mock(NativeProviderVerifier.class);
    private final InteractionCodeStore interactions = new InteractionCodeStore();
    private final AegisTokenMinter minter = mock(AegisTokenMinter.class);

    private final TenantAppAuthController controller = new TenantAppAuthController(
            clients, mfaClient, broker, identityClient, verifier, interactions, minter);

    private void bindClient(String clientId, String tenant) {
        RegisteredClient rc = mock(RegisteredClient.class);
        when(rc.getClientSettings()).thenReturn(ClientSettings.builder().setting("tenant", tenant).build());
        when(clients.findByClientId(clientId)).thenReturn(rc);
    }

    @Test
    void login_finish_issues_an_interaction_code_for_a_matching_tenant() {
        bindClient("acme-app", "acme");
        when(mfaClient.verifyAssertion(any())).thenReturn(new MfaClient.AssertionResult(true, "acme", "alice"));

        Map<String, String> out = controller.loginFinish(Map.of("clientId", "acme-app",
                "codeChallenge", "chal", "credentialId", "c"));

        assertThat(out).containsKey("interaction_code");
    }

    @Test
    void login_finish_refuses_a_passkey_from_another_tenant() {
        bindClient("acme-app", "acme");
        when(mfaClient.verifyAssertion(any())).thenReturn(new MfaClient.AssertionResult(true, "other", "mallory"));

        assertThatThrownBy(() -> controller.loginFinish(Map.of("clientId", "acme-app",
                "codeChallenge", "chal", "credentialId", "c")))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void login_finish_rejects_an_invalid_assertion() {
        bindClient("acme-app", "acme");
        when(mfaClient.verifyAssertion(any())).thenReturn(new MfaClient.AssertionResult(false, null, null));
        assertThatThrownBy(() -> controller.loginFinish(Map.of("clientId", "acme-app", "codeChallenge", "chal")))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void social_native_verifies_provisions_and_returns_a_code() {
        bindClient("acme-app", "acme");
        var provider = mock(BrokerClient.ProviderConfig.class);
        when(broker.resolve("acme", "google")).thenReturn(provider);
        when(verifier.verify(eq(provider), anyString()))
                .thenReturn(new NativeProviderVerifier.VerifiedIdentity("jane@acme.com", "jane"));
        when(identityClient.provisionFederated("acme", "jane@acme.com", "jane"))
                .thenReturn(new AegisUserPrincipal("acme", "u-1", "jane"));

        Map<String, String> out = controller.socialNative(Map.of("clientId", "acme-app",
                "provider", "google", "idToken", "tok", "codeChallenge", "chal"));

        assertThat(out).containsKey("interaction_code");
        verify(identityClient).provisionFederated("acme", "jane@acme.com", "jane");
    }

    @Test
    void social_native_rejects_an_unknown_provider() {
        bindClient("acme-app", "acme");
        when(broker.resolve("acme", "nope")).thenReturn(null);
        assertThatThrownBy(() -> controller.socialNative(Map.of("clientId", "acme-app",
                "provider", "nope", "idToken", "tok", "codeChallenge", "chal")))
                .isInstanceOf(ResponseStatusException.class);
    }

    @Test
    void token_exchange_consumes_the_code_and_mints_tokens() throws Exception {
        bindClient("acme-app", "acme");
        // Seed a code, then exchange it with the matching verifier.
        String verifierStr = "verifier-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        var digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest(verifierStr.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        String challenge = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        String code = interactions.create("acme", "alice", "acme-app", challenge, "webauthn");
        when(minter.mint("acme", "alice", "acme-app", "webauthn"))
                .thenReturn(new AegisTokenMinter.Tokens("at", "it", "Bearer", 600, "openid profile"));

        Map<String, Object> out = controller.token(Map.of("clientId", "acme-app",
                "interaction_code", code, "code_verifier", verifierStr));

        assertThat(out).containsEntry("access_token", "at").containsEntry("token_type", "Bearer");
    }

    @Test
    void an_unknown_client_is_rejected() {
        when(clients.findByClientId("ghost")).thenReturn(null);
        assertThatThrownBy(() -> controller.loginOptions(Map.of("clientId", "ghost")))
                .isInstanceOf(ResponseStatusException.class);
    }
}
