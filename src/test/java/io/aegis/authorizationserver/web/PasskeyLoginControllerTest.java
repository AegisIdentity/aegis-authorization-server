package io.aegis.authorizationserver.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.aegis.authorizationserver.auth.AegisUserPrincipal;
import io.aegis.authorizationserver.auth.MfaClient;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Passwordless passkey sign-in: a verified assertion establishes a WebAuthn-factor session; an
 * unrecognised one is rejected and leaves the context empty (no session on a failed assertion).
 */
class PasskeyLoginControllerTest {

    private final MfaClient mfaClient = mock(MfaClient.class);
    private final PasskeyLoginController controller = new PasskeyLoginController(mfaClient);

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void options_delegates_to_the_mfa_service() {
        when(mfaClient.assertionOptions("acme")).thenReturn(Map.of("challengeId", "c1", "challenge", "x"));
        Map<String, Object> out = controller.options(Map.of("tenant", "acme"));
        assertThat(out).containsEntry("challengeId", "c1");
    }

    @Test
    void an_unrecognized_passkey_is_rejected_and_no_session_is_created() {
        when(mfaClient.verifyAssertion(any())).thenReturn(new MfaClient.AssertionResult(false, null, null));
        var request = new MockHttpServletRequest("POST", "/login/webauthn/verify");
        request.getSession(true);

        ResponseEntity<Map<String, String>> res =
                controller.verify(Map.of("credentialId", "x"), request, new MockHttpServletResponse());

        assertThat(res.getStatusCode().value()).isEqualTo(401);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void a_valid_assertion_establishes_a_webauthn_session_and_returns_where_to_continue() {
        when(mfaClient.verifyAssertion(any())).thenReturn(new MfaClient.AssertionResult(true, "acme", "alice"));
        var request = new MockHttpServletRequest("POST", "/login/webauthn/verify");
        request.getSession(true);

        ResponseEntity<Map<String, String>> res =
                controller.verify(Map.of("credentialId", "x"), request, new MockHttpServletResponse());

        assertThat(res.getStatusCode().value()).isEqualTo(200);
        assertThat(res.getBody()).containsKey("redirect");
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isNotNull();
        assertThat(auth.getPrincipal()).isInstanceOf(AegisUserPrincipal.class);
        assertThat(((AegisUserPrincipal) auth.getPrincipal()).tenantId()).isEqualTo("acme");
        assertThat(((AegisUserPrincipal) auth.getPrincipal()).username()).isEqualTo("alice");
        // Carries a WebAuthn authentication factor (passkey login is itself strong/MFA-grade).
        assertThat(auth.getAuthorities()).anyMatch(a -> "FACTOR_WEBAUTHN".equals(a.getAuthority()));
    }
}
