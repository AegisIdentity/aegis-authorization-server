package io.aegis.authorizationserver.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.FilterChain;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * The MFA step-up decision + the gate that enforces it. Password is assumed already verified; these
 * cover the second-factor policy (challenge enrolled users; enrol when the org requires it) and the
 * boundary that no token is issued until the second factor completes.
 */
class MfaStepUpTest {

    private final MfaClient mfaClient = mock(MfaClient.class);
    private final MfaStepUp stepUp = new MfaStepUp(mfaClient);

    private Authentication passwordAuth(String tenant, String userId, String username, boolean mfaRequired) {
        var request = new MockHttpServletRequest();
        request.setParameter("tenant", tenant);
        var details = new TenantWebAuthenticationDetails(request);
        details.setMfaRequired(mfaRequired);
        var token = new UsernamePasswordAuthenticationToken(
                new AegisUserPrincipal(tenant, userId, username), null, List.of());
        token.setDetails(details);
        return token;
    }

    @Test
    void an_enrolled_user_is_always_challenged() {
        when(mfaClient.status("acme", "alice")).thenReturn(new MfaClient.StepUpStatus(true, List.of("totp")));
        var request = new MockHttpServletRequest();

        MfaStepUp.Mode mode = stepUp.arm(request, passwordAuth("acme", "u-1", "alice", false));

        assertThat(mode).isEqualTo(MfaStepUp.Mode.CHALLENGE);
        assertThat(stepUp.isPending(request)).isTrue();
    }

    @Test
    void a_required_but_unenrolled_user_is_forced_to_enrol() {
        when(mfaClient.status("acme", "bob")).thenReturn(new MfaClient.StepUpStatus(false, List.of()));
        var request = new MockHttpServletRequest();

        MfaStepUp.Mode mode = stepUp.arm(request, passwordAuth("acme", "u-2", "bob", true));

        assertThat(mode).isEqualTo(MfaStepUp.Mode.ENROL);
        assertThat(stepUp.isPending(request)).isTrue();
    }

    @Test
    void a_not_required_unenrolled_user_proceeds_without_mfa() {
        when(mfaClient.status("acme", "carol")).thenReturn(new MfaClient.StepUpStatus(false, List.of()));
        var request = new MockHttpServletRequest();

        MfaStepUp.Mode mode = stepUp.arm(request, passwordAuth("acme", "u-3", "carol", false));

        assertThat(mode).isEqualTo(MfaStepUp.Mode.NONE);
        assertThat(stepUp.isPending(request)).isFalse();
    }

    @Test
    void the_gate_blocks_the_authorize_endpoint_while_a_step_up_is_pending() throws Exception {
        when(mfaClient.status("acme", "alice")).thenReturn(new MfaClient.StepUpStatus(true, List.of("totp")));
        var request = new MockHttpServletRequest("GET", "/oauth2/authorize");
        // Arm the pending state on this request's session.
        stepUp.arm(request, passwordAuth("acme", "u-1", "alice", false));

        var response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);
        new MfaPendingGateFilter(stepUp).doFilter(request, response, chain);

        // Blocked: redirected to /mfa, the authorization endpoint filter never runs.
        assertThat(response.getRedirectedUrl()).isEqualTo("/mfa");
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void the_gate_lets_the_authorize_endpoint_through_when_nothing_is_pending() throws Exception {
        var request = new MockHttpServletRequest("GET", "/oauth2/authorize");
        var response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        new MfaPendingGateFilter(stepUp).doFilter(request, response, chain);

        assertThat(response.getRedirectedUrl()).isNull();
        verify(chain).doFilter(request, response);
    }

    @Test
    void the_success_handler_routes_to_mfa_when_a_step_up_is_armed() throws Exception {
        when(mfaClient.status("acme", "alice")).thenReturn(new MfaClient.StepUpStatus(true, List.of("totp")));
        var request = new MockHttpServletRequest("POST", "/login");
        var response = new MockHttpServletResponse();

        new MfaStepUpAuthenticationSuccessHandler(stepUp)
                .onAuthenticationSuccess(request, response, passwordAuth("acme", "u-1", "alice", false));

        assertThat(response.getRedirectedUrl()).isEqualTo("/mfa");
    }
}
