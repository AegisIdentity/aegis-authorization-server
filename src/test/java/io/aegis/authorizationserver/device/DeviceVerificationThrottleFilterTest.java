package io.aegis.authorizationserver.device;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * The device user_code brute-force throttle. The code is short enough to type, hence guessable, so
 * an authenticated user must not be able to submit an unbounded number of guesses at device
 * authorizations pending for other users.
 */
class DeviceVerificationThrottleFilterTest {

    private static final String ENDPOINT = "/oauth2/device_verification";

    private final DeviceVerificationThrottleFilter filter =
            new DeviceVerificationThrottleFilter(ENDPOINT);

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private void authenticateAs(String user) {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(user, "n/a",
                        AuthorityUtils.createAuthorityList("ROLE_USER")));
    }

    private MockHttpServletRequest submission() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", ENDPOINT);
        request.setRequestURI(ENDPOINT);
        request.setParameter("user_code", "WDJB-MJHT");
        return request;
    }

    @Test
    void submissions_within_the_cap_pass_through() throws Exception {
        authenticateAs("alice");
        for (int i = 0; i < DeviceVerificationThrottleFilter.MAX_ATTEMPTS; i++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            FilterChain chain = new MockFilterChain();
            filter.doFilter(submission(), response, chain);
            assertThat(response.getStatus()).isEqualTo(200);
        }
    }

    @Test
    void the_attempt_over_the_cap_is_rejected_with_429() throws Exception {
        authenticateAs("alice");
        for (int i = 0; i < DeviceVerificationThrottleFilter.MAX_ATTEMPTS; i++) {
            filter.doFilter(submission(), new MockHttpServletResponse(), new MockFilterChain());
        }

        MockHttpServletResponse blocked = new MockHttpServletResponse();
        // A chain that would fail the test if it were ever invoked past the cap.
        FilterChain mustNotProceed = (req, res) ->
                org.junit.jupiter.api.Assertions.fail("request past the cap should not reach the endpoint");
        filter.doFilter(submission(), blocked, mustNotProceed);

        assertThat(blocked.getStatus()).isEqualTo(429);
        assertThat(blocked.getHeader("Retry-After")).isNotNull();
    }

    @Test
    void the_cap_is_per_subject_so_one_users_guessing_does_not_lock_out_another() throws Exception {
        authenticateAs("attacker");
        for (int i = 0; i < DeviceVerificationThrottleFilter.MAX_ATTEMPTS + 5; i++) {
            filter.doFilter(submission(), new MockHttpServletResponse(), new MockFilterChain());
        }

        // A different, legitimate user is unaffected.
        SecurityContextHolder.clearContext();
        authenticateAs("victim");
        MockHttpServletResponse victimResponse = new MockHttpServletResponse();
        filter.doFilter(submission(), victimResponse, new MockFilterChain());

        assertThat(victimResponse.getStatus()).isEqualTo(200);
    }

    @Test
    void a_GET_that_renders_the_form_is_never_throttled() throws Exception {
        authenticateAs("alice");
        MockHttpServletRequest get = new MockHttpServletRequest("GET", ENDPOINT);
        get.setRequestURI(ENDPOINT);

        // Far more than the cap — a GET must always pass, it carries no guess.
        for (int i = 0; i < DeviceVerificationThrottleFilter.MAX_ATTEMPTS + 20; i++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(get, response, new MockFilterChain());
            assertThat(response.getStatus()).isEqualTo(200);
        }
    }

    @Test
    void requests_to_other_endpoints_are_not_throttled() throws Exception {
        authenticateAs("alice");
        MockHttpServletRequest other = new MockHttpServletRequest("POST", "/oauth2/token");
        other.setRequestURI("/oauth2/token");
        other.setParameter("user_code", "irrelevant");

        for (int i = 0; i < DeviceVerificationThrottleFilter.MAX_ATTEMPTS + 20; i++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(other, response, new MockFilterChain());
            assertThat(response.getStatus()).isEqualTo(200);
        }
    }
}
