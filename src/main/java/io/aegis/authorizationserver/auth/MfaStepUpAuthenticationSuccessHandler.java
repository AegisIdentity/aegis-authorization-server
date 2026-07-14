package io.aegis.authorizationserver.auth;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

/**
 * Runs after the <em>password</em> factor succeeds. If the user needs a second factor
 * ({@link MfaStepUp#arm} returns CHALLENGE or ENROL) the browser is sent to {@code /mfa} instead of the
 * saved authorize request — which stays cached and is resumed only once the step-up completes. The
 * authorization endpoint itself is blocked meanwhile by {@link MfaPendingGateFilter}, so redirecting
 * here is a UX convenience, not the security boundary.
 */
public class MfaStepUpAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final MfaStepUp stepUp;
    private final AuthenticationSuccessHandler delegate = new SavedRequestAwareAuthenticationSuccessHandler();

    public MfaStepUpAuthenticationSuccessHandler(MfaStepUp stepUp) {
        this.stepUp = stepUp;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        if (stepUp.arm(request, authentication) != MfaStepUp.Mode.NONE) {
            response.sendRedirect(request.getContextPath() + "/mfa");
            return;
        }
        delegate.onAuthenticationSuccess(request, response, authentication);
    }
}
