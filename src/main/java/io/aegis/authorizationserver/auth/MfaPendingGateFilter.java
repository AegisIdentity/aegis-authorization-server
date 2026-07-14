package io.aegis.authorizationserver.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * The security boundary for MFA step-up. While a step-up is pending in the session, this filter blocks
 * the interactive authorization endpoint and redirects to {@code /mfa}. Installed on the authorization
 * server's protocol filter chain (which matches {@code /oauth2/**}), so an attacker who has only the
 * password — and therefore a session that passed the first factor but not the second — cannot reach
 * {@code /oauth2/authorize} to obtain an authorization code, no matter how they navigate.
 *
 * <p>Only the authorization endpoint is gated: JWKS/discovery/token are not interactive login steps and
 * a code is only ever minted at {@code /oauth2/authorize}, so gating it is sufficient to withhold tokens.
 */
public class MfaPendingGateFilter extends OncePerRequestFilter {

    private final MfaStepUp stepUp;

    public MfaPendingGateFilter(MfaStepUp stepUp) {
        this.stepUp = stepUp;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        // Matches both the root issuer (/oauth2/authorize) and per-tenant issuers (/{tenant}/oauth2/authorize).
        boolean isAuthorizeEndpoint = request.getRequestURI().contains("/oauth2/authorize");
        if (isAuthorizeEndpoint && stepUp.isPending(request)) {
            response.sendRedirect(request.getContextPath() + "/mfa");
            return;
        }
        filterChain.doFilter(request, response);
    }
}
