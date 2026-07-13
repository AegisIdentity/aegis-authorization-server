package io.aegis.authorizationserver.auth;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

/** Captures the {@code tenant} (organization) field from the login form so the authentication
 * provider can verify credentials against the right tenant. */
public class TenantWebAuthenticationDetails extends WebAuthenticationDetails {

    private final String tenant;

    public TenantWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        this.tenant = request.getParameter("tenant");
    }

    public String getTenant() {
        return tenant;
    }
}
