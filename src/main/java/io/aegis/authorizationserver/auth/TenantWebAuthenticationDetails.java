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

    /**
     * Reconstruction constructor used by the JDBC authorization store's Jackson deserializer (via
     * {@link TenantWebAuthenticationDetailsMixin}): the authenticated token — including these details —
     * is persisted inside the saved {@code OAuth2Authorization} and re-read at the token endpoint.
     */
    public TenantWebAuthenticationDetails(String remoteAddress, String sessionId, String tenant) {
        super(remoteAddress, sessionId);
        this.tenant = tenant;
    }

    public String getTenant() {
        return tenant;
    }
}
