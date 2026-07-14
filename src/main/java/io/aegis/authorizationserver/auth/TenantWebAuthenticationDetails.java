package io.aegis.authorizationserver.auth;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

/** Captures the {@code tenant} (organization) field from the login form so the authentication
 * provider can verify credentials against the right tenant. */
public class TenantWebAuthenticationDetails extends WebAuthenticationDetails {

    private final String tenant;

    /**
     * Transient hint carried from {@link IdentityAuthenticationProvider} (which learns it from
     * identity-service's authenticate response) to the MFA step-up success handler, both within the same
     * login POST. Deliberately {@link JsonIgnore}d: it is a login-time signal only, so it must never be
     * persisted into the saved {@code OAuth2Authorization} — the stored details stay exactly as before.
     */
    private boolean mfaRequired;

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

    @JsonIgnore
    public boolean isMfaRequired() {
        return mfaRequired;
    }

    @JsonIgnore
    public void setMfaRequired(boolean mfaRequired) {
        this.mfaRequired = mfaRequired;
    }
}
