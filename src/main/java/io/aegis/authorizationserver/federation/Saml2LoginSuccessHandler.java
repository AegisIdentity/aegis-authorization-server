package io.aegis.authorizationserver.federation;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Locale;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.StringUtils;

/**
 * Completes a SAML federated login: maps the (IdP-signed) assertion to an email, then delegates to
 * {@link FederatedSessionEstablisher} to JIT-provision and resume the authorize flow.
 *
 * <p>Unlike social OAuth, a SAML assertion is cryptographically signed by the specific IdP the tenant
 * configured, so an asserted email is trusted (the IdP is the verifier) — there is no unverified-email
 * takeover vector here. Common email/uid attribute names are tried, falling back to the NameID.
 */
public class Saml2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private static final List<String> EMAIL_ATTRS = List.of(
            "email", "mail",
            "urn:oid:0.9.2342.19200300.100.1.3",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress");
    private static final List<String> USERNAME_ATTRS = List.of(
            "urn:oid:0.9.2342.19200300.100.1.1", "uid", "username", "preferred_username");

    private final FederatedSessionEstablisher establisher;

    public Saml2LoginSuccessHandler(FederatedSessionEstablisher establisher) {
        this.establisher = establisher;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        if (!(authentication.getPrincipal() instanceof Saml2AuthenticatedPrincipal principal)) {
            return;
        }
        String registrationId = principal.getRelyingPartyRegistrationId();
        int sep = registrationId == null ? -1 : registrationId.indexOf(BrokerClientRegistrationRepository.SEPARATOR);
        String tenant = sep < 0 ? registrationId : registrationId.substring(0, sep);

        String email = firstAttribute(principal, EMAIL_ATTRS);
        if (!StringUtils.hasText(email) && looksLikeEmail(principal.getName())) {
            email = principal.getName();
        }
        if (!StringUtils.hasText(email)) {
            throw new IllegalStateException("SAML assertion carried no email to identify the user");
        }
        String username = firstAttribute(principal, USERNAME_ATTRS);
        if (!StringUtils.hasText(username)) {
            username = email;
        }
        establisher.establish(tenant, email.toLowerCase(Locale.ROOT), username, request, response);
    }

    private static String firstAttribute(Saml2AuthenticatedPrincipal principal, List<String> names) {
        for (String name : names) {
            Object value = principal.getFirstAttribute(name);
            if (value != null && StringUtils.hasText(value.toString())) {
                return value.toString();
            }
        }
        return null;
    }

    private static boolean looksLikeEmail(String value) {
        return value != null && value.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");
    }
}
