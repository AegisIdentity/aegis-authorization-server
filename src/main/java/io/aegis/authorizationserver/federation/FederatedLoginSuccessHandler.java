package io.aegis.authorizationserver.federation;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Locale;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.StringUtils;

/**
 * Completes an OAuth2/OIDC federated login: maps the external identity, then delegates to
 * {@link FederatedSessionEstablisher} to JIT-provision and resume the authorize flow.
 *
 * <p>Only a <strong>verified</strong> email is accepted as the account key. For OIDC we require
 * {@code email_verified == true}; for OAuth2 (GitHub) whose userinfo carries no verification flag, we
 * ignore the mutable {@code email} attribute and key on the provider-bound {@code login} (GitHub's
 * stable noreply address). Without this, an attacker could set a victim's unverified email at a provider
 * and take over the victim's account by JIT matching-by-email.
 */
public class FederatedLoginSuccessHandler implements AuthenticationSuccessHandler {

    private final FederatedSessionEstablisher establisher;

    public FederatedLoginSuccessHandler(FederatedSessionEstablisher establisher) {
        this.establisher = establisher;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        if (!(authentication instanceof OAuth2AuthenticationToken oauthToken)) {
            return;
        }
        String registrationId = oauthToken.getAuthorizedClientRegistrationId();
        int sep = registrationId.indexOf(BrokerClientRegistrationRepository.SEPARATOR);
        String tenant = sep < 0 ? registrationId : registrationId.substring(0, sep);

        OAuth2User user = oauthToken.getPrincipal();
        String email = extractEmail(user);
        String username = extractUsername(user, email);

        establisher.establish(tenant, email, username, request, response);
    }

    private static String extractEmail(OAuth2User user) {
        if (user instanceof OidcUser) {
            String email = user.getAttribute("email");
            if (StringUtils.hasText(email) && isVerified(user.getAttribute("email_verified"))) {
                return email.toLowerCase(Locale.ROOT);
            }
            throw new IllegalStateException("OIDC provider returned no verified email; refusing to link");
        }
        // Non-OIDC provider (GitHub): the `email` attribute is not guaranteed verified, so it is not
        // trusted. The login handle is bound to the provider account and safe to key on.
        String login = user.getAttribute("login");
        if (StringUtils.hasText(login)) {
            return (login + "@users.noreply.github.com").toLowerCase(Locale.ROOT);
        }
        throw new IllegalStateException("provider returned no verified identifier; refusing to link");
    }

    private static boolean isVerified(Object emailVerified) {
        return (emailVerified instanceof Boolean b && b)
                || (emailVerified instanceof String s && "true".equalsIgnoreCase(s));
    }

    private static String extractUsername(OAuth2User user, String email) {
        String preferred = user.getAttribute("preferred_username");
        if (StringUtils.hasText(preferred)) {
            return preferred;
        }
        String login = user.getAttribute("login");
        if (StringUtils.hasText(login)) {
            return login;
        }
        return email;
    }
}
