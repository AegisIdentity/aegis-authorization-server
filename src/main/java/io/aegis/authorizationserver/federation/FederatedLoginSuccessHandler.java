package io.aegis.authorizationserver.federation;

import io.aegis.authorizationserver.auth.AegisUserPrincipal;
import io.aegis.authorizationserver.auth.IdentityClient;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Locale;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.StringUtils;

/**
 * Completes a federated (social/OIDC) login. Spring has already authenticated the user against the
 * external provider and produced an {@link OAuth2AuthenticationToken}; this handler maps that external
 * identity to an Aegis user — <strong>JIT-provisioning</strong> it into the tenant's directory (by
 * email) — and replaces the session authentication with a {@link AegisUserPrincipal}-based token so the
 * resumed {@code /oauth2/authorize} flow issues a tenant-scoped Aegis token (the JWT customizer reads
 * the tenant/uid from the principal). It then resumes the originally-requested authorize URL.
 */
public class FederatedLoginSuccessHandler implements AuthenticationSuccessHandler {

    private static final SimpleGrantedAuthority ROLE_USER = new SimpleGrantedAuthority("ROLE_USER");

    private final IdentityClient identityClient;
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    private final SavedRequestAwareAuthenticationSuccessHandler delegate =
            new SavedRequestAwareAuthenticationSuccessHandler();

    public FederatedLoginSuccessHandler(IdentityClient identityClient) {
        this.identityClient = identityClient;
        this.delegate.setDefaultTargetUrl("/");
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        if (!(authentication instanceof OAuth2AuthenticationToken oauthToken)) {
            delegate.onAuthenticationSuccess(request, response, authentication);
            return;
        }
        String registrationId = oauthToken.getAuthorizedClientRegistrationId();
        int sep = registrationId.indexOf(BrokerClientRegistrationRepository.SEPARATOR);
        String tenant = sep < 0 ? registrationId : registrationId.substring(0, sep);

        OAuth2User user = oauthToken.getPrincipal();
        String email = extractEmail(user);
        String username = extractUsername(user, email);

        AegisUserPrincipal principal = identityClient.provisionFederated(tenant, email, username);

        List<GrantedAuthority> authorities = List.of(ROLE_USER,
                FactorGrantedAuthority.fromAuthority("FACTOR_FEDERATED"));
        var aegisAuth = new UsernamePasswordAuthenticationToken(principal, null, authorities);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(aegisAuth);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        delegate.onAuthenticationSuccess(request, response, aegisAuth);
    }

    /**
     * Resolves the email used to link/provision — the account key — and only accepts an email the
     * provider asserts as <strong>verified</strong>. Without this, an attacker could set a victim's
     * (unverified) address at a social provider and take over the victim's Aegis account via JIT
     * matching-by-email. For OIDC we require {@code email_verified == true}; for OAuth2 (GitHub) whose
     * userinfo carries no verification flag, we ignore the mutable {@code email} attribute entirely and
     * key on the provider-bound {@code login} (GitHub's stable noreply address), which cannot
     * impersonate an arbitrary address.
     */
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
