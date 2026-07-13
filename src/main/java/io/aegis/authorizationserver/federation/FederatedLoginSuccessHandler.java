package io.aegis.authorizationserver.federation;

import io.aegis.authorizationserver.auth.AegisUserPrincipal;
import io.aegis.authorizationserver.auth.IdentityClient;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
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

    private static String extractEmail(OAuth2User user) {
        String email = user.getAttribute("email");
        if (StringUtils.hasText(email)) {
            return email;
        }
        // GitHub without a public email / email scope: synthesize its stable noreply address.
        String login = user.getAttribute("login");
        if (StringUtils.hasText(login)) {
            return login + "@users.noreply.github.com";
        }
        throw new IllegalStateException("federated provider returned no email to identify the user");
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
