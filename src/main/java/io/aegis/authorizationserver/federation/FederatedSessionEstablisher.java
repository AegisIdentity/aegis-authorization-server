package io.aegis.authorizationserver.federation;

import io.aegis.authorizationserver.auth.AegisUserPrincipal;
import io.aegis.authorizationserver.auth.IdentityClient;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;

/**
 * Shared tail of a federated login (OAuth2/OIDC and SAML): JIT-provision the external identity into the
 * tenant's directory (by verified email), replace the session authentication with an
 * {@link AegisUserPrincipal}-based token carrying an authentication factor (so an OIDC id_token gets an
 * {@code auth_time}), and resume the originally-requested {@code /oauth2/authorize}.
 */
@Component
public class FederatedSessionEstablisher {

    private static final SimpleGrantedAuthority ROLE_USER = new SimpleGrantedAuthority("ROLE_USER");

    private final IdentityClient identityClient;
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();
    private final SavedRequestAwareAuthenticationSuccessHandler resume =
            new SavedRequestAwareAuthenticationSuccessHandler();

    public FederatedSessionEstablisher(IdentityClient identityClient) {
        this.identityClient = identityClient;
        this.resume.setDefaultTargetUrl("/");
    }

    public void establish(String tenant, String email, String username,
                          HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        AegisUserPrincipal principal = identityClient.provisionFederated(tenant, email, username);

        List<GrantedAuthority> authorities = List.of(ROLE_USER,
                FactorGrantedAuthority.fromAuthority("FACTOR_FEDERATED"));
        var aegisAuth = new UsernamePasswordAuthenticationToken(principal, null, authorities);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(aegisAuth);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        resume.onAuthenticationSuccess(request, response, aegisAuth);
    }
}
