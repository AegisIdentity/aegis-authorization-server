package io.aegis.authorizationserver.auth;

import java.util.List;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

/**
 * Authenticates the resource owner as {@code (organization, username, password)} against
 * {@code identity-service}. The organization/tenant comes from the login form (via
 * {@link TenantWebAuthenticationDetails}); on success the resulting {@link Authentication} carries an
 * {@link AegisUserPrincipal} with the user's tenant, which the JWT customizer stamps onto the token.
 */
@Component
public class IdentityAuthenticationProvider implements AuthenticationProvider {

    private static final List<GrantedAuthority> USER = List.of(new SimpleGrantedAuthority("ROLE_USER"));

    private final IdentityClient identityClient;

    public IdentityAuthenticationProvider(IdentityClient identityClient) {
        this.identityClient = identityClient;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = String.valueOf(authentication.getCredentials());
        String tenant = tenantOf(authentication);
        if (tenant == null || tenant.isBlank()) {
            throw new BadCredentialsException("organization is required");
        }
        AegisUserPrincipal principal = identityClient.authenticate(tenant, username, password)
                .orElseThrow(() -> new BadCredentialsException("invalid organization, username, or password"));

        var result = new UsernamePasswordAuthenticationToken(principal, null, USER);
        result.setDetails(authentication.getDetails());
        return result;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static String tenantOf(Authentication authentication) {
        return authentication.getDetails() instanceof TenantWebAuthenticationDetails details
                ? details.getTenant() : null;
    }
}
