package io.aegis.authorizationserver.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

class IdentityAuthenticationProviderTest {

    private final IdentityClient identityClient = mock(IdentityClient.class);
    private final IdentityAuthenticationProvider provider =
            new IdentityAuthenticationProvider(identityClient);

    private static UsernamePasswordAuthenticationToken loginAttempt(String tenant, String user, String pw) {
        var token = new UsernamePasswordAuthenticationToken(user, pw);
        if (tenant != null) {
            var request = new MockHttpServletRequest();
            request.setParameter("tenant", tenant);
            token.setDetails(new TenantWebAuthenticationDetails(request));
        }
        return token;
    }

    @Test
    void authenticates_and_carries_the_users_tenant() {
        when(identityClient.authenticate("acme", "alice", "pw"))
                .thenReturn(Optional.of(new AegisUserPrincipal("acme", "u-1", "alice")));

        Authentication result = provider.authenticate(loginAttempt("acme", "alice", "pw"));

        assertThat(result.isAuthenticated()).isTrue();
        assertThat(result.getPrincipal()).isInstanceOf(AegisUserPrincipal.class);
        var principal = (AegisUserPrincipal) result.getPrincipal();
        assertThat(principal.tenantId()).isEqualTo("acme");
        assertThat(principal.username()).isEqualTo("alice");
        // A PASSWORD authentication-factor authority must be present: the Authorization Server derives
        // the OIDC id_token `auth_time` from it, and id_token generation fails without one.
        assertThat(result.getAuthorities()).anyMatch(a ->
                org.springframework.security.core.authority.FactorGrantedAuthority.PASSWORD_AUTHORITY
                        .equals(a.getAuthority()));
    }

    @Test
    void rejects_bad_credentials() {
        when(identityClient.authenticate(any(), any(), any())).thenReturn(Optional.empty());
        assertThatThrownBy(() -> provider.authenticate(loginAttempt("acme", "alice", "wrong")))
                .isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void requires_an_organization() {
        assertThatThrownBy(() -> provider.authenticate(loginAttempt(null, "alice", "pw")))
                .isInstanceOf(BadCredentialsException.class);
    }
}
