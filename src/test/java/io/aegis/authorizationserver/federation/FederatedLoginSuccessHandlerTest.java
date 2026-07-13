package io.aegis.authorizationserver.federation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.aegis.authorizationserver.auth.AegisUserPrincipal;
import io.aegis.authorizationserver.auth.IdentityClient;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

class FederatedLoginSuccessHandlerTest {

    private final IdentityClient identityClient = mock(IdentityClient.class);
    private final FederatedLoginSuccessHandler handler = new FederatedLoginSuccessHandler(identityClient);

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private void run(OAuth2User user, String registrationId) throws Exception {
        var token = new OAuth2AuthenticationToken(user, user.getAuthorities(), registrationId);
        var request = new MockHttpServletRequest();
        request.getSession(true);
        handler.onAuthenticationSuccess(request, new MockHttpServletResponse(), token);
    }

    private static DefaultOidcUser oidcUser(Map<String, Object> claims) {
        var builder = OidcIdToken.withTokenValue("token")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(300));
        claims.forEach(builder::claim);
        return new DefaultOidcUser(List.of(new SimpleGrantedAuthority("ROLE_USER")), builder.build());
    }

    @Test
    void provisions_by_verified_oidc_email_and_swaps_in_the_aegis_principal_with_a_factor() throws Exception {
        when(identityClient.provisionFederated("acme", "jane@acme.com", "jane"))
                .thenReturn(new AegisUserPrincipal("acme", "u-1", "jane@acme.com"));
        OAuth2User user = oidcUser(Map.of("sub", "ext-1", "email", "jane@acme.com",
                "email_verified", true, "preferred_username", "jane"));

        run(user, BrokerClientRegistrationRepository.registrationId("acme", "google"));

        // JIT-provisioned into the tenant derived from the registrationId, by verified email.
        verify(identityClient).provisionFederated("acme", "jane@acme.com", "jane");
        Authentication result = SecurityContextHolder.getContext().getAuthentication();
        assertThat(result.getPrincipal()).isInstanceOf(AegisUserPrincipal.class);
        // Carries an authentication factor so the OIDC id_token gets an auth_time.
        assertThat(result.getAuthorities()).anyMatch(a -> "FACTOR_FEDERATED".equals(a.getAuthority()));
    }

    @Test
    void refuses_to_link_an_unverified_oidc_email() throws Exception {
        // Account-takeover guard: an unverified email must never JIT-link to an existing account.
        OAuth2User user = oidcUser(Map.of("sub", "ext-9", "email", "victim@acme.com",
                "email_verified", false, "preferred_username", "attacker"));

        assertThatThrownBy(() -> run(user, BrokerClientRegistrationRepository.registrationId("acme", "google")))
                .isInstanceOf(IllegalStateException.class);
        verify(identityClient, never()).provisionFederated(
                ArgumentMatchers.anyString(), ArgumentMatchers.anyString(), ArgumentMatchers.anyString());
    }

    @Test
    void github_without_email_uses_login_and_synthesizes_a_noreply_address() throws Exception {
        when(identityClient.provisionFederated("bravo", "octocat@users.noreply.github.com", "octocat"))
                .thenReturn(new AegisUserPrincipal("bravo", "u-2", "octocat"));
        OAuth2User user = new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")),
                Map.of("id", "9999", "login", "octocat"), "id");

        run(user, BrokerClientRegistrationRepository.registrationId("bravo", "github"));

        verify(identityClient).provisionFederated("bravo", "octocat@users.noreply.github.com", "octocat");
        assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal())
                .isInstanceOf(AegisUserPrincipal.class);
    }
}
