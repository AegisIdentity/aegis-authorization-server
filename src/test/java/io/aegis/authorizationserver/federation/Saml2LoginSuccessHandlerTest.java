package io.aegis.authorizationserver.federation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.aegis.authorizationserver.auth.AegisUserPrincipal;
import io.aegis.authorizationserver.auth.IdentityClient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;

class Saml2LoginSuccessHandlerTest {

    private final IdentityClient identityClient = mock(IdentityClient.class);
    private final Saml2LoginSuccessHandler handler =
            new Saml2LoginSuccessHandler(new FederatedSessionEstablisher(identityClient));

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void maps_the_saml_assertion_to_email_and_jit_provisions_in_the_registration_tenant() throws Exception {
        when(identityClient.provisionFederated("acme", "jane@acme.com", "jane"))
                .thenReturn(new AegisUserPrincipal("acme", "u-1", "jane@acme.com"));

        Saml2AuthenticatedPrincipal principal = mock(Saml2AuthenticatedPrincipal.class);
        when(principal.getRelyingPartyRegistrationId()).thenReturn(
                BrokerClientRegistrationRepository.registrationId("acme", "corp-okta"));
        when(principal.getFirstAttribute("email")).thenReturn("Jane@Acme.com");
        when(principal.getFirstAttribute("urn:oid:0.9.2342.19200300.100.1.1")).thenReturn("jane");
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn(principal);

        var request = new MockHttpServletRequest();
        request.getSession(true);
        handler.onAuthenticationSuccess(request, new MockHttpServletResponse(), auth);

        // tenant taken from the registrationId, email lowercased, username from the uid attribute
        verify(identityClient).provisionFederated("acme", "jane@acme.com", "jane");
        assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal())
                .isInstanceOf(AegisUserPrincipal.class);
    }
}
