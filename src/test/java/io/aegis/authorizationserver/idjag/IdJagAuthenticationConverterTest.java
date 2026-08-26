package io.aegis.authorizationserver.idjag;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

/**
 * Parses an RFC 7523 {@code jwt-bearer} token request — the grant Spring Authorization Server 7.1
 * does not ship, and the one MCP Enterprise-Managed Authorization depends on.
 */
class IdJagAuthenticationConverterTest {

    private final IdJagAuthenticationConverter converter = new IdJagAuthenticationConverter();

    @BeforeEach
    void authenticateClient() {
        // In production the client-authentication filter runs before this converter and leaves the
        // authenticated client in the context; the tests reproduce that.
        SecurityContextHolder.setContext(new SecurityContextImpl(
                new TestingAuthenticationToken("mcp-client", null)));
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private static MockHttpServletRequest tokenRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth2/token");
        request.addParameter(OAuth2ParameterNames.GRANT_TYPE, IdJagAuthenticationConverter.GRANT_TYPE);
        request.addParameter("assertion", "eyJhbGciOiJSUzI1NiJ9.body.sig");
        request.addParameter(OAuth2ParameterNames.RESOURCE, "https://mcp.acme.com/files");
        request.addParameter(OAuth2ParameterNames.SCOPE, "files:read files:list");
        return request;
    }

    @Test
    void parses_a_jwt_bearer_request() {
        Authentication authentication = converter.convert(tokenRequest());

        assertThat(authentication).isInstanceOf(IdJagAuthenticationToken.class);
        IdJagAuthenticationToken token = (IdJagAuthenticationToken) authentication;

        assertThat(token.getAssertion()).isEqualTo("eyJhbGciOiJSUzI1NiJ9.body.sig");
        assertThat(token.getResource()).isEqualTo("https://mcp.acme.com/files");
        assertThat(token.getScopes()).containsExactlyInAnyOrder("files:read", "files:list");
    }

    @Test
    void ignores_a_request_for_a_different_grant_type() {
        // Returning null lets SAS's other converters handle their own grants. Claiming the request
        // here would break client_credentials and authorization_code outright.
        MockHttpServletRequest other = new MockHttpServletRequest("POST", "/oauth2/token");
        other.addParameter(OAuth2ParameterNames.GRANT_TYPE, "client_credentials");

        assertThat(converter.convert(other)).isNull();
    }

    @Test
    void ignores_a_request_with_no_grant_type() {
        assertThat(converter.convert(new MockHttpServletRequest("POST", "/oauth2/token"))).isNull();
    }

    @Test
    void a_missing_assertion_is_an_invalid_request() {
        MockHttpServletRequest request = tokenRequest();
        request.removeParameter("assertion");

        assertThatThrownBy(() -> converter.convert(request))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .hasMessageContaining("assertion");
    }

    @Test
    void a_missing_resource_is_an_invalid_request() {
        // RFC 8707 resource indicators are MANDATORY in MCP rev 2026-07-28. Without one there is no
        // audience to narrow the issued token to, and an unaudienced token is usable anywhere.
        MockHttpServletRequest request = tokenRequest();
        request.removeParameter(OAuth2ParameterNames.RESOURCE);

        assertThatThrownBy(() -> converter.convert(request))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .hasMessageContaining("resource");
    }

    @Test
    void a_duplicated_parameter_is_rejected() {
        // Duplicate parameters are a classic request-smuggling shape: two values, and which one wins
        // depends on the parser. Rejecting is the only unambiguous answer.
        MockHttpServletRequest request = tokenRequest();
        request.addParameter("assertion", "a-second-assertion");

        assertThatThrownBy(() -> converter.convert(request))
                .isInstanceOf(OAuth2AuthenticationException.class);
    }

    @Test
    void scope_is_optional() {
        MockHttpServletRequest request = tokenRequest();
        request.removeParameter(OAuth2ParameterNames.SCOPE);

        IdJagAuthenticationToken token = (IdJagAuthenticationToken) converter.convert(request);
        assertThat(token.getScopes()).isEmpty();
    }

    @Test
    void the_grant_type_is_the_registered_rfc_7523_urn() {
        assertThat(IdJagAuthenticationConverter.GRANT_TYPE)
                .isEqualTo("urn:ietf:params:oauth:grant-type:jwt-bearer");
    }

    @Test
    void carries_the_authenticated_client_as_the_principal() {
        HttpServletRequest request = tokenRequest();
        IdJagAuthenticationToken token = (IdJagAuthenticationToken) converter.convert(request);

        assertThat(token.getPrincipal()).isNotNull();
    }

    @Test
    void an_unauthenticated_client_is_refused_rather_than_treated_as_anonymous() {
        // Building a grant with a null principal would issue a token to nobody in particular.
        SecurityContextHolder.clearContext();

        assertThatThrownBy(() -> converter.convert(tokenRequest()))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .hasMessageContaining("client authentication");
    }
}
