package io.aegis.authorizationserver.idjag;

import java.util.Map;
import java.util.Set;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

/** An RFC 7523 {@code jwt-bearer} token request carrying an ID-JAG. */
public class IdJagAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    private final String assertion;
    private final String resource;
    private final Set<String> scopes;

    public IdJagAuthenticationToken(Authentication clientPrincipal, String assertion, String resource,
                                    Set<String> scopes, Map<String, Object> additionalParameters) {
        super(new AuthorizationGrantType(IdJagAuthenticationConverter.GRANT_TYPE),
                clientPrincipal, additionalParameters);
        this.assertion = assertion;
        this.resource = resource;
        this.scopes = scopes == null ? Set.of() : Set.copyOf(scopes);
    }

    public String getAssertion() {
        return assertion;
    }

    /** RFC 8707 resource indicator — the MCP server this token is for. */
    public String getResource() {
        return resource;
    }

    public Set<String> getScopes() {
        return scopes;
    }
}
