package io.aegis.authorizationserver.idjag;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.LinkedMultiValueMap;

/**
 * Converts an RFC 7523 {@code jwt-bearer} token request into an {@link IdJagAuthenticationToken}.
 *
 * <p>Spring Authorization Server 7.1 does <b>not</b> ship this grant — verified against the jar —
 * so it is ours. It is the second half of MCP Enterprise-Managed Authorization: having obtained an
 * ID-JAG from the enterprise IdP, the client redeems it here for an MCP access token, without ever
 * being redirected to the MCP server's own consent screen.
 */
public class IdJagAuthenticationConverter implements AuthenticationConverter {

    /** RFC 7523 grant type URN. */
    public static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    private static final String ASSERTION = "assertion";

    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!GRANT_TYPE.equals(grantType)) {
            // Not ours. Returning null lets SAS's other converters handle their own grants;
            // claiming the request here would break client_credentials and authorization_code.
            return null;
        }

        MultiValueMap<String, String> parameters = parametersOf(request);

        String assertion = single(parameters, ASSERTION);
        if (assertion == null || assertion.isBlank()) {
            throw invalidRequest("assertion is required for the jwt-bearer grant");
        }

        String resource = single(parameters, OAuth2ParameterNames.RESOURCE);
        if (resource == null || resource.isBlank()) {
            // RFC 8707 resource indicators are MANDATORY in MCP rev 2026-07-28. Without one there is
            // no audience to narrow the issued token to, and an unaudienced token is usable anywhere.
            throw invalidRequest("resource is required: the token must be audience-restricted");
        }

        Set<String> scopes = new LinkedHashSet<>();
        String scope = single(parameters, OAuth2ParameterNames.SCOPE);
        if (scope != null && !scope.isBlank()) {
            scopes.addAll(Arrays.asList(scope.split(" ")));
        }

        Map<String, Object> additional = new HashMap<>();
        parameters.forEach((key, values) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE)
                    && !key.equals(ASSERTION)
                    && !key.equals(OAuth2ParameterNames.SCOPE)) {
                additional.put(key, values.get(0));
            }
        });

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
        if (clientPrincipal == null) {
            // The client-authentication filter runs before this converter and populates the context.
            // An empty context therefore means the client never authenticated — refuse rather than
            // build a grant with an anonymous principal, which would issue a token to nobody in
            // particular.
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
                            "client authentication is required for the jwt-bearer grant", null));
        }
        return new IdJagAuthenticationToken(clientPrincipal, assertion, resource, scopes, additional);
    }

    /**
     * @throws OAuth2AuthenticationException if the parameter appears more than once. Duplicate
     *         parameters are a classic request-smuggling shape — two values, and which one wins
     *         depends on the parser — so rejecting is the only unambiguous answer.
     */
    private static String single(MultiValueMap<String, String> parameters, String name) {
        var values = parameters.get(name);
        if (values == null || values.isEmpty()) {
            return null;
        }
        if (values.size() != 1) {
            throw invalidRequest("parameter '" + name + "' must appear exactly once");
        }
        return values.get(0);
    }

    private static MultiValueMap<String, String> parametersOf(HttpServletRequest request) {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        request.getParameterMap().forEach((key, values) -> {
            for (String value : values) {
                parameters.add(key, value);
            }
        });
        return parameters;
    }

    private static OAuth2AuthenticationException invalidRequest(String message) {
        return new OAuth2AuthenticationException(
                new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, message, null));
    }
}
