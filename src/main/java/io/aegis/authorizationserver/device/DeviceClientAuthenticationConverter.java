package io.aegis.authorizationserver.device;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.MultiValueMap;

/**
 * Extracts the {@code client_id} of a <em>public</em> client calling the device authorization
 * endpoint (RFC 8628 §3.1).
 *
 * <p>Spring Authorization Server does not ship client authentication for this case. Its
 * {@code PublicClientAuthenticationConverter} is built for {@code authorization_code} + PKCE and
 * keys off {@code code_verifier}, which the device grant has no equivalent of — so a device posting
 * only its {@code client_id} produces no {@code Authentication} at all, the request stays anonymous,
 * and the endpoint's {@code authenticated()} rule rejects it before any device code is issued.
 *
 * <p>Deliberately narrow, because this converter's whole job is to let an <em>unauthenticated</em>
 * caller through:
 * <ul>
 *   <li>it matches only the configured device authorization endpoint — nothing else can be reached
 *       by presenting a bare {@code client_id};</li>
 *   <li>it declines when any other credential is present ({@code Authorization} header, or a
 *       {@code client_secret} parameter), so it can never downgrade a confidential client's
 *       authentication to "public" — that would turn a secret-protected client into an open one;</li>
 *   <li>it rejects a duplicated {@code client_id} parameter rather than picking one, since parameter
 *       smuggling is a classic way to make a proxy and a server disagree about identity.</li>
 * </ul>
 *
 * <p>Establishing that the client is a <em>registered</em> public client is
 * {@link DeviceClientAuthenticationProvider}'s job; this class only parses.
 */
public final class DeviceClientAuthenticationConverter implements AuthenticationConverter {

    /** RFC 8628 grant type URN, used to scope the token-endpoint case. */
    private static final String DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

    private final RequestMatcher deviceRequestMatcher;

    public DeviceClientAuthenticationConverter(String deviceAuthorizationEndpointUri,
                                               String tokenEndpointUri) {
        this.deviceRequestMatcher = request -> {
            if (!"POST".equals(request.getMethod())) {
                return false;
            }
            String uri = request.getRequestURI();
            if (deviceAuthorizationEndpointUri.equals(uri)) {
                return true;
            }
            // The device also polls the TOKEN endpoint with only its client_id (RFC 8628 §3.4).
            // Scoped strictly to the device grant: widening public-client authentication to the
            // token endpoint in general would let a public client redeem an authorization_code
            // without PKCE, removing the protection that makes public clients safe at all.
            return tokenEndpointUri.equals(uri)
                    && DEVICE_CODE_GRANT.equals(request.getParameter(OAuth2ParameterNames.GRANT_TYPE));
        };
    }

    @Override
    public Authentication convert(HttpServletRequest request) {
        if (!this.deviceRequestMatcher.matches(request)) {
            return null;
        }
        // Never weaken a client that is presenting real credentials: let the standard converters
        // handle those. Without this guard, a confidential client could be authenticated as public
        // simply by having its secret ignored.
        if (request.getHeader("Authorization") != null
                || request.getParameter(OAuth2ParameterNames.CLIENT_SECRET) != null) {
            return null;
        }

        MultiValueMap<String, String> parameters = getParameters(request);
        String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
        if (clientId == null || clientId.isBlank()) {
            return null; // not a client_id-authenticated request; let the chain decide
        }
        if (parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST));
        }
        return new OAuth2ClientAuthenticationToken(
                clientId, ClientAuthenticationMethod.NONE, null, null);
    }

    /**
     * The servlet container already merges query-string and form parameters, so reading the
     * parameter map is enough — and using one representation avoids the classic mismatch where a
     * parser and the framework disagree about which duplicate wins.
     */
    private static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        MultiValueMap<String, String> parameters = new org.springframework.util.LinkedMultiValueMap<>();
        request.getParameterMap().forEach((key, values) -> {
            for (String value : values) {
                parameters.add(key, value);
            }
        });
        return parameters;
    }
}
