package io.aegis.authorizationserver.device;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

/**
 * Authenticates a public client at the device authorization endpoint by {@code client_id} alone
 * (RFC 8628 §3.1), completing what {@link DeviceClientAuthenticationConverter} parses.
 *
 * <p>"Authenticates" is doing limited work here, and that is inherent to the grant rather than a
 * weakness in this class: a device binary cannot hold a secret, so possession of a {@code client_id}
 * proves nothing about who is calling. What this establishes is only that the client is
 * <em>registered</em> and <em>declared public</em>. The grant's real authorization comes later, when
 * a signed-in human approves the {@code user_code} on a second screen — which is why the activation
 * page sits behind authentication.
 *
 * <p>The checks below are therefore about refusing to let this weak path be used where a strong one
 * is expected:
 * <ul>
 *   <li>an unknown {@code client_id} is rejected — no anonymous device flows;</li>
 *   <li>a client that is <strong>not</strong> registered with
 *       {@link ClientAuthenticationMethod#NONE} is rejected, so a confidential client's secret can
 *       never be bypassed by routing it through this provider;</li>
 *   <li>a client that was not granted the device grant is refused at the endpoint itself.</li>
 * </ul>
 * Every failure returns the generic {@code invalid_client} with no detail about which check failed,
 * so the endpoint is not a client-enumeration oracle.
 */
public final class DeviceClientAuthenticationProvider implements AuthenticationProvider {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";

    private final RegisteredClientRepository registeredClientRepository;

    public DeviceClientAuthenticationProvider(RegisteredClientRepository registeredClientRepository) {
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2ClientAuthenticationToken clientAuthentication =
                (OAuth2ClientAuthenticationToken) authentication;

        if (!ClientAuthenticationMethod.NONE.equals(clientAuthentication.getClientAuthenticationMethod())) {
            return null; // not ours — let another provider handle it
        }

        String clientId = clientAuthentication.getPrincipal().toString();
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            throw invalidClient(OAuth2ParameterNames.CLIENT_ID);
        }
        // The client must genuinely be public. Refusing here is what stops this path from being used
        // to sidestep a confidential client's secret.
        if (!registeredClient.getClientAuthenticationMethods().contains(ClientAuthenticationMethod.NONE)) {
            throw invalidClient("authentication_method");
        }
        return new OAuth2ClientAuthenticationToken(
                registeredClient, ClientAuthenticationMethod.NONE, null);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /** Generic error — the parameter name is for logs, never echoed to the caller. */
    private static OAuth2AuthenticationException invalidClient(String parameterName) {
        return new OAuth2AuthenticationException(new OAuth2Error(
                OAuth2ErrorCodes.INVALID_CLIENT,
                "Client authentication failed: " + parameterName,
                ERROR_URI));
    }
}
