package io.aegis.authorizationserver.idjag;

import io.aegis.commons.audit.AuditEvent;
import io.aegis.commons.audit.AuditEventPublisher;
import io.aegis.commons.audit.AuditOutcome;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

/**
 * Redeems an ID-JAG for an MCP access token — the RFC 7523 {@code jwt-bearer} grant that Spring
 * Authorization Server 7.1 does not ship.
 *
 * <p>This completes MCP <b>Enterprise-Managed Authorization</b>. The user signed in once at the
 * enterprise IdP, which evaluated tenant policy and issued an ID-JAG; the client presents it here and
 * receives a token for one specific MCP resource, never having been redirected to that server's own
 * consent screen. Revoking a user's access to every MCP server in an estate becomes one
 * control-plane action.
 *
 * <p>Scopes are <b>intersected</b>, never unioned: the issued token can only ever be narrower than
 * both the assertion's grant and the client's registration.
 */
public class IdJagAuthenticationProvider implements AuthenticationProvider {

    private final JwtDecoder assertionDecoder;
    private final IdJagAssertionValidator validator;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final OAuth2AuthorizationService authorizationService;
    private final AuditEventPublisher audit;

    public IdJagAuthenticationProvider(JwtDecoder assertionDecoder,
                                       IdJagAssertionValidator validator,
                                       OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
                                       OAuth2AuthorizationService authorizationService,
                                       AuditEventPublisher audit) {
        this.assertionDecoder = assertionDecoder;
        this.validator = validator;
        this.tokenGenerator = tokenGenerator;
        this.authorizationService = authorizationService;
        this.audit = audit;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        IdJagAuthenticationToken request = (IdJagAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken clientPrincipal = clientPrincipalOf(request);
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        // Signature first: everything downstream reads claims, and reading claims from an unverified
        // token is reading attacker-controlled input.
        Jwt assertion;
        try {
            assertion = assertionDecoder.decode(request.getAssertion());
        } catch (JwtException e) {
            deny(registeredClient, request, "signature");
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_GRANT, "ID-JAG signature verification failed", null));
        }

        IdJagValidationResult result =
                validator.validate(assertion, request.getResource(), Instant.now());
        if (result != IdJagValidationResult.VALID) {
            deny(registeredClient, request, result.name());
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.INVALID_GRANT, "ID-JAG rejected: " + result, null));
        }

        Set<String> scopes = intersect(request.getScopes(), assertion.getClaimAsString("scope"),
                registeredClient);

        OAuth2TokenContext context = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(clientPrincipal)
                .authorizationServerContext(
                        org.springframework.security.oauth2.server.authorization.context
                                .AuthorizationServerContextHolder.getContext())
                .authorizedScopes(scopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                .authorizationGrantType(new AuthorizationGrantType(IdJagAuthenticationConverter.GRANT_TYPE))
                .authorizationGrant(request)
                .build();

        OAuth2Token generated = tokenGenerator.generate(context);
        if (generated == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(
                    OAuth2ErrorCodes.SERVER_ERROR, "failed to generate an access token", null));
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                generated.getTokenValue(), generated.getIssuedAt(), generated.getExpiresAt(), scopes);

        OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(assertion.getSubject())
                .authorizationGrantType(new AuthorizationGrantType(IdJagAuthenticationConverter.GRANT_TYPE))
                .authorizedScopes(scopes)
                .accessToken(accessToken)
                .build();
        authorizationService.save(authorization);

        record(registeredClient, assertion.getSubject(), request.getResource(),
                AuditOutcome.SUCCESS, null);

        return new OAuth2AccessTokenAuthenticationToken(
                registeredClient, clientPrincipal, accessToken, null, null);
    }

    /**
     * The narrowest of: what was requested, what the assertion granted, and what the client is
     * registered for.
     *
     * <p>Intersection rather than union — an ID-JAG must never be able to widen a client's
     * registered authority, and a client must never be able to widen what the IdP granted.
     */
    static Set<String> intersect(Set<String> requested, String assertionScope,
                                         RegisteredClient client) {
        Set<String> granted = new LinkedHashSet<>();
        if (assertionScope != null && !assertionScope.isBlank()) {
            granted.addAll(Set.of(assertionScope.split(" ")));
        }

        Set<String> effective = new LinkedHashSet<>(requested.isEmpty() ? granted : requested);
        if (!granted.isEmpty()) {
            effective.retainAll(granted);
        }
        effective.retainAll(client.getScopes());
        return effective;
    }

    private static OAuth2ClientAuthenticationToken clientPrincipalOf(IdJagAuthenticationToken request) {
        Authentication principal = (Authentication) request.getPrincipal();
        if (principal instanceof OAuth2ClientAuthenticationToken client && client.isAuthenticated()
                && client.getRegisteredClient() != null) {
            return client;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }

    private void deny(RegisteredClient client, IdJagAuthenticationToken request, String reason) {
        record(client, null, request.getResource(), AuditOutcome.DENIED, reason);
    }

    private void record(RegisteredClient client, String subject, String resource,
                        AuditOutcome outcome, String reason) {
        if (audit == null) {
            return;
        }
        AuditEvent.Builder event = AuditEvent.of("authz", "idjag.redeem", outcome)
                .actor(client == null ? "unknown" : client.getClientId())
                .target(resource);
        if (subject != null) {
            event.onBehalfOf(subject);
        }
        if (reason != null) {
            event.attribute("reason", reason);
        }
        audit.publish(event.build());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return IdJagAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
