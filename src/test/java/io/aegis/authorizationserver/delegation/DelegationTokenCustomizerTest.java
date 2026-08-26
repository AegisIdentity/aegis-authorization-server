package io.aegis.authorizationserver.delegation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.aegis.commons.audit.AuditEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeActor;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeCompositeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

/** Wires {@link DelegationClaims} and {@link ScopeNarrowing} into actual token issuance. */
class DelegationTokenCustomizerTest {

    private List<AuditEvent> published;
    private DelegationTokenCustomizer customizer;

    @BeforeEach
    void setUp() {
        published = new ArrayList<>();
        customizer = new DelegationTokenCustomizer(published::add);
    }

    private static RegisteredClient client() {
        return RegisteredClient.withId("c").clientId("agent-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .scope("files:read").scope("files:write")
                .build();
    }

    private static JwtEncodingContext context(Object principal, Set<String> authorizedScopes,
                                              Set<String> subjectScopes) {
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder().subject("ignored");
        JwtEncodingContext.Builder builder = JwtEncodingContext
                .with(JwsHeader.with(org.springframework.security.oauth2.jose.jws.SignatureAlgorithm.RS256), claims)
                .registeredClient(client())
                .principal(principal instanceof org.springframework.security.core.Authentication a
                        ? a : new TestingAuthenticationToken(principal, null))
                .authorizedScopes(authorizedScopes)
                .tokenType(OAuth2TokenType.ACCESS_TOKEN);
        if (subjectScopes != null) {
            builder.put(DelegationTokenCustomizer.SUBJECT_SCOPES_ATTRIBUTE, subjectScopes);
        }
        return builder.build();
    }

    private static OAuth2TokenExchangeCompositeAuthenticationToken exchange() {
        return new OAuth2TokenExchangeCompositeAuthenticationToken(
                new TestingAuthenticationToken("user:alice@acme", null),
                // SAS supplies actors nearest-first, mirroring the act-claim nesting they came from.
                List.of(new OAuth2TokenExchangeActor(Map.of("sub", "agent:researcher")),
                        new OAuth2TokenExchangeActor(Map.of("sub", "agent:planner"))));
    }

    @Test
    void an_exchange_sets_subject_to_the_root_and_nests_the_actor_chain() {
        JwtEncodingContext context = context(exchange(), Set.of("files:read"), Set.of("files:read"));

        customizer.customize(context);
        Map<String, Object> claims = context.getClaims().build().getClaims();

        assertThat(claims.get("sub")).isEqualTo("user:alice@acme");

        @SuppressWarnings("unchecked")
        Map<String, Object> act = (Map<String, Object>) claims.get("act");
        assertThat(act.get("sub")).isEqualTo("agent:researcher");
        @SuppressWarnings("unchecked")
        Map<String, Object> inner = (Map<String, Object>) act.get("act");
        assertThat(inner.get("sub")).isEqualTo("agent:planner");
    }

    @Test
    void an_exchange_that_widens_scope_is_refused() {
        JwtEncodingContext context =
                context(exchange(), Set.of("files:read", "files:write"), Set.of("files:read"));

        // Delegation laundering: refused at the exchange, because there is no later point at which
        // the resulting token looks wrong.
        assertThatThrownBy(() -> customizer.customize(context))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .hasMessageContaining("files:write");
    }

    @Test
    void a_refused_exchange_is_audited_as_denied_with_the_escalated_scope_named() {
        JwtEncodingContext context =
                context(exchange(), Set.of("files:read", "files:write"), Set.of("files:read"));

        assertThatThrownBy(() -> customizer.customize(context))
                .isInstanceOf(OAuth2AuthenticationException.class);

        assertThat(published).hasSize(1);
        AuditEvent event = published.get(0);
        assertThat(event.action()).isEqualTo("token.exchange");
        assertThat(event.outcome().name()).isEqualTo("DENIED");
        assertThat(event.onBehalfOf()).isEqualTo("user:alice@acme");
        assertThat(event.attributes().get("escalatedScopes")).contains("files:write");
    }

    @Test
    void a_permitted_exchange_is_audited_with_the_delegation_chain() {
        customizer.customize(context(exchange(), Set.of("files:read"), Set.of("files:read")));

        assertThat(published).hasSize(1);
        AuditEvent event = published.get(0);
        assertThat(event.outcome().name()).isEqualTo("SUCCESS");
        assertThat(event.onBehalfOf()).isEqualTo("user:alice@acme");
        assertThat(event.actor()).isEqualTo("agent:researcher");
        assertThat(event.delegationChain().depth()).isEqualTo(3);
    }

    @Test
    void a_non_exchange_grant_is_left_completely_alone() {
        // client_credentials and authorization_code must be untouched by this customizer — it only
        // has an opinion about delegation.
        JwtEncodingContext context = context("plain-principal", Set.of("files:read"), null);

        customizer.customize(context);

        assertThat(context.getClaims().build().getClaims()).doesNotContainKey("act");
        assertThat(published).isEmpty();
    }
}
