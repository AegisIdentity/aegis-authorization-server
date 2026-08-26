package io.aegis.authorizationserver.idjag;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

/**
 * Scopes on the ID-JAG redemption path are <b>intersected</b>, never unioned.
 *
 * <p>Two independent ceilings apply and neither is sufficient alone: an ID-JAG must never widen a
 * client's registered authority, and a client must never widen what the IdP actually granted. Union
 * anywhere in this chain turns enterprise-managed authorization into enterprise-managed
 * privilege escalation.
 */
class IdJagScopeIntersectionTest {

    private static RegisteredClient client(String... scopes) {
        RegisteredClient.Builder builder = RegisteredClient.withId("c").clientId("mcp-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(new AuthorizationGrantType(
                        IdJagAuthenticationConverter.GRANT_TYPE));
        for (String scope : scopes) {
            builder.scope(scope);
        }
        return builder.build();
    }

    @Test
    void the_result_is_the_narrowest_of_requested_granted_and_registered() {
        Set<String> effective = IdJagAuthenticationProvider.intersect(
                Set.of("files:read", "files:write"),      // requested
                "files:read files:list",                   // granted by the ID-JAG
                client("files:read", "files:write", "files:list"));

        assertThat(effective).containsExactly("files:read");
    }

    @Test
    void a_client_cannot_request_more_than_the_assertion_granted() {
        Set<String> effective = IdJagAuthenticationProvider.intersect(
                Set.of("admin:all"), "files:read", client("admin:all", "files:read"));

        assertThat(effective).isEmpty();
    }

    @Test
    void an_assertion_cannot_grant_more_than_the_client_is_registered_for() {
        // The IdP and the resource server are different trust domains. A compromised or overly
        // generous IdP must not be able to expand a client's registration.
        Set<String> effective = IdJagAuthenticationProvider.intersect(
                Set.of(), "files:read admin:all", client("files:read"));

        assertThat(effective).containsExactly("files:read");
    }

    @Test
    void requesting_nothing_falls_back_to_what_the_assertion_granted_still_capped_by_registration() {
        Set<String> effective = IdJagAuthenticationProvider.intersect(
                Set.of(), "files:read files:list", client("files:read", "files:list", "extra"));

        assertThat(effective).containsExactlyInAnyOrder("files:read", "files:list");
    }

    @Test
    void an_assertion_with_no_scope_cannot_widen_beyond_what_was_requested_and_registered() {
        Set<String> effective = IdJagAuthenticationProvider.intersect(
                Set.of("files:read"), null, client("files:read", "admin:all"));

        assertThat(effective).containsExactly("files:read");
    }

    @Test
    void a_client_registered_for_nothing_receives_nothing() {
        assertThat(IdJagAuthenticationProvider.intersect(
                Set.of("files:read"), "files:read", client())).isEmpty();
    }
}
