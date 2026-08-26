package io.aegis.authorizationserver.delegation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Identity Assertion JWT Authorization Grant — the token at the centre of MCP's
 * <b>Enterprise-Managed Authorization</b> extension.
 *
 * <p>The flow it enables: a user signs in once at the enterprise IdP, the client exchanges that ID
 * token for an ID-JAG (RFC 8693) — <em>and the IdP evaluates tenant policy at that moment</em> — then
 * redeems the ID-JAG at the MCP authorization server for an access token (RFC 7523). The user is
 * never redirected to the MCP server's own consent screen, and revoking access to every MCP server
 * in an estate becomes one control-plane action.
 *
 * <p>Aegis plays both roles: it issues ID-JAGs as the enterprise IdP, and redeems them as an MCP
 * authorization server.
 */
class IdJagTest {

    private static final Instant NOW = Instant.parse("2026-08-26T10:00:00Z");
    private static final String MCP_RESOURCE = "https://mcp.acme.com/files";

    private static IdJag issued() {
        return IdJag.issue("https://login.acme.com/t/acme", "user:alice@acme", "mcp-client",
                MCP_RESOURCE, "files:read", NOW, Duration.ofMinutes(5));
    }

    @Test
    void carries_the_audience_of_the_target_mcp_resource_not_the_client() {
        // RFC 8707 resource indicators: the ID-JAG is minted FOR one MCP server. An ID-JAG audienced
        // to the client would be a bearer token for anything the client could reach.
        assertThat(issued().audience()).isEqualTo(MCP_RESOURCE);
    }

    @Test
    void carries_the_subject_so_the_mcp_server_can_link_the_account() {
        assertThat(issued().subject()).isEqualTo("user:alice@acme");
    }

    @Test
    void is_short_lived() {
        assertThat(issued().expiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(5)));
    }

    @Test
    void renders_the_claim_set_an_mcp_authorization_server_expects() {
        Map<String, Object> claims = issued().toClaims();

        assertThat(claims).containsEntry("iss", "https://login.acme.com/t/acme");
        assertThat(claims).containsEntry("sub", "user:alice@acme");
        assertThat(claims).containsEntry("aud", MCP_RESOURCE);
        assertThat(claims).containsEntry("client_id", "mcp-client");
        assertThat(claims).containsEntry("scope", "files:read");
        // Distinguishes an ID-JAG from an ordinary access token with the same audience.
        assertThat(claims).containsEntry("token_type", IdJag.TOKEN_TYPE);
    }

    @Test
    void the_token_type_is_the_registered_id_jag_urn() {
        assertThat(IdJag.TOKEN_TYPE).isEqualTo("urn:ietf:params:oauth:token-type:id-jag");
    }

    // --- validation on the redeeming side -------------------------------------------------------

    @Test
    void validates_a_well_formed_grant_for_the_expected_audience() {
        assertThat(issued().validateFor(MCP_RESOURCE, NOW.plusSeconds(30)))
                .isEqualTo(IdJagValidation.VALID);
    }

    @Test
    void refuses_a_grant_minted_for_a_different_resource() {
        // The confused-deputy defence. MCP rev 2026-07-28 states servers MUST validate they are the
        // intended audience and MUST NOT accept or transit any other token.
        assertThat(issued().validateFor("https://mcp.evil.example/files", NOW.plusSeconds(30)))
                .isEqualTo(IdJagValidation.WRONG_AUDIENCE);
    }

    @Test
    void refuses_an_expired_grant() {
        assertThat(issued().validateFor(MCP_RESOURCE, NOW.plusSeconds(301)))
                .isEqualTo(IdJagValidation.EXPIRED);
    }

    @Test
    void refuses_a_grant_presented_before_it_was_issued() {
        // Clock skew in the wrong direction, or a replayed/forged iat.
        assertThat(issued().validateFor(MCP_RESOURCE, NOW.minusSeconds(60)))
                .isEqualTo(IdJagValidation.NOT_YET_VALID);
    }

    @Test
    void requires_an_issuer_subject_and_audience() {
        assertThatThrownBy(() -> IdJag.issue(null, "user:alice", "c", MCP_RESOURCE, "s", NOW, Duration.ofMinutes(5)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> IdJag.issue("iss", " ", "c", MCP_RESOURCE, "s", NOW, Duration.ofMinutes(5)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> IdJag.issue("iss", "user:alice", "c", " ", "s", NOW, Duration.ofMinutes(5)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void refuses_an_unbounded_lifetime() {
        // An ID-JAG is a bearer credential for a specific resource; "no expiry" is never correct.
        assertThatThrownBy(() -> IdJag.issue("iss", "user:alice", "c", MCP_RESOURCE, "s", NOW, Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
