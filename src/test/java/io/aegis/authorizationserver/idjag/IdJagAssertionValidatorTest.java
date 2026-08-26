package io.aegis.authorizationserver.idjag;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Validation of an Identity Assertion JWT Authorization Grant on the <b>redeeming</b> side.
 *
 * <p>This is the second half of MCP Enterprise-Managed Authorization: the client already exchanged
 * its ID token for an ID-JAG at the enterprise IdP (where tenant policy was evaluated), and now
 * presents it here to obtain an MCP access token. Signature verification happens before this — a
 * {@code JwtDecoder} does it — so what remains is everything a valid signature does <em>not</em>
 * prove.
 */
class IdJagAssertionValidatorTest {

    private static final Instant NOW = Instant.parse("2026-08-26T10:00:00Z");
    private static final String RESOURCE = "https://mcp.acme.com/files";

    private final IdJagAssertionValidator validator =
            new IdJagAssertionValidator(Set.of("https://login.acme.com/acme", "https://login.acme.com"));

    private static Jwt.Builder assertionBuilder() {
        return Jwt.withTokenValue("assertion")
                .header("alg", "RS256")
                .claim("iss", "https://login.acme.com/acme")
                .claim("sub", "user:alice@acme")
                .claim("aud", List.of(RESOURCE))
                .claim("client_id", "mcp-client")
                .claim("scope", "files:read")
                .claim("token_type", "urn:ietf:params:oauth:token-type:id-jag")
                .issuedAt(NOW)
                .expiresAt(NOW.plusSeconds(300));
    }

    @Test
    void a_well_formed_assertion_for_this_resource_is_valid() {
        assertThat(validator.validate(assertionBuilder().build(), RESOURCE, NOW.plusSeconds(30)))
                .isEqualTo(IdJagValidationResult.VALID);
    }

    // --- audience: the confused-deputy defence -----------------------------------------------------

    @Test
    void an_assertion_minted_for_a_different_resource_is_refused() {
        // MCP rev 2026-07-28 requires a server to confirm it is the intended audience and forbids
        // accepting or transiting any other token. An MCP server is unusually exposed here because
        // it acts as BOTH a resource server and a client to its own downstream dependencies.
        assertThat(validator.validate(assertionBuilder().build(),
                "https://mcp.evil.example/files", NOW.plusSeconds(30)))
                .isEqualTo(IdJagValidationResult.WRONG_AUDIENCE);
    }

    @Test
    void an_assertion_with_no_audience_is_refused() {
        Jwt noAudience = assertionBuilder().claim("aud", List.of()).build();
        assertThat(validator.validate(noAudience, RESOURCE, NOW.plusSeconds(30)))
                .isEqualTo(IdJagValidationResult.WRONG_AUDIENCE);
    }

    @Test
    void a_multi_audience_assertion_is_valid_only_if_this_resource_is_among_them() {
        Jwt multi = assertionBuilder()
                .claim("aud", List.of("https://other.example", RESOURCE)).build();
        assertThat(validator.validate(multi, RESOURCE, NOW.plusSeconds(30)))
                .isEqualTo(IdJagValidationResult.VALID);
    }

    // --- issuer -------------------------------------------------------------------------------------

    @Test
    void an_assertion_from_an_unknown_issuer_is_refused() {
        // A valid signature only proves SOMEONE signed it. Without an issuer allow-list, any IdP
        // whose key we happen to be able to fetch could mint grants for our resources.
        Jwt foreign = assertionBuilder().claim("iss", "https://idp.evil.example").build();
        assertThat(validator.validate(foreign, RESOURCE, NOW.plusSeconds(30)))
                .isEqualTo(IdJagValidationResult.UNTRUSTED_ISSUER);
    }

    @Test
    void an_assertion_with_no_issuer_is_refused() {
        Jwt noIssuer = Jwt.withTokenValue("a").header("alg", "RS256")
                .claim("sub", "user:alice@acme").claim("aud", List.of(RESOURCE))
                .claim("token_type", "urn:ietf:params:oauth:token-type:id-jag")
                .issuedAt(NOW).expiresAt(NOW.plusSeconds(300)).build();
        assertThat(validator.validate(noIssuer, RESOURCE, NOW.plusSeconds(30)))
                .isEqualTo(IdJagValidationResult.UNTRUSTED_ISSUER);
    }

    // --- token type --------------------------------------------------------------------------------

    @Test
    void an_ordinary_access_token_cannot_be_replayed_as_an_ID_JAG() {
        // Without this check, any access token audienced to the MCP resource could be presented at
        // the token endpoint and swapped for a fresh one — a token-laundering primitive.
        Jwt accessToken = assertionBuilder().claim("token_type", null).build();
        assertThat(validator.validate(accessToken, RESOURCE, NOW.plusSeconds(30)))
                .isEqualTo(IdJagValidationResult.NOT_AN_ID_JAG);
    }

    @Test
    void a_token_of_some_other_type_is_refused() {
        Jwt refresh = assertionBuilder()
                .claim("token_type", "urn:ietf:params:oauth:token-type:refresh_token").build();
        assertThat(validator.validate(refresh, RESOURCE, NOW.plusSeconds(30)))
                .isEqualTo(IdJagValidationResult.NOT_AN_ID_JAG);
    }

    // --- lifetime ----------------------------------------------------------------------------------

    @Test
    void an_expired_assertion_is_refused() {
        assertThat(validator.validate(assertionBuilder().build(), RESOURCE, NOW.plusSeconds(301)))
                .isEqualTo(IdJagValidationResult.EXPIRED);
    }

    @Test
    void an_assertion_presented_before_it_was_issued_is_refused() {
        assertThat(validator.validate(assertionBuilder().build(), RESOURCE, NOW.minusSeconds(60)))
                .isEqualTo(IdJagValidationResult.NOT_YET_VALID);
    }

    @Test
    void an_assertion_with_no_expiry_is_refused() {
        // A bearer credential for a specific resource with no expiry is never correct, and treating
        // a missing exp as "never expires" is how one becomes a permanent key.
        Jwt noExpiry = Jwt.withTokenValue("a").header("alg", "RS256")
                .claim("iss", "https://login.acme.com/acme")
                .claim("sub", "user:alice@acme").claim("aud", List.of(RESOURCE))
                .claim("token_type", "urn:ietf:params:oauth:token-type:id-jag")
                .issuedAt(NOW).build();
        assertThat(validator.validate(noExpiry, RESOURCE, NOW.plusSeconds(30)))
                .isEqualTo(IdJagValidationResult.EXPIRED);
    }

    // --- subject -----------------------------------------------------------------------------------

    @Test
    void an_assertion_with_no_subject_is_refused() {
        // The subject is what the MCP server links to a local account. Without it the grant is
        // anonymous authority, which is the opposite of what enterprise-managed auth is for.
        Jwt noSubject = assertionBuilder().claim("sub", null).build();
        assertThat(validator.validate(noSubject, RESOURCE, NOW.plusSeconds(30)))
                .isEqualTo(IdJagValidationResult.NO_SUBJECT);
    }

    @Test
    void an_empty_issuer_allow_list_trusts_nothing() {
        IdJagAssertionValidator closed = new IdJagAssertionValidator(Set.of());
        assertThat(closed.validate(assertionBuilder().build(), RESOURCE, NOW.plusSeconds(30)))
                .isEqualTo(IdJagValidationResult.UNTRUSTED_ISSUER);
    }
}
