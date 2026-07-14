package io.aegis.authorizationserver.tenantapp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * The interaction-code exchange guard: a code is single-use, client-bound, and only redeemable by the
 * holder of the PKCE code_verifier. These are the properties that make the token swap safe for public
 * (mobile/SPA) clients.
 */
class InteractionCodeStoreTest {

    private final InteractionCodeStore store = new InteractionCodeStore();

    private static String challenge(String verifier) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    @Test
    void a_code_is_redeemable_once_with_the_matching_verifier() throws Exception {
        String verifier = "a-long-random-code-verifier-value-1234567890";
        String code = store.create("acme", "alice", "acme-app", challenge(verifier), "webauthn");

        InteractionCodeStore.Transaction txn = store.consume(code, "acme-app", verifier);
        assertThat(txn.tenant()).isEqualTo("acme");
        assertThat(txn.subject()).isEqualTo("alice");
        assertThat(txn.amr()).isEqualTo("webauthn");

        // Single use: a second redemption fails.
        assertThatThrownBy(() -> store.consume(code, "acme-app", verifier))
                .isInstanceOf(InteractionCodeStore.InvalidInteractionException.class);
    }

    @Test
    void a_wrong_verifier_is_rejected() throws Exception {
        String code = store.create("acme", "alice", "acme-app", challenge("the-real-verifier-aaaaaaaaaaaaaaaaaa"), "webauthn");
        assertThatThrownBy(() -> store.consume(code, "acme-app", "a-different-verifier-bbbbbbbbbbbbbbbbbb"))
                .isInstanceOf(InteractionCodeStore.InvalidInteractionException.class);
    }

    @Test
    void a_code_cannot_be_redeemed_by_a_different_client() throws Exception {
        String verifier = "verifier-cccccccccccccccccccccccccccccccc";
        String code = store.create("acme", "alice", "acme-app", challenge(verifier), "social");
        assertThatThrownBy(() -> store.consume(code, "someone-elses-app", verifier))
                .isInstanceOf(InteractionCodeStore.InvalidInteractionException.class);
    }

    @Test
    void an_unknown_code_is_rejected() {
        assertThatThrownBy(() -> store.consume("nope", "acme-app", "whatever"))
                .isInstanceOf(InteractionCodeStore.InvalidInteractionException.class);
    }

    @Test
    void a_missing_challenge_is_rejected_at_creation() {
        assertThatThrownBy(() -> store.create("acme", "alice", "acme-app", "  ", "webauthn"))
                .isInstanceOf(InteractionCodeStore.InvalidInteractionException.class);
    }
}
