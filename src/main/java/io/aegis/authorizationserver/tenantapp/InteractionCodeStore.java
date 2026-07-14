package io.aegis.authorizationserver.tenantapp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * Short-lived, single-use interaction codes for the tenant-app flows. After a user is authenticated
 * out-of-band (verified passkey assertion, or verified provider id_token), we hand the app an
 * interaction code bound to its client and PKCE {@code code_challenge}; the app then swaps it — proving
 * possession of the {@code code_verifier} — for tokens. This keeps the actual credential/assertion off
 * the token endpoint and makes the exchange safe for public (mobile/SPA) clients.
 *
 * <p>In-memory with a TTL and one-time consumption (single dev AS instance). Production moves this to
 * Redis so it survives restarts and spans instances — a documented follow-up.
 */
@Component
public class InteractionCodeStore {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Duration TTL = Duration.ofMinutes(2);

    public record Transaction(String tenant, String subject, String clientId, String codeChallenge,
                              String amr, Instant expiresAt) {
    }

    public static class InvalidInteractionException extends RuntimeException {
        public InvalidInteractionException(String message) {
            super(message);
        }
    }

    private final Map<String, Transaction> transactions = new ConcurrentHashMap<>();

    /** Bind an authenticated user to a fresh interaction code for the client's PKCE challenge. */
    public String create(String tenant, String subject, String clientId, String codeChallenge, String amr) {
        if (codeChallenge == null || codeChallenge.isBlank()) {
            throw new InvalidInteractionException("code_challenge is required");
        }
        byte[] raw = new byte[32];
        RANDOM.nextBytes(raw);
        String code = B64URL.encodeToString(raw);
        transactions.put(code, new Transaction(tenant, subject, clientId, codeChallenge, amr,
                Instant.now().plus(TTL)));
        sweep();
        return code;
    }

    /**
     * Consume a code: verify it exists, is unexpired, matches the client, and that
     * {@code S256(codeVerifier) == codeChallenge}. Removes it (single use) and returns the transaction.
     */
    public Transaction consume(String code, String clientId, String codeVerifier) {
        Transaction txn = code == null ? null : transactions.remove(code);
        if (txn == null) {
            throw new InvalidInteractionException("invalid or already-used interaction code");
        }
        if (Instant.now().isAfter(txn.expiresAt())) {
            throw new InvalidInteractionException("interaction code expired");
        }
        if (!txn.clientId().equals(clientId)) {
            throw new InvalidInteractionException("client mismatch");
        }
        if (!pkceMatches(codeVerifier, txn.codeChallenge())) {
            throw new InvalidInteractionException("PKCE verification failed");
        }
        return txn;
    }

    private static boolean pkceMatches(String codeVerifier, String codeChallenge) {
        if (codeVerifier == null || codeVerifier.isBlank()) {
            return false;
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            String computed = B64URL.encodeToString(digest);
            // Constant-time compare of the base64url challenge bytes.
            return MessageDigest.isEqual(computed.getBytes(StandardCharsets.US_ASCII),
                    codeChallenge.getBytes(StandardCharsets.US_ASCII));
        } catch (Exception ex) {
            return false;
        }
    }

    private void sweep() {
        Instant now = Instant.now();
        transactions.entrySet().removeIf(e -> now.isAfter(e.getValue().expiresAt()));
    }
}
