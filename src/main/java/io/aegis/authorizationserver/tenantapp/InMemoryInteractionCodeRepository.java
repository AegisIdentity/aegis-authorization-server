package io.aegis.authorizationserver.tenantapp;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Process-local interaction codes — correct for unit tests and a single-instance local run, wrong
 * for a multi-replica deployment (a code created on one pod is invisible to the others, so the token
 * exchange fails whenever the two requests land on different pods).
 * {@code RedisInteractionCodeRepository} is selected automatically when Redis is configured.
 *
 * <p>{@link ConcurrentHashMap#remove} provides the required atomic take.
 */
public class InMemoryInteractionCodeRepository implements InteractionCodeRepository {

    private record Entry(InteractionCodeStore.Transaction transaction, Instant expiresAt) {
    }

    private final Map<String, Entry> entries = new ConcurrentHashMap<>();

    @Override
    public void save(String code, InteractionCodeStore.Transaction transaction, Duration ttl) {
        entries.put(code, new Entry(transaction, Instant.now().plus(ttl)));
        sweep();
    }

    @Override
    public Optional<InteractionCodeStore.Transaction> consume(String code) {
        if (code == null) {
            return Optional.empty();
        }
        // Atomic: exactly one concurrent caller can receive a non-null entry.
        Entry entry = entries.remove(code);
        if (entry == null) {
            return Optional.empty();
        }
        if (Instant.now().isAfter(entry.expiresAt())) {
            return Optional.empty(); // already removed above; expired codes are simply gone
        }
        return Optional.of(entry.transaction());
    }

    /** Redis expires keys for us; in memory we drop stale entries opportunistically. */
    private void sweep() {
        Instant now = Instant.now();
        entries.entrySet().removeIf(e -> now.isAfter(e.getValue().expiresAt()));
    }
}
