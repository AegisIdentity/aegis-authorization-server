package io.aegis.authorizationserver.tenantapp;

import java.time.Duration;
import java.util.Optional;

/**
 * Storage for in-flight interaction codes.
 *
 * <p>Extracted so the code can live in Redis and therefore span replicas and survive restarts. The
 * validation rules (expiry, client binding, PKCE) stay in {@link InteractionCodeStore} — this
 * interface is only about where the transaction is kept.
 *
 * <p><strong>{@link #consume} must be atomic.</strong> An interaction code is a bearer credential
 * that is exchanged for tokens, so it has to be redeemable exactly once even when two requests
 * arrive concurrently on different replicas. A non-atomic read-then-delete would let both callers
 * observe the transaction before either removed it, and a single authentication would yield two
 * independent token sets. Implementations must therefore use a genuine atomic take
 * (Redis {@code GETDEL}, {@code ConcurrentHashMap#remove}), never {@code get} followed by
 * {@code delete}.
 */
public interface InteractionCodeRepository {

    /** Store a transaction under {@code code}, expiring automatically after {@code ttl}. */
    void save(String code, InteractionCodeStore.Transaction transaction, Duration ttl);

    /**
     * Atomically fetch and remove the transaction for {@code code}.
     *
     * @return the transaction if this caller was the one that removed it; empty if the code was
     *         unknown, already redeemed, or expired.
     */
    Optional<InteractionCodeStore.Transaction> consume(String code);
}
