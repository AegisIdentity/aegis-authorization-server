package io.aegis.authorizationserver.tenantapp;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * Redis-backed interaction codes, so a code created on one authorization-server replica can be
 * redeemed on another and survives a restart.
 *
 * <p><strong>Single-use is enforced by {@code GETDEL}</strong> (via
 * {@code opsForValue().getAndDelete}), a single atomic Redis command that returns the value and
 * removes it in one step. That is the whole reason this class exists rather than a
 * {@code get(...)} followed by {@code delete(...)}: with two replicas racing on the same code, the
 * non-atomic pair would let both callers read the transaction before either deleted it, and one
 * authentication would mint two independent token sets. With {@code GETDEL}, exactly one caller
 * receives a value.
 *
 * <p>Expiry is delegated to Redis (per-key TTL), so an abandoned ceremony cannot accumulate — the
 * storage-exhaustion problem the in-memory version had to sweep for.
 */
public class RedisInteractionCodeRepository implements InteractionCodeRepository {

    private static final Logger log = LoggerFactory.getLogger(RedisInteractionCodeRepository.class);

    /**
     * Key prefix. Interaction codes are 256-bit random values, so the key itself is unguessable;
     * the prefix exists for operational clarity, not secrecy.
     */
    static final String KEY_PREFIX = "aegis:interaction:";

    private final StringRedisTemplate redis;
    private final ObjectMapper mapper;

    public RedisInteractionCodeRepository(StringRedisTemplate redis) {
        this.redis = redis;
        this.mapper = new ObjectMapper().registerModule(new JavaTimeModule());
    }

    /**
     * Wire form. Kept separate from {@link InteractionCodeStore.Transaction} so the persisted shape
     * is an explicit, stable contract: a field added to the domain record cannot silently change
     * what is already stored in Redis during a rolling deploy.
     */
    record StoredTransaction(
            @JsonProperty("tenant") String tenant,
            @JsonProperty("subject") String subject,
            @JsonProperty("clientId") String clientId,
            @JsonProperty("codeChallenge") String codeChallenge,
            @JsonProperty("amr") String amr,
            @JsonProperty("expiresAt") String expiresAt) {

        static StoredTransaction from(InteractionCodeStore.Transaction t) {
            return new StoredTransaction(t.tenant(), t.subject(), t.clientId(), t.codeChallenge(),
                    t.amr(), t.expiresAt().toString());
        }

        InteractionCodeStore.Transaction toDomain() {
            return new InteractionCodeStore.Transaction(tenant, subject, clientId, codeChallenge, amr,
                    Instant.parse(expiresAt));
        }
    }

    @Override
    public void save(String code, InteractionCodeStore.Transaction transaction, Duration ttl) {
        try {
            String json = mapper.writeValueAsString(StoredTransaction.from(transaction));
            redis.opsForValue().set(KEY_PREFIX + code, json, ttl);
        } catch (Exception e) {
            // Do not leak the code or the subject into the message.
            throw new IllegalStateException("unable to store interaction code", e);
        }
    }

    @Override
    public Optional<InteractionCodeStore.Transaction> consume(String code) {
        if (code == null || code.isBlank()) {
            return Optional.empty();
        }
        // GETDEL — atomic take. See the class javadoc for why this must not be get-then-delete.
        String json = redis.opsForValue().getAndDelete(KEY_PREFIX + code);
        if (json == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(mapper.readValue(json, StoredTransaction.class).toDomain());
        } catch (Exception e) {
            // A corrupt entry must fail closed, not fall through to a partially-populated transaction.
            log.warn("discarding an unreadable interaction-code entry");
            return Optional.empty();
        }
    }
}
