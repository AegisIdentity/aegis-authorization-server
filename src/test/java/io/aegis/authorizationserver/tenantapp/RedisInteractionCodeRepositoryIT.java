package io.aegis.authorizationserver.tenantapp;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Interaction codes against a real Redis. These are the properties that let the authorization-server
 * run more than one replica: a code created on one pod must be redeemable on another, and redeemable
 * exactly once even when pods race.
 */
class RedisInteractionCodeRepositoryIT {

    @SuppressWarnings("resource")
    private static final GenericContainer<?> REDIS =
            new GenericContainer<>(DockerImageName.parse("redis:7-alpine")).withExposedPorts(6379);

    private static LettuceConnectionFactory connectionFactory;
    private static StringRedisTemplate template;

    @BeforeAll
    static void startRedis() {
        REDIS.start();
        connectionFactory = new LettuceConnectionFactory(
                new RedisStandaloneConfiguration(REDIS.getHost(), REDIS.getMappedPort(6379)));
        connectionFactory.afterPropertiesSet();
        template = new StringRedisTemplate(connectionFactory);
        template.afterPropertiesSet();
    }

    @AfterAll
    static void stopRedis() {
        if (connectionFactory != null) {
            connectionFactory.destroy();
        }
        REDIS.stop();
    }

    private static InteractionCodeStore.Transaction txn(String challenge) {
        return new InteractionCodeStore.Transaction(
                "acme", "alice", "acme-app", challenge, "webauthn", Instant.now().plusSeconds(120));
    }

    private static String challenge(String verifier) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    /** The cross-replica property: pod A creates, pod B redeems. */
    @Test
    void a_code_created_by_one_replica_is_redeemable_by_another() throws Exception {
        String verifier = "a-long-random-code-verifier-value-1234567890";
        InteractionCodeStore podA = new InteractionCodeStore(new RedisInteractionCodeRepository(template));
        InteractionCodeStore podB = new InteractionCodeStore(new RedisInteractionCodeRepository(template));

        String code = podA.create("acme", "alice", "acme-app", challenge(verifier), "webauthn");
        InteractionCodeStore.Transaction redeemed = podB.consume(code, "acme-app", verifier);

        assertThat(redeemed.subject()).isEqualTo("alice");
        assertThat(redeemed.tenant()).isEqualTo("acme");
    }

    /**
     * The atomicity property. Many replicas redeem the same code simultaneously; exactly one may
     * succeed. A get-then-delete implementation lets several callers observe the transaction before
     * any of them removes it, so one authentication yields several token sets — this test is the
     * reason the repository uses GETDEL.
     */
    @Test
    void concurrent_redemption_of_one_code_succeeds_exactly_once() throws Exception {
        RedisInteractionCodeRepository repository = new RedisInteractionCodeRepository(template);
        String code = "race-" + java.util.UUID.randomUUID();
        repository.save(code, txn("challenge"), Duration.ofMinutes(2));

        int contenders = 16;
        ExecutorService pool = Executors.newFixedThreadPool(contenders);
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger winners = new AtomicInteger();

        try {
            List<Callable<Void>> tasks = new java.util.ArrayList<>();
            for (int i = 0; i < contenders; i++) {
                tasks.add(() -> {
                    go.await();
                    if (repository.consume(code).isPresent()) {
                        winners.incrementAndGet();
                    }
                    return null;
                });
            }
            List<Future<Void>> futures = new java.util.ArrayList<>();
            for (Callable<Void> task : tasks) {
                futures.add(pool.submit(task));
            }
            go.countDown();
            pool.shutdown();
            assertThat(pool.awaitTermination(30, TimeUnit.SECONDS)).isTrue();
            for (Future<Void> f : futures) {
                f.get();
            }
        } finally {
            pool.shutdownNow();
        }

        assertThat(winners.get()).isEqualTo(1);
    }

    /** Redis expires the key itself, so abandoned ceremonies cannot accumulate. */
    @Test
    void an_expired_code_is_removed_by_redis_without_a_sweep() {
        RedisInteractionCodeRepository repository = new RedisInteractionCodeRepository(template);
        String code = "ttl-" + java.util.UUID.randomUUID();
        repository.save(code, txn("challenge"), Duration.ofMillis(250));

        org.awaitility.Awaitility.await().atMost(Duration.ofSeconds(5))
                .until(() -> repository.consume(code).isEmpty());

        assertThat(template.hasKey(RedisInteractionCodeRepository.KEY_PREFIX + code)).isFalse();
    }

    /**
     * Deserialises a HAND-WRITTEN payload rather than one this class just serialised.
     *
     * <p>A round-trip test through the same class in the same JVM passes even when the mapping is
     * wrong, because it only proves write and read agree with each other. During a rolling deploy an
     * old pod's entry is read by a new pod, so what actually matters is that a literal on-the-wire
     * document parses to the right fields — which is what this asserts, and it is the only test here
     * that would catch a broken record-binding annotation.
     */
    @Test
    void a_hand_written_stored_payload_deserialises_to_the_right_fields() {
        RedisInteractionCodeRepository repository = new RedisInteractionCodeRepository(template);
        String code = "wire-" + java.util.UUID.randomUUID();
        String json = """
                {"tenant":"acme","subject":"alice","clientId":"acme-app",\
                "codeChallenge":"abc123","amr":"webauthn","expiresAt":"2099-01-01T00:00:00Z"}""";
        template.opsForValue().set(RedisInteractionCodeRepository.KEY_PREFIX + code, json);

        InteractionCodeStore.Transaction parsed = repository.consume(code).orElseThrow();

        assertThat(parsed.tenant()).isEqualTo("acme");
        assertThat(parsed.subject()).isEqualTo("alice");
        assertThat(parsed.clientId()).isEqualTo("acme-app");
        assertThat(parsed.codeChallenge()).isEqualTo("abc123");
        assertThat(parsed.amr()).isEqualTo("webauthn");
        assertThat(parsed.expiresAt()).isEqualTo(Instant.parse("2099-01-01T00:00:00Z"));
    }

    @Test
    void an_unknown_code_yields_empty_rather_than_an_error() {
        RedisInteractionCodeRepository repository = new RedisInteractionCodeRepository(template);

        Optional<InteractionCodeStore.Transaction> result = repository.consume("never-issued");

        assertThat(result).isEmpty();
    }

    /** A corrupt entry must fail closed rather than produce a half-populated transaction. */
    @Test
    void a_corrupt_entry_is_discarded_rather_than_partially_parsed() {
        RedisInteractionCodeRepository repository = new RedisInteractionCodeRepository(template);
        String code = "corrupt-" + java.util.UUID.randomUUID();
        template.opsForValue().set(RedisInteractionCodeRepository.KEY_PREFIX + code, "{not-json");

        assertThat(repository.consume(code)).isEmpty();
    }

    /** All the store's validation rules still hold over the Redis repository, not just in memory. */
    @Test
    void the_stores_pkce_and_client_binding_rules_hold_over_redis() throws Exception {
        String verifier = "a-long-random-code-verifier-value-1234567890";
        InteractionCodeStore store = new InteractionCodeStore(new RedisInteractionCodeRepository(template));

        String wrongVerifierCode = store.create("acme", "alice", "acme-app", challenge(verifier), "webauthn");
        org.assertj.core.api.Assertions
                .assertThatThrownBy(() -> store.consume(wrongVerifierCode, "acme-app", "wrong-verifier"))
                .isInstanceOf(InteractionCodeStore.InvalidInteractionException.class);

        String wrongClientCode = store.create("acme", "alice", "acme-app", challenge(verifier), "webauthn");
        org.assertj.core.api.Assertions
                .assertThatThrownBy(() -> store.consume(wrongClientCode, "someone-elses-app", verifier))
                .isInstanceOf(InteractionCodeStore.InvalidInteractionException.class);
    }
}
