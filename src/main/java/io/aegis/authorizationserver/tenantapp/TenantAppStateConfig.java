package io.aegis.authorizationserver.tenantapp;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.StringRedisTemplate;

/**
 * Keeps short-lived interaction codes in Redis, so a code created on one replica can be redeemed on
 * another and a restart does not strand in-flight logins.
 *
 * <p><strong>Deliberately unconditional</strong>, for the same reason as
 * {@code session.RedisSessionConfig}: a silent in-memory fallback turns a missing Redis into an
 * intermittent, hard-to-diagnose failure that only appears once a second replica exists. This
 * service is not correct without Redis, so it should refuse to run without one rather than pretend.
 *
 * <p>Note that gating this on {@code spring.data.redis.host} would also have been subtly wrong:
 * Testcontainers' {@code @ServiceConnection} supplies a {@code RedisConnectionDetails} bean rather
 * than setting that property, so a property-based condition evaluates false in integration tests
 * and they would have silently exercised the in-memory path while claiming to cover Redis.
 *
 * <p>{@link InMemoryInteractionCodeRepository} still exists for unit tests, which use
 * {@code new InteractionCodeStore()} and never start a Spring context.
 */
@Configuration(proxyBeanMethods = false)
public class TenantAppStateConfig {

    @Bean
    public InteractionCodeRepository interactionCodeRepository(StringRedisTemplate redis) {
        return new RedisInteractionCodeRepository(redis);
    }

    @Bean
    public InteractionCodeStore interactionCodeStore(InteractionCodeRepository repository) {
        return new InteractionCodeStore(repository);
    }
}
