package io.aegis.authorizationserver.session;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.authorizationserver.TestcontainersConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.test.context.ActiveProfiles;

/**
 * Proves the login session actually lands in Redis rather than in process memory.
 *
 * <p>Without this, "sessions are Redis-backed" is only a configuration claim — and that claim was
 * briefly false: adding {@code spring-session-data-redis} alone left it inert, because Boot 4 moved
 * session auto-configuration into the separate {@code spring-boot-session} module, so no
 * {@link SessionRepository} bean existed at all and the container quietly kept using a
 * process-local {@code HttpSession}. Boot 4 also removed {@code spring.session.store-type}, so
 * "configuring" the store via that property is an unnoticed no-op; the store is chosen by classpath
 * auto-detection instead. Both facts are load-bearing and neither is visible from configuration, so
 * they are asserted here rather than assumed.
 */
@SpringBootTest
@ActiveProfiles("dev")
@Import(TestcontainersConfig.class)
class RedisSessionWiringIT {

    @Autowired
    SessionRepository<? extends Session> sessionRepository;

    @Autowired
    StringRedisTemplate redisTemplate;

    @Test
    void the_active_session_repository_is_redis_backed_not_in_memory() {
        // The concrete type differs across Boot/Session versions, so assert on the package rather
        // than a class name that a minor upgrade could rename out from under this test.
        assertThat(sessionRepository.getClass().getName())
                .as("session repository must come from spring-session-data-redis")
                .contains("org.springframework.session.data.redis");
    }

    @Test
    void a_created_session_is_written_to_redis_so_any_replica_can_read_it() {
        Session session = sessionRepository.createSession();
        session.setAttribute("probe", "value");
        writeSession(session);

        // Visible in Redis itself — the property that lets another pod serve the next request.
        assertThat(redisTemplate.keys("spring:session:*")).isNotEmpty();

        Session reloaded = sessionRepository.findById(session.getId());
        assertThat(reloaded).isNotNull();
        assertThat(reloaded.<String>getAttribute("probe")).isEqualTo("value");
    }

    @Test
    void a_deleted_session_is_gone_from_redis() {
        Session session = sessionRepository.createSession();
        writeSession(session);
        String id = session.getId();

        sessionRepository.deleteById(id);

        assertThat(sessionRepository.findById(id)).isNull();
    }

    /** {@code SessionRepository} is generic in its own session type; save through a raw view. */
    @SuppressWarnings({"unchecked", "rawtypes"})
    private void writeSession(Session session) {
        ((SessionRepository) sessionRepository).save(session);
    }

    /** Also assert the interaction-code repository picked Redis, since the host is configured here. */
    @Test
    void configuring_redis_also_switches_interaction_codes_off_the_in_memory_store(
            @Autowired io.aegis.authorizationserver.tenantapp.InteractionCodeRepository repository) {
        assertThat(repository)
                .isInstanceOf(io.aegis.authorizationserver.tenantapp.RedisInteractionCodeRepository.class);
    }
}
