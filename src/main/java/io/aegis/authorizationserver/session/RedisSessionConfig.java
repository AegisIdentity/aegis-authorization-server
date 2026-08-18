package io.aegis.authorizationserver.session;

import org.springframework.context.annotation.Configuration;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

/**
 * Stores the interactive login session in Redis so any replica can serve any request.
 *
 * <p><strong>This annotation is load-bearing and has no configuration-property equivalent.</strong>
 * Spring Boot 4 removed {@code spring.session.store-type} and ships <em>no</em> auto-configuration
 * that selects a session store: {@code spring-boot-session} contributes only the session filter,
 * cookie serializer and {@code SessionProperties}, and {@code spring-boot-data-redis} contributes no
 * session support at all. Putting {@code spring-session-data-redis} on the classpath therefore does
 * nothing on its own — the container silently keeps using a process-local {@code HttpSession}, which
 * is exactly the defect this service needed to fix. The store must be opted into explicitly, here.
 *
 * <p><strong>Deliberately unconditional.</strong> An earlier version gated this on Redis being
 * configured and fell back to an in-memory session. That is the wrong default for this service: it
 * turns a missing Redis into a silent correctness bug that only shows up as intermittent broken
 * logins once a second replica exists. Requiring Redis makes the failure loud and immediate at
 * startup instead. Every integration test supplies one (see {@code TestcontainersConfig}), so tests
 * exercise the same store as production.
 *
 * <p>Uses {@code RedisSessionRepository} (not the <em>indexed</em> variant): indexed sessions add
 * principal-name lookup and expiry events at the cost of requiring Redis keyspace notifications.
 * Nothing here needs either, and enabling keyspace notifications on a managed cache is an operator
 * action that would otherwise become a hidden deployment prerequisite.
 */
@Configuration(proxyBeanMethods = false)
@EnableRedisHttpSession(maxInactiveIntervalInSeconds = 1800) // 30m — mirrors spring.session.timeout
public class RedisSessionConfig {
}
