package io.aegis.authorizationserver;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Real backing services for AS integration tests.
 *
 * <p>Postgres holds registered clients, authorizations, consents and the durable per-tenant signing
 * keys. Redis holds the login session and interaction codes.
 *
 * <p>Redis is not optional here. Spring Session selects its store by classpath auto-detection in
 * Boot 4 (there is no {@code spring.session.store-type} any more), so with
 * {@code spring-session-data-redis} on the classpath this service always stores sessions in Redis.
 * Running the integration tests against the same store the deployment uses is the point — it is what
 * turns "sessions are shared across replicas" from a configuration claim into a tested one.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfig {

    @Bean
    @ServiceConnection
    PostgreSQLContainer<?> postgresContainer() {
        return new PostgreSQLContainer<>(DockerImageName.parse("postgres:16-alpine"))
                .withDatabaseName("aegis_authz");
    }

    @Bean
    @ServiceConnection(name = "redis")
    GenericContainer<?> redisContainer() {
        return new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
                .withExposedPorts(6379);
    }
}
