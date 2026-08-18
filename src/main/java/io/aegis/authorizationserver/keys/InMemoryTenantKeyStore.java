package io.aegis.authorizationserver.keys;

import com.nimbusds.jose.jwk.RSAKey;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Ephemeral, process-local key store — the original behaviour, kept deliberately.
 *
 * <p>This is the right implementation for unit tests (no database) and for a single-process local
 * run. It is the <em>wrong</em> implementation for any multi-replica deployment, because each
 * replica would mint a different key per tenant; {@code JpaTenantKeyStore} is selected automatically
 * whenever the persistence layer is available, so a real deployment never silently lands here.
 */
public class InMemoryTenantKeyStore implements TenantKeyStore {

    private final Map<String, RSAKey> keys = new ConcurrentHashMap<>();

    @Override
    public Optional<RSAKey> findActive(String tenant) {
        return Optional.ofNullable(keys.get(tenant));
    }

    @Override
    public RSAKey saveIfAbsent(String tenant, RSAKey generated) {
        // putIfAbsent gives the same "first writer wins, everyone uses the winner" semantics the
        // JPA store gets from its unique constraint.
        RSAKey existing = keys.putIfAbsent(tenant, generated);
        return existing != null ? existing : generated;
    }

    @Override
    public List<RSAKey> findAllActive() {
        return List.copyOf(keys.values());
    }
}
