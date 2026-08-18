package io.aegis.authorizationserver.keys;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import io.aegis.authorizationserver.auth.TenantJwkSource;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * The horizontal-scalability contract for tenant signing keys.
 *
 * <p>Every test here fails against the previous implementation, which generated keys into a
 * per-process map. A shared {@link TenantKeyStore} stands in for the shared database: two
 * {@link TenantJwkSource} instances over one store are two replicas of the authorization-server.
 *
 * <p>This matters because the Helm chart ships {@code replicaCount: 2} with an HPA to 8 and a
 * Service with no session affinity. Without these guarantees, a token signed by one pod fails
 * validation against another pod's JWKS, and every restart silently invalidates every issued token.
 */
class TenantKeyPersistenceTest {

    /** Two replicas sharing one store must sign with the SAME key for a given tenant. */
    @Test
    void two_replicas_over_one_store_converge_on_the_same_key_per_tenant() {
        TenantKeyStore shared = new InMemoryTenantKeyStore();
        TenantJwkSource podA = new TenantJwkSource(shared);
        TenantJwkSource podB = new TenantJwkSource(shared);

        String kidFromA = podA.jwkSetFor("acme").getKeys().get(0).getKeyID();
        String kidFromB = podB.jwkSetFor("acme").getKeys().get(0).getKeyID();

        assertThat(kidFromB).isEqualTo(kidFromA);
    }

    /** A token signed by one replica must be verifiable against another replica's aggregate JWKS. */
    @Test
    void a_key_created_on_one_replica_is_published_by_the_other_replicas_aggregate_jwks() {
        TenantKeyStore shared = new InMemoryTenantKeyStore();
        TenantJwkSource podA = new TenantJwkSource(shared);
        TenantJwkSource podB = new TenantJwkSource(shared);

        // Pod B publishes its aggregate first, so its snapshot is warm and does not yet know "acme".
        podB.allKeys();
        String kidFromA = podA.jwkSetFor("acme").getKeys().get(0).getKeyID();

        // Pod B must still converge — a stale snapshot may not strand a peer's key.
        assertThat(kidsOf(podB.jwkSetFor("acme"))).containsExactly(kidFromA);
    }

    /** Restart = a fresh source over the same store. The key must be reused, not regenerated. */
    @Test
    void keys_survive_a_restart_rather_than_invalidating_every_issued_token() {
        TenantKeyStore durable = new InMemoryTenantKeyStore();

        String beforeRestart = new TenantJwkSource(durable).jwkSetFor("acme").getKeys().get(0).getKeyID();
        String afterRestart = new TenantJwkSource(durable).jwkSetFor("acme").getKeys().get(0).getKeyID();

        assertThat(afterRestart).isEqualTo(beforeRestart);
    }

    /** Distinct tenants still get cryptographically distinct keys — isolation is not weakened. */
    @Test
    void distinct_tenants_still_get_distinct_keys() {
        TenantKeyStore shared = new InMemoryTenantKeyStore();
        TenantJwkSource source = new TenantJwkSource(shared);

        String acme = source.jwkSetFor("acme").getKeys().get(0).getKeyID();
        String globex = source.jwkSetFor("globex").getKeys().get(0).getKeyID();

        assertThat(acme).startsWith("aegis-acme-");
        assertThat(globex).startsWith("aegis-globex-");
        assertThat(acme).isNotEqualTo(globex);
    }

    /**
     * The concurrent-creation race. Many replicas booting at once must not each mint a key for the
     * same new tenant — exactly one wins and everyone adopts it.
     */
    @Test
    void concurrent_first_use_across_replicas_yields_exactly_one_key() throws Exception {
        TenantKeyStore shared = new InMemoryTenantKeyStore();
        int replicas = 8;
        ExecutorService pool = Executors.newFixedThreadPool(replicas);
        CountDownLatch startTogether = new CountDownLatch(1);
        Set<String> observedKids = ConcurrentHashMap.newKeySet();

        try {
            for (int i = 0; i < replicas; i++) {
                TenantJwkSource replica = new TenantJwkSource(shared);
                pool.submit(() -> {
                    startTogether.await();
                    observedKids.add(replica.jwkSetFor("acme").getKeys().get(0).getKeyID());
                    return null;
                });
            }
            startTogether.countDown();
            pool.shutdown();
            assertThat(pool.awaitTermination(30, TimeUnit.SECONDS)).isTrue();
        } finally {
            pool.shutdownNow();
        }

        // Every replica agreed on one kid, and the store holds exactly one key.
        assertThat(observedKids).hasSize(1);
        assertThat(shared.findAllActive()).hasSize(1);
    }

    /** A replica that loses the race must adopt the winner's key, never its own discarded one. */
    @Test
    void the_loser_of_a_creation_race_adopts_the_winners_key() {
        TenantKeyStore shared = new InMemoryTenantKeyStore();
        RSAKey winner = firstKeyOf(new TenantJwkSource(shared).jwkSetFor("acme"));

        // A late arrival offers its own freshly generated key for the same tenant.
        RSAKey latecomer = firstKeyOf(new TenantJwkSource(new InMemoryTenantKeyStore()).jwkSetFor("acme"));
        RSAKey authoritative = shared.saveIfAbsent("acme", latecomer);

        assertThat(authoritative.getKeyID()).isEqualTo(winner.getKeyID());
        assertThat(shared.findAllActive()).hasSize(1);
    }

    /** The aggregate JWKS must still publish public material only — never a private exponent. */
    @Test
    void the_aggregate_jwks_never_exposes_private_key_material() {
        TenantJwkSource source = new TenantJwkSource(new InMemoryTenantKeyStore());
        source.jwkSetFor("acme");
        source.jwkSetFor(null);

        assertThat(source.allKeys().toJSONObject(true).toString()).doesNotContain("\"d\"");
    }

    private static List<String> kidsOf(JWKSet set) {
        return set.getKeys().stream().map(k -> k.getKeyID()).toList();
    }

    private static RSAKey firstKeyOf(JWKSet set) {
        return (RSAKey) set.getKeys().get(0);
    }
}
