package io.aegis.authorizationserver.keys.vault;

import com.nimbusds.jose.jwk.JWK;
import io.aegis.authorizationserver.auth.TenantJwkSource;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.springframework.beans.factory.ObjectProvider;

/**
 * Every public key this authorization server can currently verify against — the union of the local
 * key store and, when Vault signing is enabled, Vault Transit.
 *
 * <p><b>Why this exists as one component rather than two call sites.</b> The published JWKS and the
 * AS's own {@code JwtDecoder} must agree. When they drifted, the AS published a Vault key that
 * downstream services happily used, then rejected tokens signed with that very key at its own
 * {@code /userinfo} — verifying its own signature against a key set that no longer contained the
 * signing key. Deriving both from this single source makes that divergence impossible rather than
 * merely unlikely.
 *
 * <p>During the ADR-0015 §7 migration <em>both</em> sets must be present: the Vault key so newly
 * minted tokens verify, and the legacy key until every token it signed has expired.
 */
public class AggregateVerificationKeys {

    private static final String DEFAULT_TENANT = "default";

    private final TenantJwkSource localKeys;
    private final ObjectProvider<VaultTenantSigner> vaultSigner;

    public AggregateVerificationKeys(TenantJwkSource localKeys,
                                     ObjectProvider<VaultTenantSigner> vaultSigner) {
        this.localKeys = localKeys;
        this.vaultSigner = vaultSigner;
    }

    /** Public keys only. Safe to publish and safe to verify against. */
    public List<JWK> all() {
        // Ensures the default key exists before the first root-issuer token is minted, so an
        // early-booting resource server never caches an empty key set.
        localKeys.jwkSetFor(null);

        List<JWK> keys = new ArrayList<>(localKeys.allKeys().getKeys());

        VaultTenantSigner signer = vaultSigner.getIfAvailable();
        if (signer != null) {
            for (String tenant : tenantsOf(keys)) {
                keys.addAll(signer.publicJwks(tenant));
            }
        }
        return keys;
    }

    /** Tenants known from the local key set — {@code aegis-<tenant>-<suffix>} — plus the default. */
    private static Set<String> tenantsOf(List<JWK> keys) {
        Set<String> tenants = new LinkedHashSet<>();
        tenants.add(DEFAULT_TENANT);
        for (JWK key : keys) {
            String kid = key.getKeyID();
            if (kid != null && kid.startsWith("aegis-")) {
                int lastDash = kid.lastIndexOf('-');
                if (lastDash > "aegis-".length()) {
                    tenants.add(kid.substring("aegis-".length(), lastDash));
                }
            }
        }
        return tenants;
    }
}
