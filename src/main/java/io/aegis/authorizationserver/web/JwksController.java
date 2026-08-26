package io.aegis.authorizationserver.web;

import com.nimbusds.jose.jwk.JWK;
import io.aegis.authorizationserver.auth.TenantJwkSource;
import io.aegis.authorizationserver.keys.vault.VaultTenantSigner;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Aggregate JWKS: the public keys of every issuer this AS serves (the root/default key plus each
 * per-tenant key). Resource servers fetch this single in-network URI, so a token signed with any
 * tenant's key validates without per-tenant JWKS wiring on their side — the issuer claim is still
 * checked against their allowlist (see each service's ResourceServerJwtConfig).
 *
 * <p>Per-tenant JWKS stays at {@code /{tenant}/oauth2/jwks} for external validators doing standard
 * OIDC discovery; this endpoint is the internal union. Public keys only, so exposure is harmless,
 * but it is deliberately not routed through the edge gateway.
 */
@RestController
public class JwksController {

    private final TenantJwkSource jwkSource;
    private final ObjectProvider<VaultTenantSigner> vaultSigner;

    public JwksController(TenantJwkSource jwkSource, ObjectProvider<VaultTenantSigner> vaultSigner) {
        this.jwkSource = jwkSource;
        this.vaultSigner = vaultSigner;
    }

    @GetMapping(value = "/internal/jwks", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> aggregateJwks() {
        // Ensure the default key exists even before the first root-issuer token is minted, so an
        // early-booting resource server never caches an empty key set.
        jwkSource.jwkSetFor(null);

        List<JWK> keys = new ArrayList<>(jwkSource.allKeys().getKeys());

        // Migration overlap (VAULT-ARCHITECTURE.md §7): while the cutover is in progress BOTH key
        // sets must be published — the Vault kid before it signs anything, and the old KMS kid until
        // every token it signed has expired. Publishing only one of them at a time would reject live
        // tokens on one side of the switch or the other.
        VaultTenantSigner signer = vaultSigner.getIfAvailable();
        if (signer != null) {
            for (String tenant : tenantsOf(keys)) {
                keys.addAll(signer.publicJwks(tenant));
            }
        }
        return new com.nimbusds.jose.jwk.JWKSet(keys).toJSONObject(true); // true = public keys only
    }

    /** Tenants already known from the local key set — {@code aegis-<tenant>-<suffix>}. */
    private static Set<String> tenantsOf(List<JWK> keys) {
        Set<String> tenants = new LinkedHashSet<>();
        tenants.add("default");
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
