package io.aegis.authorizationserver.web;

import io.aegis.authorizationserver.auth.TenantJwkSource;
import java.util.Map;
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

    public JwksController(TenantJwkSource jwkSource) {
        this.jwkSource = jwkSource;
    }

    @GetMapping(value = "/internal/jwks", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> aggregateJwks() {
        // Ensure the default key exists even before the first root-issuer token is minted, so an
        // early-booting resource server never caches an empty key set.
        jwkSource.jwkSetFor(null);
        return jwkSource.allKeys().toJSONObject(true); // true = public keys only
    }
}
