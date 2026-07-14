package io.aegis.authorizationserver.auth;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.stereotype.Component;

/**
 * Tenant-aware signing keys. Each tenant (resolved from the per-request issuer, i.e. the
 * {@code /{tenant}} path prefix under {@code multipleIssuersAllowed}) gets its own RSA key with a
 * distinct {@code kid}. A token minted for tenant A is signed with A's key and therefore cannot be
 * forged for tenant B — the cryptographic isolation that per-tenant issuers alone do not provide.
 *
 * <p>Keys are generated on demand and held for the process lifetime (dev). Production wraps each
 * tenant key in KMS / Key Vault (ARCHITECTURE.md §7 / ADR-0007) and rotates with overlap. Requests
 * with no tenant path (the root issuer) use a default key, so the existing single-issuer flow keeps
 * working unchanged.
 */
@Component
public class TenantJwkSource implements JWKSource<SecurityContext> {

    private static final String DEFAULT_TENANT = "__default__";

    private final Map<String, JWKSet> keysByTenant = new ConcurrentHashMap<>();

    @Override
    public List<JWK> get(JWKSelector jwkSelector, SecurityContext context) {
        return jwkSelector.select(currentTenantJwkSet());
    }

    /** The JWKSet for the tenant of the current request's issuer (or the default key at the root). */
    public JWKSet currentTenantJwkSet() {
        AuthorizationServerContext asContext = AuthorizationServerContextHolder.getContext();
        String tenant = asContext != null ? tenantFromIssuer(asContext.getIssuer()) : null;
        return jwkSetFor(tenant);
    }

    /** The JWKSet for an explicitly named tenant (generated on first use) — for flows that know their
     * tenant out-of-band rather than from the request context, e.g. the tenant-app interaction-code
     * minter, which runs outside the protocol chain where no issuer context is set. */
    public JWKSet jwkSetFor(String tenant) {
        String key = (tenant == null || tenant.isBlank()) ? DEFAULT_TENANT : tenant;
        return keysByTenant.computeIfAbsent(key, TenantJwkSource::generateKeySet);
    }

    /** The union of every key generated so far (default + all tenants). For VALIDATION and the
     * aggregate JWKS endpoint only — never wire this into a signer, which must select exactly its
     * own tenant's key (see class javadoc for why the isolation matters). */
    public JWKSet allKeys() {
        List<JWK> keys = keysByTenant.values().stream()
                .flatMap(set -> set.getKeys().stream())
                .toList();
        return new JWKSet(keys);
    }

    /** Extracts the tenant from an issuer like {@code http://host:port/acme} → {@code acme};
     * returns null for a root issuer with no path. */
    static String tenantFromIssuer(String issuer) {
        if (issuer == null || issuer.isBlank()) {
            return null;
        }
        try {
            String path = URI.create(issuer).getPath();
            if (path == null || path.isBlank() || path.equals("/")) {
                return null;
            }
            String[] segments = path.replaceAll("^/", "").split("/");
            return segments.length == 0 ? null : segments[segments.length - 1];
        } catch (Exception ex) {
            return null;
        }
    }

    private static JWKSet generateKeySet(String tenant) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();
            // kid = readable tenant prefix + a per-generation suffix. The suffix is essential: keys are
            // regenerated on restart (dev), and a *stable* kid would make resource servers keep a stale
            // key cached under the same kid and reject the new tokens. A fresh kid is unknown to the
            // cache, so the decoder re-fetches the JWKS and self-heals. (Production persists keys in KMS.)
            String prefix = tenant.equals(DEFAULT_TENANT) ? "aegis-default" : "aegis-" + tenant;
            RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey((RSAPrivateKey) keyPair.getPrivate())
                    .keyID(prefix + "-" + UUID.randomUUID().toString().substring(0, 8))
                    .build();
            return new JWKSet(rsaKey);
        } catch (Exception ex) {
            throw new IllegalStateException("unable to generate signing key for tenant " + tenant, ex);
        }
    }
}
