package io.aegis.authorizationserver.auth;

import java.security.Principal;

/**
 * The authenticated resource owner, carrying the <strong>tenant they belong to</strong> (and their
 * user id) alongside the username. This is what makes issued tokens tenant-specific: the JWT
 * customizer reads the tenant from here, so a token reflects the actual user's tenant rather than a
 * fixed per-client setting.
 */
public record AegisUserPrincipal(String tenantId, String userId, String username) implements Principal {

    @Override
    public String getName() {
        return username;
    }
}
