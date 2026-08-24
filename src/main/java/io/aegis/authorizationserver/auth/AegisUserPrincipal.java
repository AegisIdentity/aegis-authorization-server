package io.aegis.authorizationserver.auth;

import java.io.Serial;
import java.io.Serializable;
import java.security.Principal;

/**
 * The authenticated resource owner, carrying the <strong>tenant they belong to</strong> (and their
 * user id) alongside the username. This is what makes issued tokens tenant-specific: the JWT
 * customizer reads the tenant from here, so a token reflects the actual user's tenant rather than a
 * fixed per-client setting.
 *
 * <p>{@link Serializable} is required, not decorative. This principal ends up inside the
 * {@code SecurityContext} stored in the {@code HttpSession}, and the AS runs Spring Session backed by
 * Redis, which serializes session attributes with JDK serialization. Without this, the very first
 * successful interactive login fails with {@code NotSerializableException} while writing the session
 * — surfacing as a 500 Whitelabel page on {@code /login}, after the credentials were already
 * accepted. Covered by {@code AegisUserPrincipalSerializationTest}.
 */
public record AegisUserPrincipal(String tenantId, String userId, String username)
        implements Principal, Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Override
    public String getName() {
        return username;
    }
}
