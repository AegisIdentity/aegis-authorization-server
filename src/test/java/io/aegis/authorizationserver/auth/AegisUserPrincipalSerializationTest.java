package io.aegis.authorizationserver.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;

/**
 * The AS runs Spring Session backed by Redis, which writes session attributes with JDK
 * serialization. A successful interactive login stores the {@code SecurityContext} — and therefore
 * {@link AegisUserPrincipal} and the login {@code details} — into the session, so every object on
 * that path must be {@link java.io.Serializable}.
 *
 * <p>When it was not, the failure was badly placed: credentials were accepted, then the session write
 * blew up with {@code NotSerializableException}, so the user saw a 500 Whitelabel page on
 * {@code /login} and could never sign in. Nothing in the unit suite covered it because the objects
 * are only serialized when a real Redis session store is active.
 */
class AegisUserPrincipalSerializationTest {

    @Test
    void principalSurvivesJdkSerialization() throws Exception {
        AegisUserPrincipal principal = new AegisUserPrincipal("acme", "user-123", "alice");

        AegisUserPrincipal restored = roundTrip(principal);

        assertThat(restored).isEqualTo(principal);
        assertThat(restored.tenantId()).isEqualTo("acme");
        assertThat(restored.userId()).isEqualTo("user-123");
        assertThat(restored.getName()).isEqualTo("alice");
    }

    /**
     * The shape Spring Session actually persists: the whole authenticated {@code SecurityContext},
     * including the tenant-carrying login details. This is the assertion that would have caught the
     * 500 — the principal alone is not the only object on the wire.
     */
    @Test
    void authenticatedSecurityContextSurvivesJdkSerialization() throws Exception {
        AegisUserPrincipal principal = new AegisUserPrincipal("acme", "user-123", "alice");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("tenant", "acme");
        UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken
                .authenticated(principal, null, List.of(new SimpleGrantedAuthority("ROLE_USER")));
        authentication.setDetails(new TenantWebAuthenticationDetails(request));
        SecurityContext context = new SecurityContextImpl(authentication);

        SecurityContext restored = roundTrip(context);

        assertThat(restored.getAuthentication().getPrincipal()).isEqualTo(principal);
        assertThat(((TenantWebAuthenticationDetails) restored.getAuthentication().getDetails()).getTenant())
                .isEqualTo("acme");
    }

    @SuppressWarnings("unchecked")
    private static <T> T roundTrip(T value) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream out = new ObjectOutputStream(bytes)) {
            out.writeObject(value);
        }
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            return (T) in.readObject();
        }
    }
}
