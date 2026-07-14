package io.aegis.authorizationserver.web;

import io.aegis.authorizationserver.auth.AegisUserPrincipal;
import io.aegis.authorizationserver.auth.MfaClient;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Passwordless sign-in with a WebAuthn passkey, driven from the hosted login page. Two JSON endpoints
 * the login-page script calls: fetch assertion options, then submit the authenticator's assertion. On a
 * verified assertion the user's session is established directly (the passkey is a strong, phishing-
 * resistant factor — user presence + verification), and the original {@code /oauth2/authorize} request
 * is resumed. The cryptographic verification (challenge, origin, rpId, signature, sign-count) is done by
 * mfa-webauthn-service; this controller never trusts the browser's claim of who it is.
 */
@RestController
public class PasskeyLoginController {

    private static final SimpleGrantedAuthority ROLE_USER = new SimpleGrantedAuthority("ROLE_USER");

    private final MfaClient mfaClient;
    private final RequestCache requestCache;
    private final String consoleUrl;
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    public PasskeyLoginController(MfaClient mfaClient, RequestCache authorizeRequestCache,
                                 @org.springframework.beans.factory.annotation.Value(
                                         "${aegis.console-url:http://localhost:3000}") String consoleUrl) {
        this.mfaClient = mfaClient;
        this.requestCache = authorizeRequestCache;
        this.consoleUrl = consoleUrl;
    }

    /** Start the ceremony: a challenge + rpId for {@code navigator.credentials.get()}. */
    @PostMapping("/login/webauthn/options")
    public Map<String, Object> options(@RequestBody(required = false) Map<String, Object> body) {
        String tenant = body == null ? null : (String) body.get("tenant");
        return mfaClient.assertionOptions(tenant);
    }

    /** Finish the ceremony: verify the assertion, establish the session, and return where to continue. */
    @PostMapping("/login/webauthn/verify")
    public ResponseEntity<Map<String, String>> verify(@RequestBody Map<String, Object> assertion,
                                                      HttpServletRequest request, HttpServletResponse response) {
        MfaClient.AssertionResult result = mfaClient.verifyAssertion(assertion);
        if (!result.valid() || result.tenant() == null || result.subject() == null) {
            return ResponseEntity.status(401).body(Map.of("error", "passkey_not_recognized"));
        }

        // The subject is the token `sub` (== username); userId mirrors it for a passwordless session.
        AegisUserPrincipal principal = new AegisUserPrincipal(result.tenant(), result.subject(), result.subject());
        List<GrantedAuthority> authorities = List.of(ROLE_USER,
                FactorGrantedAuthority.fromAuthority("FACTOR_WEBAUTHN"));
        var auth = new UsernamePasswordAuthenticationToken(principal, null, authorities);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(auth);
        SecurityContextHolder.setContext(context);
        securityContextRepository.saveContext(context, request, response);

        // Resume the original authorize request; if there is none (e.g. passkey clicked at a bare /login),
        // send the user to the console rather than a dead authorization-server root.
        SavedRequest saved = requestCache.getRequest(request, response);
        String redirect = saved != null ? saved.getRedirectUrl() : consoleUrl;
        return ResponseEntity.ok(Map.of("redirect", redirect));
    }
}
