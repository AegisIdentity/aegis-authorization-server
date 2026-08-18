package io.aegis.authorizationserver.tenantapp;

import io.aegis.authorizationserver.auth.AegisUserPrincipal;
import io.aegis.authorizationserver.auth.IdentityClient;
import io.aegis.authorizationserver.auth.MfaClient;
import io.aegis.authorizationserver.federation.BrokerClient;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * The tenant-app (embedded) authentication API — what a tenant's own web/mobile app calls to sign users
 * in with a passkey or a native-social token and receive Aegis tokens, and to enrol passkeys bound to
 * the tenant's own domain.
 *
 * <p>Flow: run the WebAuthn assertion (or obtain a provider id_token from a native SDK) → POST it here →
 * get a single-use, PKCE-bound {@code interaction_code} → swap it for tokens. Credentials never touch the
 * token endpoint; the exchange is safe for public mobile/SPA clients.
 */
@RestController
public class TenantAppAuthController {

    private final RegisteredClientRepository clients;
    private final MfaClient mfaClient;
    private final BrokerClient broker;
    private final IdentityClient identityClient;
    private final NativeProviderVerifier providerVerifier;
    private final InteractionCodeStore interactions;
    private final AegisTokenMinter tokenMinter;
    private final io.aegis.commons.audit.AuditRecorder audit;

    public TenantAppAuthController(RegisteredClientRepository clients, MfaClient mfaClient, BrokerClient broker,
                                  IdentityClient identityClient, NativeProviderVerifier providerVerifier,
                                  InteractionCodeStore interactions, AegisTokenMinter tokenMinter,
                                  io.aegis.commons.audit.AuditRecorder audit) {
        this.clients = clients;
        this.mfaClient = mfaClient;
        this.broker = broker;
        this.identityClient = identityClient;
        this.providerVerifier = providerVerifier;
        this.interactions = interactions;
        this.tokenMinter = tokenMinter;
        this.audit = audit;
    }

    // --- Passkey enrolment (signed-in user; passkey bound to the tenant's own rpId) ---

    @PostMapping("/api/v1/webauthn/register/options")
    public Map<String, Object> registerOptions(@AuthenticationPrincipal Jwt caller) {
        String tenant = tenantOf(caller);
        return mfaClient.registerOptions(tenant, caller.getSubject(), accountOf(caller), displayNameOf(caller));
    }

    @PostMapping("/api/v1/webauthn/register/finish")
    @ResponseStatus(HttpStatus.CREATED)
    public Map<String, Object> registerFinish(@AuthenticationPrincipal Jwt caller,
                                              @RequestBody Map<String, Object> body) {
        mfaClient.registerFinish(tenantOf(caller), caller.getSubject(), body);
        return Map.of("status", "registered");
    }

    // --- Passwordless passkey login → interaction code ---

    @PostMapping("/api/v1/webauthn/login/options")
    public Map<String, Object> loginOptions(@RequestBody Map<String, Object> body) {
        String tenant = tenantOfClient(str(body, "clientId"));
        return mfaClient.assertionOptions(tenant);
    }

    @PostMapping("/api/v1/webauthn/login/finish")
    public Map<String, String> loginFinish(@RequestBody Map<String, Object> body) {
        String clientId = str(body, "clientId");
        String tenant = tenantOfClient(clientId);
        MfaClient.AssertionResult result = mfaClient.verifyAssertion(assertionOf(body));
        if (!result.valid() || result.tenant() == null || result.subject() == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "passkey not recognized");
        }
        // The passkey's owning tenant must match the app's tenant — no cross-tenant sign-in.
        if (!tenant.equals(result.tenant())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "passkey belongs to another organization");
        }
        String code = interactions.create(tenant, result.subject(), clientId, str(body, "codeChallenge"), "webauthn");
        return Map.of("interaction_code", code);
    }

    // --- Native social (provider id_token from a native SDK) → interaction code ---

    @PostMapping("/api/v1/social/native")
    public Map<String, String> socialNative(@RequestBody Map<String, Object> body) {
        String clientId = str(body, "clientId");
        String tenant = tenantOfClient(clientId);
        String providerAlias = str(body, "provider");
        BrokerClient.ProviderConfig provider = broker.resolve(tenant, providerAlias);
        if (provider == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "unknown provider: " + providerAlias);
        }
        NativeProviderVerifier.VerifiedIdentity id = providerVerifier.verify(provider, str(body, "idToken"));
        // JIT-provision by verified email (same guard as browser federation).
        AegisUserPrincipal principal = identityClient.provisionFederated(tenant, id.email(), id.preferredUsername());
        String code = interactions.create(tenant, principal.username(), clientId, str(body, "codeChallenge"), "social");
        return Map.of("interaction_code", code);
    }

    // --- Interaction code → tokens (PKCE-verified) ---

    @PostMapping("/api/v1/oauth/interaction/token")
    public Map<String, Object> token(@RequestBody Map<String, Object> body) {
        String clientId = str(body, "clientId");
        InteractionCodeStore.Transaction txn = interactions.consume(
                str(body, "interaction_code"), clientId, str(body, "code_verifier"));
        AegisTokenMinter.Tokens t = tokenMinter.mint(txn.tenant(), txn.subject(), clientId, txn.amr());
        // Token issuance is a core auth event — stream it to the platform trail (no token in the record).
        audit.record("auth", "auth.token.issued", txn.tenant(), txn.subject(), clientId, "amr", txn.amr());
        // OAuth2 token response (snake_case).
        return Map.of(
                "access_token", t.accessToken(),
                "id_token", t.idToken(),
                "token_type", t.tokenType(),
                "expires_in", t.expiresIn(),
                "scope", t.scope());
    }

    // --- helpers ---

    private String tenantOfClient(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "clientId is required");
        }
        RegisteredClient client = clients.findByClientId(clientId);
        if (client == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "unknown client");
        }
        Object tenant = client.getClientSettings().getSetting("tenant");
        if (tenant == null || tenant.toString().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "client is not bound to a tenant");
        }
        return tenant.toString();
    }

    private static String tenantOf(Jwt caller) {
        String tenant = caller.getClaimAsString("tenant");
        if (tenant == null || tenant.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "token carries no tenant");
        }
        return tenant;
    }

    private static Map<String, Object> assertionOf(Map<String, Object> body) {
        // A plain HashMap (not Map.of) because userHandle may be legitimately null and Map.of rejects nulls.
        Map<String, Object> assertion = new java.util.HashMap<>();
        for (String k : new String[] {"challengeId", "credentialId", "authenticatorData", "clientDataJSON",
                "signature", "userHandle"}) {
            Object v = body == null ? null : body.get(k);
            assertion.put(k, v == null ? "" : v);
        }
        return assertion;
    }

    private static String accountOf(Jwt caller) {
        String u = caller.getClaimAsString("preferred_username");
        return (u == null || u.isBlank()) ? caller.getSubject() : u;
    }

    private static String displayNameOf(Jwt caller) {
        String name = caller.getClaimAsString("name");
        return (name == null || name.isBlank()) ? accountOf(caller) : name;
    }

    private static String str(Map<String, Object> body, String key) {
        Object v = body == null ? null : body.get(key);
        return v == null ? null : v.toString();
    }

    @ExceptionHandler(InteractionCodeStore.InvalidInteractionException.class)
    public ResponseEntity<Map<String, String>> invalidInteraction(InteractionCodeStore.InvalidInteractionException ex) {
        return ResponseEntity.badRequest().body(Map.of("error", "invalid_grant", "error_description", ex.getMessage()));
    }

    @ExceptionHandler(NativeProviderVerifier.NativeVerificationException.class)
    public ResponseEntity<Map<String, String>> nativeFailure(NativeProviderVerifier.NativeVerificationException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "invalid_token", "error_description", ex.getMessage()));
    }
}
