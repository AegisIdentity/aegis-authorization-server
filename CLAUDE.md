# aegis-authorization-server — working notes

**Maturity: core.** OIDC/OAuth2/M2M provider on Spring Authorization Server 7.1. Package
`io.aegis.authorizationserver`. Port 9000. Store: Postgres (JDBC) — no Redis in v1.

## Where things are
- `config/AuthorizationServerConfig` — protocol filter chain (Security 7.1 API:
  `new OAuth2AuthorizationServerConfigurer()` + `http.with(...)`; the config classes were folded into
  `spring-security-config`), JDBC repos, JWK source, per-client `tenant` claim customizer, issuer.
- `config/DefaultSecurityConfig` — `/login` form chain (Organization + Username + Password).
  Credentials are verified **per-tenant against identity-service** via `auth/IdentityAuthenticationProvider`
  + `auth/IdentityClient` (the AS mints a short-lived service JWT with its own key). The token's
  `tenant` claim is the authenticated user's real tenant (set in the JWT customizer from `AegisUserPrincipal`).
- `config/ApiSecurityConfig` — resource-server chain for `/api/**` (applications admin API), scope-gated.
- `resources/db/postgresql/*.sql` — Postgres-adapted AS schemas (shipped SQL uses `blob`; Postgres
  needs `text`). Regenerate on AS upgrade — see that folder`\s README.

## Non-negotiables (security)
- PKCE stays mandatory for public clients; no implicit / no ROPC (OAuth 2.1, ADR-0004).
- **Per-tenant issuers + signing keys** (`auth/TenantJwkSource`, `multipleIssuersAllowed(true)`, no
  explicit issuer): the issuer is the `/{tenant}` path prefix; each tenant gets its own RSA key/`kid`
  (`aegis-<tenant>`), so a token for tenant A can't be forged for B. Root path (no prefix) = default
  key, so the single-issuer console flow still works. Dev generates keys on demand; production wraps
  each in KMS and rotates with overlap, and must NOT regenerate on restart. See ARCHITECTURE.md §7.
- **Aggregate JWKS + union decoder** (`web/JwksController` → `GET /internal/jwks`): the union of every
  tenant's PUBLIC key. Resource servers point `AEGIS_JWKS_URI` here (root `/oauth2/jwks` has only the
  default key, so per-tenant-key tokens would 401). The AS's own `jwtDecoder` bean likewise validates
  with `TenantJwkSource#allKeys()` — outside the protocol chain there is no issuer context. Never wire
  `allKeys()` into an ENCODER (a signer must select exactly its tenant's key).
- **Tenant-app minted tokens are public-issuer, tenant-key signed** (`tenantapp/AegisTokenMinter`):
  `iss = ${aegis.public-issuer-base}/{tenant}` (compose: the edge gateway host) and signed with that
  tenant's key, so a tenant's backend validates them via standard OIDC discovery through the gateway
  (`/{tenant}/.well-known/...`). The gateway reaches the AS with `preserveHostHeader`, which is what
  makes gateway-host issuers come out of SAS discovery/token endpoints — see aegis-edge-gateway.
- Every new client/grant change ships with a test (unregistered client rejected, wrong redirect_uri
  rejected — the common real-world misconfigs).
- **Interactive-login principal must round-trip through the JDBC authorization store.** An
  authorization_code authorization persists the login `Authentication`, whose principal is
  `AegisUserPrincipal` and whose details are `TenantWebAuthenticationDetails` (both custom). The store
  uses Jackson 3 (`tools.jackson`) with a locked-down `PolymorphicTypeValidator`, so
  `AuthorizationServerConfig#authorizationService` swaps in a `JsonMapper` that (a) allowlists the
  `io.aegis.authorizationserver.auth` package and (b) registers mix-ins giving both types a JSON
  creator — on BOTH the read row mapper and the write parameters mapper. Any new custom type stored in
  the authentication needs the same treatment, or login 500s at the token endpoint with
  `InvalidTypeIdException`/"no Creators". Covered by
  `AuthorizationServerFlowsIT#authorization_with_a_custom_login_principal_round_trips_through_the_store`.
- **The login token must carry a `FactorGrantedAuthority`** (`IdentityAuthenticationProvider` grants
  `FACTOR_PASSWORD`). SAS derives the OIDC id_token `auth_time` from the latest factor's `issuedAt`;
  without a factor authority, id_token generation fails with "authenticationTime cannot be null".
- **MFA step-up is enforced by `MfaPendingGateFilter` on the protocol chain (Order 1), NOT by the
  success handler.** After the password factor, `MfaStepUp#arm` may set a session PENDING flag; the gate
  blocks `/oauth2/authorize` (so no code/token is issued) until `/mfa` verifies the second factor. The
  redirect from the login success handler is only UX — removing the gate would let a password-only
  session obtain tokens by navigating straight to the authorize endpoint. Step-up MUST key on the token
  `sub` (== `AegisUserPrincipal#getName()` == username), the same id self-service MFA stores factors
  under, or enforcement silently no-ops. Covered by `MfaStepUpTest` + the e2e in scripts.

## Build / test
`mvn verify` (needs Docker for Testcontainers Postgres). Coverage floor 0.60.
