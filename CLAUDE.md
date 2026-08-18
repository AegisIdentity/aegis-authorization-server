# aegis-authorization-server — working notes

**Maturity: core.** OIDC/OAuth2/M2M provider on Spring Authorization Server 7.1. Package
`io.aegis.authorizationserver`. Port 9000. Stores: Postgres (JDBC) for clients/authorizations/
consents **and durable per-tenant signing keys**; Redis for the login session (Spring Session) and
interaction codes.

## This service is the platform's only STATEFUL service — keep its state external
It hosts interactive login, so it is the one place where "any pod can serve any request" is not free.
Three things used to live in process memory and no longer do:
| State | Now | Wired by |
|---|---|---|
| per-tenant signing keys | Postgres, AES-GCM encrypted | `keys/JpaTenantKeyStore` |
| login session | Redis (Spring Session) | `session/RedisSessionConfig` |
| interaction codes | Redis, `GETDEL` single-use | `tenantapp/TenantAppStateConfig` |

**Redis is required — there is no in-memory fallback, on purpose.** A fallback turns a missing
Redis into intermittent broken logins that only appear once a second replica exists; failing at
startup is louder and cheaper to diagnose. Every IT supplies Redis via `TestcontainersConfig`.

**Two Boot 4 traps, both load-bearing and both invisible in configuration:**
1. `spring.session.store-type` **no longer exists** in Boot 4 — setting it is a silent no-op. The
   store is not property-selectable.
2. Boot 4 ships **no session-store auto-configuration at all**. `spring-boot-session` contributes
   only the filter/cookie/properties, and `spring-boot-data-redis` contributes no session support —
   so adding `spring-session-data-redis` alone leaves it **inert**, with no `SessionRepository` bean
   and a silently process-local `HttpSession`. Redis sessions must be opted into in code
   (`@EnableRedisHttpSession`), and the `spring-boot-session` dependency is required for the filter.
   `session/RedisSessionWiringIT` asserts the active repository really is Redis-backed, because
   neither trap is detectable from config review.

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
  key, so the single-issuer console flow still works. See ARCHITECTURE.md §7.
- **Signing keys are DURABLE, not per-process** (`keys/TenantKeyStore` + `keys/JpaTenantKeyStore`,
  table `tenant_signing_key`). They were previously generated into a `ConcurrentHashMap`, which meant
  a restart invalidated every issued token and — since the Helm chart runs `replicaCount: 2` with an
  HPA to 8 and no session affinity — each replica minted a *different* key per tenant, so a token
  signed by one pod failed against another pod's JWKS. Now: one key per tenant for the whole cluster,
  surviving restarts. The private half is AES-256-GCM encrypted at rest via
  `io.aegis.commons.crypto.FieldEncryption`. The AES data key comes from a `keys/kms/DataKeyProvider`:
  a base64 key (`aegis.crypto.field-key` / `AEGIS_FIELD_ENC_KEY`), OR — when
  `aegis.crypto.kms.enabled=true` — a **KMS envelope** data key unwrapped from a cloud CMK at startup
  (`keys/kms/AwsKmsKeyUnwrapper`, AWS SDK v2; the CMK never leaves KMS, ADR-0007). Fail-closed outside
  an explicit `dev` profile (neither key nor KMS configured → refuse to start). A partial unique index
  (`uk_tenant_signing_key_one_active_per_tenant`) makes concurrent first-use across replicas converge
  on one key instead of forking — `saveIfAbsent` returns whichever key won.
  Covered by `keys/TenantKeyPersistenceTest` (multi-replica, restart, 8-way race),
  `keys/TenantSigningKeyIT` (real Postgres, encryption-at-rest, DB constraint), and
  `keys/kms/AwsKmsUnwrapIT` (real KMS Decrypt via LocalStack).
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
