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
- Every new client/grant change ships with a test (unregistered client rejected, wrong redirect_uri
  rejected — the common real-world misconfigs).

## Build / test
`mvn verify` (needs Docker for Testcontainers Postgres). Coverage floor 0.60.
