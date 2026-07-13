# aegis-authorization-server

The **OIDC/OAuth2 provider** and interactive-login host — the core token-issuing service (Spring
Authorization Server 7.1). Grants: `authorization_code`+PKCE, `client_credentials` (M2M/host-to-host),
`refresh_token`, device. Persistence: PostgreSQL (JDBC repositories). Port `9000`.

## Endpoints
`/.well-known/openid-configuration`, `/oauth2/authorize`, `/oauth2/token`, `/oauth2/jwks`,
`/userinfo`, `/oauth2/revoke`, `/oauth2/introspect`, `/connect/logout`, plus `/login`.

## Build / run
```bash
mvn verify        # 5 integration tests vs real Postgres (Testcontainers)
# local: see aegis-platform-infra/compose
```
See [SERVICE-CATALOG.md](../aegis-platform-docs/architecture/SERVICE-CATALOG.md).
