# Postgres schemas for Spring Authorization Server

These three files are **Postgres-adapted copies** of the schemas that ship inside
`spring-security-oauth2-authorization-server` (package
`org/springframework/security/oauth2/server/authorization/**`). The shipped versions target H2/MySQL
and declare the JSON/text state columns as `blob`, which Postgres does not have. `JdbcOAuth2Authorization*`
store these as text (JSON), so the change here is `blob` → `text` (not `bytea` — Postgres will not
coerce a `character varying` bind into `bytea`). We also make each `CREATE TABLE` an
`CREATE TABLE IF NOT EXISTS`, because `spring.sql.init.mode=always` re-runs these on every startup —
without it, the second boot against a persisted volume fails with "relation already exists".
Structure, column names, and constraints are otherwise identical.

Regenerate when upgrading the Authorization Server version:

```bash
ASJAR=$(find ~/.m2 -name 'spring-security-oauth2-authorization-server-*.jar' | grep -v sources | head -1)
unzip -p "$ASJAR" org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql \
  | sed -e 's/blob/text/g' -e 's/CREATE TABLE /CREATE TABLE IF NOT EXISTS /' > oauth2-authorization-schema.sql
# ...repeat for oauth2-authorization-consent-schema.sql and client/oauth2-registered-client-schema.sql
```

Do **not** hand-edit these beyond those two substitutions; the DDL must match what the `Jdbc*`
repositories in the AS jar expect.
