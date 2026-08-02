# Fakebook Authentication Subgraph

Authentication and identity subgraph for Fakebook. This service owns credentials and identity creation, email verification, login, refresh token rotation, session management, password reset, password change, OTP limits, and authentication audit events. SocialGraph orchestrates normal public registration and exclusively owns user profile fields such as name, birthdate, gender, and location.

It is designed to run behind a GraphQL Federation Gateway. The Gateway should be the public entry point, while this subgraph remains responsible for credentials, sessions, JWT issuing, refresh token validation, and cookie instructions.

## Tech Stack

- .NET 8 ASP.NET Core
- HotChocolate GraphQL
- PostgreSQL
- Dapper + Npgsql
- BCrypt password hashing
- SMTP email delivery
- Docker-ready build

## Project Layout

```text
fakebookAuth/
  Configuration/        Runtime options
  GraphQL/              GraphQL schema and contracts
  Models/               Domain models and constants
  Repositories/         PostgreSQL data access
  Security/             Hashing, JWT, token, OTP, Snowflake ID helpers
  Services/             Auth business logic and SMTP sender
  migrations/           Idempotent migrations for existing databases
  schema.sql            Immutable fresh-database baseline (`00000000_schema`)
  AGENT.md              Detailed English agent/developer guide
  AGENT_VIE.md          Detailed Vietnamese agent/developer guide
```

## Core Features

- Canonical registration through Gateway `createUser` and SocialGraph provisioning
- Create an unverified identity with a caller-supplied canonical SocialGraph user ID
- Resend email verification code with cooldown and rate limiting
- Email/password login
- Short-lived JWT access tokens
- Refresh token rotation with SHA-256 hashed storage
- Refresh token reuse detection
- Logout current session, one session, or all sessions
- Session listing and session history
- Request password reset by OTP
- Reset password and revoke old sessions
- Change password and revoke other sessions
- Login failure rate limiting
- OTP failure and resend rate limiting
- Security audit logs
- Gateway cookie instruction contract
- Request correlation through `X-Correlation-ID`

## Requirements

- .NET SDK 10
- PostgreSQL
- SMTP account if real email delivery is enabled

## Configuration

The service reads the database connection string from:

1. `ConnectionStrings:DefaultConnection`
2. `POSTGRES_CONNECTION_STRING`

Important environment variables:

```text
ConnectionStrings__DefaultConnection
DatabaseMigrations__Enabled
DatabaseMigrations__ConnectionString
DatabaseMigrations__CommandTimeoutSeconds
POSTGRES_MIGRATION_CONNECTION_STRING
Jwt__PrivateKeyBase64
Jwt__KeyId
Jwt__LegacySigningKey
Jwt__Issuer
Jwt__Audience
Jwt__AccessTokenMinutes
Auth__RefreshTokenDays
Auth__OtpCooldownSeconds
Auth__OtpFailureLimit
Auth__OtpResendLimit
Auth__LoginFailureLimit
Auth__RefreshTokenCookieName
Auth__RefreshTokenCookieSameSite
Gateway__InternalSharedSecret
Payment__InternalSharedSecret
Smtp__Enabled
Smtp__Host
Smtp__Port
Smtp__Username
Smtp__Password
Smtp__FromEmail
Snowflake__WorkerId
```

`Jwt__PrivateKeyBase64` must contain a PKCS#8 RSA private key of at least 2048 bits.
Only Authentication receives this private key; Gateway and Upload receive its SPKI public
half. `Jwt__LegacySigningKey` is empty unless a bounded HS256 migration window is active.
Do not commit real JWT keys, database passwords, or SMTP passwords.

## Database

Database migrations run automatically before the HTTP server starts and are enabled by
default. Production should set `DatabaseMigrations__ConnectionString` (or
`POSTGRES_MIGRATION_CONNECTION_STRING`) to a migration-owner connection; otherwise the
migrator explicitly falls back to the runtime connection. Set
`DatabaseMigrations__Enabled=false` only when an external deployment step applies the
same migrations. A migration failure fails service startup.

The migration connection is always opened with Npgsql pooling, multiplexing, and ambient
transaction enlistment disabled. This keeps the advisory lock bound to one physical
PostgreSQL session and guarantees physical close releases it even if explicit unlock
cannot complete; runtime database pooling is unchanged.

The startup migrator holds a PostgreSQL session advisory lock, verifies immutable SQL
checksums in `auth.schema_migrations`, including `schema.sql` as ledger version
`00000000_schema`, and handles each database state deliberately:

- no `auth`/`fb` schema: apply embedded `schema.sql` and baseline every included version;
- legacy `fb`: apply/reconcile the immutable historical files in their declared order,
  rename to `auth`, then apply current `auth` migrations;
- existing `auth`: reconcile already-satisfied history without replaying destructive
  `fb` migrations, then apply only missing current migrations;
- both `fb` and `auth`: fail startup because the state is ambiguous.

Before an existing final `auth` database can be reconciled to `00000000_schema`, its
required tables, column PostgreSQL types/nullability, primary keys, unique email
constraint, session-expiry constraint, required valid indexes, and absence of legacy
profile columns are checked against the canonical baseline. A partial schema is rejected
without recording the baseline. The baseline and published migration SQL are immutable;
a checksum change on a later startup fails closed and requires a new migration version.

The schema uses PostgreSQL schema `auth` and includes:

- `id_user`
- `id_credential`
- `id_session`
- `id_session_refresh_token`
- `id_verification`
- `id_audit_log`
- role, permission, and MFA placeholder tables

Refresh tokens are never stored raw. The database stores SHA-256 hashes only.

## Run Locally

```powershell
dotnet build .\fakebookAuth\fakebookAuth.csproj --no-restore
dotnet run --project .\fakebookAuth\fakebookAuth.csproj
```

Example with environment variables:

```powershell
$env:ConnectionStrings__DefaultConnection="Host=localhost;Port=5432;Database=fakebook;Username=postgres;Password=..."
$env:Jwt__PrivateKeyBase64="<PKCS8-RSA-private-key-base64>"
$env:Jwt__KeyId="fakebook-rs256-<fingerprint>"
$env:Smtp__Enabled="false"
dotnet run --project .\fakebookAuth\fakebookAuth.csproj
```

GraphQL endpoint:

```text
http://localhost:<port>/graphql
```

## Health

Health endpoints used by local orchestration and containers:

```text
GET /health/live   Process liveness; does not require PostgreSQL.
GET /health/ready  Opens PostgreSQL and executes SELECT 1; returns 503 until ready.
```

## Docker

Build:

```powershell
docker build -t fakebook-auth -f .\fakebookAuth\Dockerfile .
```

Run:

```powershell
docker run --rm -p 5000:8080 `
  -e ConnectionStrings__DefaultConnection="Host=host.docker.internal;Port=5432;Database=fakebook;Username=postgres;Password=..." `
  -e Jwt__PrivateKeyBase64="<PKCS8-RSA-private-key-base64>" `
  -e Jwt__KeyId="fakebook-rs256-<fingerprint>" `
  -e Smtp__Enabled="false" `
  fakebook-auth
```

## GraphQL Surface

Queries:

```graphql
health: String!
me: UserType!
mySessions: [SessionType!]!
mySessionHistory: [SessionType!]!
validateGatewaySession(input: GatewaySessionValidationInput!): GatewaySessionValidationPayload!
```

Mutations:

```graphql
register(input: RegisterInput!): RegisterPayload!
verifyEmail(input: VerifyEmailInput!): VerifyEmailPayload!
resendEmailVerification(input: ResendEmailVerificationInput!): AuthActionPayload!
login(input: LoginInput!): LoginPayload!
refreshToken(input: RefreshTokenInput!): LoginPayload!
logout(input: LogoutInput!): AuthActionPayload!
logoutAll: AuthActionPayload!
logoutSession(input: LogoutSessionInput!): AuthActionPayload!
requestPasswordReset(input: RequestPasswordResetInput!): AuthActionPayload!
resetPassword(input: ResetPasswordInput!): AuthActionPayload!
changePassword(input: ChangePasswordInput!): AuthActionPayload!
```

`register` is available for direct Authentication testing and backward compatibility, but the Gateway marks it `@internal`. It accepts only `email` and `password`. Normal frontend registration must call SocialGraph `createUser` so the canonical user ID and profile are created before Auth credentials.

`UserType` contains only `userId`, `email`, `validDate`, and `status`. Authentication currently supports email login only and has no phone identifier. Name, username, birthdate, gender, location, avatar, and other profile data must be queried from SocialGraph.

Protected operations require:

```text
Authorization: Bearer <accessToken>
```

## Internal Service API

SocialGraph creates the canonical Fakebook user id first, then calls Authentication to create the identity row with that exact id.

These internal endpoints authenticate with the `X-Internal-AuthenticationService-Secret` header, with `X-Gateway-Secret` accepted as a fallback. Backend-Payment instead authenticates against Authentication's GraphQL endpoint with `X-Payment-Secret` (see Payment Premium Validity).

```http
POST /internal/users
X-Internal-AuthenticationService-Secret: <Gateway__InternalSharedSecret>
```

Body:

```json
{
  "userId": 1234567890123456789,
  "email": "a@example.com",
  "password": "at-least-8-chars"
}
```

This endpoint creates an unverified user, password credential, and email verification OTP using the supplied `userId`. It is internal-only and rejects calls without the shared secret.

SocialGraph deletion uses the idempotent companion endpoint:

```http
DELETE /internal/users/{userId}
X-Internal-AuthenticationService-Secret: <Gateway__InternalSharedSecret>
```

The identity is tombstoned instead of physically removed, all active sessions are
revoked, and the email remains reserved so a deleted canonical ID cannot be reused.

SocialGraph can resolve the contact email shown on an authenticated, visible profile
through the minimal internal endpoint:

```http
GET /internal/users/{userId}/contact
X-Internal-AuthenticationService-Secret: <Authentication target secret>
X-Internal-Timestamp: <unix timestamp>
X-Internal-Nonce: <single-use nonce>
X-Internal-Signature: <HMAC signature>
```

It returns only `{ userId, email }`, only for an active identity. Missing, unverified,
disabled and deleted identities return `404`. All `/internal` routes pass through the
shared signing middleware and Redis nonce store; invalid signatures, stale timestamps,
replay, or unavailable nonce storage fail closed. This endpoint is never called by the
browser and never returns credentials, password hashes, OTPs, tokens or session data.

## Gateway Integration

The Gateway should set and clear browser cookies. This subgraph returns a `refreshTokenCookie` instruction from login, refresh, logout, logoutAll, and current-session logout flows.

Recommended flow:

```text
Registration:
  Frontend -> Gateway createUser -> SocialGraph
  SocialGraph generates canonical userId and calls Auth POST /internal/users
  Auth creates the unverified email identity, password credential, and verification OTP
  SocialGraph rolls back its user object if the required Auth call fails
  After Auth succeeds, SocialGraph concurrently provisions:
    Search PUT /internal/search/indexes/{userId}
    Recommendation PUT /internal/recommendation/users/{userId}/embedding
  Those derived projections are idempotent and best-effort
  Frontend verifies the OTP before login

Login:
  Frontend -> Gateway -> Auth login
  Auth returns accessToken + refresh token cookie instruction
  Gateway sets HttpOnly refresh cookie
  Gateway returns accessToken and user data

Refresh:
  Gateway reads refresh token from HttpOnly cookie
  Gateway calls Auth refreshToken
  Auth rotates refresh token
  Gateway updates cookie and returns new accessToken

Logout:
  Gateway calls Auth logout/logoutAll/logoutSession
  Gateway clears cookie when instruction operation is CLEAR
```

Other subgraphs should not read browser cookies. They receive trusted identity context from the Gateway as user id, session id, shared secret, and correlation id. All profile lookups belong to SocialGraph and are not persisted by Auth or carried in Auth JWTs/trusted headers.

## Payment Premium Validity

Authentication remains the sole owner of `auth.id_user.valid_date`. Backend-Payment calls these internal GraphQL operations directly with `X-Payment-Secret`:

```graphql
query PaymentPremiumState($userId: ID!) {
  paymentPremiumState(userId: $userId) { userId validDate }
}

mutation SetPaymentValidDate($input: SetPaymentValidDateInput!) {
  setPaymentValidDate(input: $input) { userId validDate }
}
```

Configure `Payment__InternalSharedSecret` independently from the Gateway secret. The setter is idempotent and uses `GREATEST`, so retries can never shorten Premium validity. Gateway composition marks both operations internal; `UserType.validDate` remains readable on normal user projections.

## Existing Database Migration

The migration history remains immutable even though production has not been deployed. The final PostgreSQL schema is named `auth`; it contains `valid_date` but no phone, username, or SocialGraph profile columns:

```text
fakebookAuth/migrations/20260713_add_gender.sql
fakebookAuth/migrations/20260713_add_valid_date.sql
fakebookAuth/migrations/20260714_remove_username.sql
fakebookAuth/migrations/20260714_remove_profile_fields.sql
fakebookAuth/migrations/20260714_remove_phone.sql
fakebookAuth/migrations/20260714_rename_schema_to_auth.sql
fakebookAuth/migrations/20260727_add_absolute_session_expiry.sql
fakebookAuth/migrations/20260727_add_login_path_indexes.sql
```

The startup migrator performs this sequence automatically. Fresh databases use
`schema.sql`, which creates schema `auth` directly and already omits `phone`, `username`,
`dob`, `display_name`, and `gender`; historical removal SQL is recorded as baselined and
is never executed on that fresh schema. Existing untracked databases are reconciled by
observable schema state before a ledger row is written. `schema.sql` itself is recorded
and checksum-verified as immutable version `00000000_schema`.

For the one-time legacy `fb` transition, stop or drain old Auth instances before starting
this version because the rename is incompatible with the old runtime SQL. Concurrent new
instances are safe: only one migrator runs at a time under the advisory lock.

## Security Notes

- Never commit real `appsettings.json` secrets.
- Never log raw refresh tokens, passwords, OTPs, SMTP credentials, database passwords, or JWT signing keys.
- Refresh tokens are rotated on every successful refresh.
- Reusing an old refresh token from an active session revokes all sessions.
- Using a token from an already revoked or expired session only returns `INVALID_REFRESH_TOKEN`.
- Access tokens include `sid`; protected auth operations reject revoked or expired sessions.
- Access tokens contain authentication identifiers such as `user_id` and `sid`, but no SocialGraph profile claims.
- Keep access tokens short-lived and refresh tokens in HttpOnly Secure cookies.

## More Documentation

For detailed developer and AI agent guidance, see:

- `fakebookAuth/AGENT.md`
- `fakebookAuth/AGENT_VIE.md`

Automated contract tests run with `dotnet test fakebookAuth.sln`. The broader `scripts/auth-gateway-e2e.ps1` suite expects Auth, SocialGraph, Gateway, Payment dependencies, and a PostgreSQL Docker container; pass `-PaymentSecret` with the same value as Auth `Payment__InternalSharedSecret`. It covers canonical registration, phone/profile-field isolation, OTP, email-only login, JWT/session, Payment validity, refresh cookies, password flows, logout, and spoofing without printing OTPs or tokens.
