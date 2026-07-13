# Fakebook Authentication Subgraph

Authentication and identity subgraph for Fakebook. This service owns credentials and identity creation, email verification, login, refresh token rotation, session management, password reset, password change, OTP limits, and authentication audit events. SocialGraph orchestrates the normal public registration flow and owns the canonical user ID.

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
  schema.sql            Reference PostgreSQL schema
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

- .NET SDK 8
- PostgreSQL
- SMTP account if real email delivery is enabled

## Configuration

The service reads the database connection string from:

1. `ConnectionStrings:DefaultConnection`
2. `POSTGRES_CONNECTION_STRING`

Important environment variables:

```text
ConnectionStrings__DefaultConnection
Jwt__SigningKey
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

`Jwt__SigningKey` is required and must be at least 32 bytes. Do not commit real JWT keys, database passwords, or SMTP passwords.

## Database

Create the PostgreSQL schema from:

```text
fakebookAuth/schema.sql
```

The schema uses PostgreSQL schema `fb` and includes:

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
$env:Jwt__SigningKey="at-least-32-bytes-long-signing-key"
$env:Smtp__Enabled="false"
dotnet run --project .\fakebookAuth\fakebookAuth.csproj
```

GraphQL endpoint:

```text
http://localhost:<port>/graphql
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
  -e Jwt__SigningKey="at-least-32-bytes-long-signing-key" `
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

`register` is available for direct Authentication testing and backward compatibility, but the Gateway marks it `@internal`. Normal frontend registration must call SocialGraph `createUser`. Authentication registration requires display name, date of birth, email, gender, and password; Authentication does not store or validate SocialGraph usernames.

Protected operations require:

```text
Authorization: Bearer <accessToken>
```

## Internal Service API

SocialGraph creates the canonical Fakebook user id first, then calls Authentication to create the identity row with that exact id.

```http
POST /internal/users
X-Gateway-Secret: <Gateway__InternalSharedSecret>
```

Body:

```json
{
  "userId": 1234567890123456789,
  "email": "a@example.com",
  "password": "at-least-8-chars",
  "displayName": "Nguyen Van A",
  "dob": "2000-01-01",
  "gender": true
}
```

Gender uses a binary boolean contract throughout Authentication:

```text
true  = Male
false = Female
```

The Auth-only GraphQL `register` mutation also requires `gender`. Existing identity rows created before the gender migration may return `gender = null` from `UserType`.

This endpoint creates an unverified user, password credential, and email verification OTP using the supplied `userId`. It is internal-only and rejects calls without the shared secret.

## Gateway Integration

The Gateway should set and clear browser cookies. This subgraph returns a `refreshTokenCookie` instruction from login, refresh, logout, logoutAll, and current-session logout flows.

Recommended flow:

```text
Registration:
  Frontend -> Gateway createUser -> SocialGraph
  SocialGraph generates canonical userId and calls Auth POST /internal/users
  Auth creates the unverified identity with gender, password credential, and verification OTP
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

Other subgraphs should not read browser cookies. They receive trusted identity context from the Gateway as user id, session id, shared secret, and correlation id. Username/profile lookups belong to SocialGraph and are not carried in Auth JWTs or trusted headers.

## Payment Premium Validity

Authentication remains the sole owner of `fb.id_user.valid_date`. Backend-Payment calls these internal GraphQL operations directly with `X-Payment-Secret`:

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

Apply the additive migrations before deploying this version because Auth user reads select `gender` and `valid_date`:

```text
fakebookAuth/migrations/20260713_add_gender.sql
fakebookAuth/migrations/20260713_add_valid_date.sql
```

For a zero-downtime rollout, deploy the SocialGraph payload change that sends `gender` first, apply the two additive migrations, then deploy Authentication and the recomposed Gateway. Older Authentication versions ignore the additional REST JSON property. After every old Authentication instance has stopped, apply the destructive `fakebookAuth/migrations/20260714_remove_username.sql` migration; the new version works while the old column is still present. In a maintenance-window deployment, all three migrations may run in filename order before starting the new application version.

## Security Notes

- Never commit real `appsettings.json` secrets.
- Never log raw refresh tokens, passwords, OTPs, SMTP credentials, database passwords, or JWT signing keys.
- Refresh tokens are rotated on every successful refresh.
- Reusing an old refresh token from an active session revokes all sessions.
- Using a token from an already revoked or expired session only returns `INVALID_REFRESH_TOKEN`.
- Access tokens include `sid`; protected auth operations reject revoked or expired sessions.
- Access tokens contain `user_id`, `sid`, and display name, but no SocialGraph username.
- Keep access tokens short-lived and refresh tokens in HttpOnly Secure cookies.

## More Documentation

For detailed developer and AI agent guidance, see:

- `fakebookAuth/AGENT.md`
- `fakebookAuth/AGENT_VIE.md`

Automated contract tests run with `dotnet test fakebookAuth.sln`. The broader `scripts/auth-gateway-e2e.ps1` suite expects Auth, SocialGraph, Gateway, Payment dependencies, and a PostgreSQL Docker container; pass `-PaymentSecret` with the same value as Auth `Payment__InternalSharedSecret`. It covers canonical registration, gender propagation, OTP, email-only login, JWT/session, Payment validity, refresh cookies, password flows, logout, and spoofing without printing OTPs or tokens.
