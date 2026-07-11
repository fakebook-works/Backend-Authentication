# Fakebook Authentication Subgraph Agent Guide

This file is the working guide for developers and AI agents modifying or integrating the Fakebook Authentication subgraph.

The most important downstream consumer is expected to be a GraphQL Federation Gateway. The Gateway should treat this subgraph as the owner of identity, credentials, sessions, refresh token rotation, OTP, and account authentication workflows.

## Project Summary

- Project type: .NET 8 ASP.NET Core GraphQL service.
- GraphQL library: HotChocolate.
- Database: PostgreSQL.
- Data access: Dapper + Npgsql.
- Password hashing: BCrypt.
- Access token format: custom HS256 JWT.
- Refresh token storage: SHA-256 hash in PostgreSQL, never raw token.
- Refresh token transport model: Auth subgraph returns token + cookie instruction; Gateway should set/clear the real browser cookie.
- Email provider: SMTP through `SmtpEmailSender`.
- Main endpoint: `/graphql`.
- Root redirect: `/` redirects to `/graphql`.

## Important Files

- `Program.cs`: service registration, options validation, GraphQL registration, request correlation middleware.
- `Configuration/Configuration.cs`: runtime options for JWT, Auth, SMTP, Snowflake IDs.
- `GraphQL/GraphQLSchema.cs`: GraphQL query and mutation resolver surface.
- `GraphQL/GraphQLContracts.cs`: GraphQL input and output records.
- `Services/AuthService.cs`: core authentication business logic.
- `Services/SmtpEmailSender.cs`: OTP email delivery through SMTP.
- `Security/SecurityServices.cs`: password hashing, JWT, refresh token generation, Snowflake IDs, OTP generation.
- `Repositories/Repositories.cs`: PostgreSQL access layer.
- `Models/DataModels.cs`: domain model records/classes and constants.
- `schema.sql`: reference schema for a new PostgreSQL database.

Do not commit secrets. Local `appsettings.json` and `appsettings.Development.json` may contain real credentials and should be treated as sensitive.

## Runtime Configuration

Connection string lookup order:

1. `ConnectionStrings:DefaultConnection`
2. `POSTGRES_CONNECTION_STRING`

Required JWT configuration:

```text
Jwt__SigningKey
```

`Jwt:SigningKey` must be at least 32 bytes.

Useful environment variables:

```text
ConnectionStrings__DefaultConnection
POSTGRES_CONNECTION_STRING
Jwt__Issuer
Jwt__Audience
Jwt__SigningKey
Jwt__AccessTokenMinutes
Auth__RefreshTokenDays
Auth__EmailVerificationMinutes
Auth__PasswordResetMinutes
Auth__OtpCooldownSeconds
Auth__OtpFailureLimit
Auth__OtpFailureWindowMinutes
Auth__OtpResendLimit
Auth__OtpResendWindowMinutes
Auth__LoginFailureLimit
Auth__LoginFailureWindowMinutes
Auth__RefreshTokenCookieName
Auth__RefreshTokenCookiePath
Auth__RefreshTokenCookieSameSite
Auth__RefreshTokenCookieHttpOnly
Auth__RefreshTokenCookieSecure
Gateway__InternalSharedSecret
Smtp__Enabled
Smtp__Host
Smtp__Port
Smtp__EnableSsl
Smtp__Username
Smtp__Password
Smtp__FromEmail
Smtp__FromName
Snowflake__WorkerId
```

Default auth values in code:

```text
RefreshTokenDays = 30
EmailVerificationMinutes = 15
PasswordResetMinutes = 15
OtpCooldownSeconds = 60
OtpFailureLimit = 5
OtpFailureWindowMinutes = 15
OtpResendLimit = 3
OtpResendWindowMinutes = 15
LoginFailureLimit = 5
LoginFailureWindowMinutes = 15
RefreshTokenCookieName = fb_refresh
RefreshTokenCookiePath = /
RefreshTokenCookieSameSite = Lax
RefreshTokenCookieHttpOnly = true
RefreshTokenCookieSecure = true
```

`Auth__RefreshTokenCookieSameSite=None` requires `Auth__RefreshTokenCookieSecure=true`.

## Database Notes

The schema is under PostgreSQL schema `fb`.

Core tables:

- `fb.id_user`: user identity profile.
- `fb.id_credential`: password credential hash.
- `fb.id_session`: active/revoked session state and current refresh token hash.
- `fb.id_session_refresh_token`: refresh token history for reuse detection.
- `fb.id_verification`: OTP verification records.
- `fb.id_audit_log`: security audit events.
- `fb.id_role`, `fb.id_permission`, `fb.id_role_permission`, `fb.id_user_role`: role/permission placeholders.
- `fb.id_mfa_method`: MFA placeholder.

User status values:

```text
1 = active
2 = disabled
3 = deleted
4 = unverified
```

Verification type values:

```text
1 = email verification
3 = password reset
```

Credential provider values:

```text
1 = password
```

Refresh token storage:

- Raw refresh token is only returned at login/refresh time.
- Database stores SHA-256 hex hash of refresh tokens.
- `id_session.refresh_token` stores the current refresh token hash.
- `id_session_refresh_token` stores current and replaced token hashes.
- Replaced token reuse can trigger account-wide session revocation if the owning session is still active.
- A token from an already revoked/expired session returns `INVALID_REFRESH_TOKEN` and does not revoke the full account.

## Observability

Every request receives or reuses `X-Correlation-ID`.

Behavior:

- If request header `X-Correlation-ID` exists, it is reused.
- Otherwise a new GUID-like correlation id is generated.
- Response header `X-Correlation-ID` is always set.
- Logs include correlation id scope.

Auth service logs important events:

- login success
- refresh token rotation
- refresh token reuse detection
- rejected token for revoked/expired session
- OTP failure/rate limits
- logout/logout all/logout session
- password reset/change

## Access Token Model

Access tokens are HS256 JWTs generated by `TokenService`.

Claims include:

```text
iss
aud
sub
user_id
username
name
iat
nbf
exp
jti
sid
```

`sid` is the session id and is included for login/refresh generated tokens.

Protected auth subgraph operations validate:

1. `Authorization: Bearer <accessToken>` exists.
2. JWT signature, issuer, audience, expiry, and not-before are valid.
3. User exists and is active.
4. If `sid` exists, session must still be active and unexpired.

This means a revoked session's access token is rejected before natural JWT expiry for operations handled by this subgraph.

## Gateway and Federation Guidance

The Gateway should be the only public entry point for frontend applications.

Recommended responsibility split:

- Auth Subgraph owns credentials, OTP, sessions, JWT issuing, refresh token rotation, and cookie instructions.
- Gateway owns actual browser cookies and public response shaping.
- Other subgraphs should not read browser cookies or refresh tokens.
- Other subgraphs should trust only identity context forwarded by the Gateway over internal network boundaries.

Recommended Gateway protected-request flow:

```text
Frontend -> Gateway protected operation
Gateway validates access token locally
Gateway extracts user_id, username, sid
Gateway optionally checks session active status with Auth Subgraph or a short-lived cache
Gateway forwards to subgraphs with internal identity headers/context
```

Suggested internal context headers if using HTTP subgraph calls:

```text
X-User-Id
X-Session-Id
X-Username
X-Correlation-ID
X-Refresh-Token
X-Gateway-Secret
X-Fakebook-Refresh-Cookie-Instruction
```

Do not let browsers set trusted identity headers directly. Strip these headers at the public edge and regenerate them inside the Gateway.
`X-Refresh-Token`, `X-Gateway-Secret`, and `X-Fakebook-Refresh-Cookie-Instruction` are internal-only headers. Browsers must not be allowed to set them.

Recommended Gateway cookie flow:

```text
login:
  Gateway calls Auth login
  Auth returns accessToken, refreshToken, refreshTokenCookie
  Gateway sets HttpOnly refresh cookie using refreshTokenCookie
  Gateway should avoid exposing refreshToken to browser JavaScript if possible
  Gateway returns accessToken and user data

refresh:
  Gateway reads refresh token from HttpOnly cookie
  Gateway calls Auth refreshToken
  Auth rotates refresh token and returns new cookie instruction
  Gateway sets the new cookie
  Gateway returns new accessToken

logout:
  Gateway reads refresh token from cookie
  Gateway calls Auth logout
  Gateway clears cookie using returned instruction

logoutAll:
  Gateway calls Auth logoutAll with bearer access token
  Gateway clears current browser cookie

logoutSession:
  Gateway calls Auth logoutSession with bearer access token
  If the returned cookie instruction is CLEAR, clear current browser cookie
  If refreshTokenCookie is null, do not modify current browser cookie
```

`LoginPayload` currently includes both `refreshToken` and `refreshTokenCookie.value`. The Gateway should treat this value as highly sensitive. Public frontend responses should preferably omit the raw refresh token and only expose the access token plus user data.

## Cookie Instruction Contract

GraphQL type:

```graphql
type GatewayCookieInstruction {
  operation: String!
  name: String!
  value: String
  path: String!
  sameSite: String!
  httpOnly: Boolean!
  secure: Boolean!
  maxAgeSeconds: Int!
  expiresAt: DateTime
}
```

Operations:

```text
SET
CLEAR
```

For `SET`:

- `value` is the raw refresh token.
- `maxAgeSeconds` equals `Auth.RefreshTokenDays` in seconds.
- `expiresAt` equals refresh token expiry.

For `CLEAR`:

- `value` is empty string.
- `maxAgeSeconds` is `0`.
- `expiresAt` is Unix epoch.

Auth also writes the same cookie instruction as base64 JSON in the internal HTTP response header:

```text
X-Fakebook-Refresh-Cookie-Instruction
```

The Gateway should consume this header, set or clear the real browser cookie, and avoid forwarding the internal header to public clients. This lets Gateway-owned cookies work even when the frontend does not select `refreshTokenCookie` in the GraphQL response.

## GraphQL Queries

### health

Public health check.

```graphql
query Health {
  health
}
```

Expected:

```json
{
  "data": {
    "health": "ok"
  }
}
```

### me

Requires:

```text
Authorization: Bearer <accessToken>
```

Validates JWT, user status, and active session.

```graphql
query Me {
  me {
    userId
    email
    username
    dob
    displayName
    status
  }
}
```

### mySessions

Requires bearer access token.

Returns only active sessions for the current user.

```graphql
query MySessions {
  mySessions {
    sessionId
    deviceName
    os
    browser
    ipAddress
    expiresAt
    createdAt
    lastSeenAt
    revocationReason
    revokedAt
    isCurrent
  }
}
```

For active sessions, `revokedAt` and `revocationReason` are normally null.

### mySessionHistory

Requires bearer access token.

Returns active and revoked sessions for the current user.

```graphql
query MySessionHistory {
  mySessionHistory {
    sessionId
    deviceName
    os
    browser
    ipAddress
    expiresAt
    createdAt
    lastSeenAt
    revocationReason
    revokedAt
    isCurrent
  }
}
```

### validateGatewaySession

Internal Gateway-only session validation.

Requires:

```text
X-Gateway-Secret: <Gateway__InternalSharedSecret>
```

```graphql
query ValidateGatewaySession($input: GatewaySessionValidationInput!) {
  validateGatewaySession(input: $input) {
    isValid
    userId
    sessionId
    username
    status
    expiresAt
  }
}
```

Notes:

- This field is for Gateway-to-Auth traffic only.
- The Gateway should mark this field `@internal` in Fusion source schema extensions so it is not exposed publicly.
- Returns `isValid = false` when the user is missing, not active, or the session is revoked/expired.
- Missing or invalid `X-Gateway-Secret` returns a GraphQL error with code `FORBIDDEN`.

## Internal REST APIs

### POST /internal/users

Internal SocialGraph-to-Auth identity creation. SocialGraph owns the canonical user id and sends it here.

Requires:

```text
X-Gateway-Secret: <Gateway__InternalSharedSecret>
```

Payload:

```json
{
  "userId": 1234567890123456789,
  "email": "a@example.com",
  "password": "at-least-8-chars",
  "displayName": "Nguyen Van A",
  "dob": "2000-01-01"
}
```

Behavior:

- Creates `id_user` with the supplied `userId`.
- Creates password credential and email verification OTP.
- Keeps the account `unverified` until `verifyEmail`.
- Generates an internal username from email local-part plus `userId` when no username is supplied.
- Rejects missing or invalid `X-Gateway-Secret`.

## GraphQL Mutations

### register

Legacy/direct-subgraph registration. The current Gateway marks this mutation `@internal`; normal frontend registration must use SocialGraph `createUser` through the Gateway. This mutation remains available for backward compatibility and isolated Auth testing.

Creates an unverified account with an Auth-generated ID and creates an email verification OTP.

```graphql
mutation Register($input: RegisterInput!) {
  register(input: $input) {
    success
    message
  }
}
```

Variables:

```json
{
  "input": {
    "displayName": "Quan Trieu",
    "dob": "2000-01-01",
    "email": "quan@example.com",
    "username": "quantrieu",
    "password": "Password123!"
  }
}
```

Notes:

- Email and username are normalized to lower-case.
- Password minimum length is 8.
- New users start with `status = 4` (unverified).
- If SMTP is enabled, OTP is emailed.
- If SMTP is disabled, OTP must be verified manually in DB/dev flow.

### verifyEmail

Activates an unverified account with a 6-digit OTP.

```graphql
mutation VerifyEmail($input: VerifyEmailInput!) {
  verifyEmail(input: $input) {
    success
    message
  }
}
```

Variables:

```json
{
  "input": {
    "identifier": "quan@example.com",
    "otp": "123456"
  }
}
```

Notes:

- `identifier` may be email or username.
- OTP must be exactly 6 digits.
- OTP failures are audited and rate limited.
- Success marks OTP used and activates the account.

### resendEmailVerification

Sends a new email verification OTP.

```graphql
mutation ResendEmailVerification($input: ResendEmailVerificationInput!) {
  resendEmailVerification(input: $input) {
    success
    message
  }
}
```

Variables:

```json
{
  "input": {
    "identifier": "quan@example.com"
  }
}
```

Notes:

- Only useful for unverified users.
- Has cooldown through `Auth.OtpCooldownSeconds`.
- Has resend rate limit through `Auth.OtpResendLimit` and `Auth.OtpResendWindowMinutes`.
- Previous unused OTPs for this type are marked used before creating the new OTP.

### login

Authenticates username/email + password and creates a new session.

```graphql
mutation Login($input: LoginInput!) {
  login(input: $input) {
    accessToken
    refreshToken
    refreshTokenExpiresAt
    refreshTokenCookie {
      operation
      name
      value
      path
      sameSite
      httpOnly
      secure
      maxAgeSeconds
      expiresAt
    }
    user {
      userId
      email
      username
      displayName
      status
    }
  }
}
```

Variables:

```json
{
  "input": {
    "identifier": "quan@example.com",
    "password": "Password123!"
  }
}
```

Notes:

- Requires verified active account.
- Records `LOGIN_SUCCESS`.
- Records `LOGIN_FAILURE` for missing user or invalid password.
- Failed login attempts are rate limited by identifier and IP when IP is available.
- Creates `id_session` row.
- Stores refresh token hash, not raw token.
- Returns access token with `sid`.
- Returns raw refresh token and cookie instruction for Gateway.

### refreshToken

Rotates refresh token and issues a new access token.

```graphql
mutation RefreshToken($input: RefreshTokenInput!) {
  refreshToken(input: $input) {
    accessToken
    refreshToken
    refreshTokenExpiresAt
    refreshTokenCookie {
      operation
      name
      value
      maxAgeSeconds
      expiresAt
    }
    user {
      userId
      email
      username
    }
  }
}
```

Variables:

```json
{
  "input": {
    "refreshToken": "<raw-refresh-token>"
  }
}
```

Notes:

- Accepts raw refresh token.
- Gateway callers may omit `input.refreshToken` when they send the raw token through internal `X-Refresh-Token`.
- Hashes token and searches active session.
- Rotates token on every successful refresh.
- Writes previous token hash to token history with `replaced_at`.
- Records `REFRESH_TOKEN_ROTATED`.
- If an old replaced token is used while its session is still active, records `REFRESH_TOKEN_REUSE_DETECTED` and revokes all sessions.
- If token belongs to already revoked/expired session, returns `INVALID_REFRESH_TOKEN` and records `REVOKED_REFRESH_TOKEN_USED` without revoking the full account.

### logout

Logs out by refresh token.

```graphql
mutation Logout($input: LogoutInput!) {
  logout(input: $input) {
    success
    message
    refreshTokenCookie {
      operation
      name
      value
      maxAgeSeconds
    }
  }
}
```

Variables:

```json
{
  "input": {
    "refreshToken": "<raw-refresh-token>"
  }
}
```

Notes:

- If token is active, revokes its session with reason `LOGOUT`.
- Gateway callers may omit `input.refreshToken` when they send the raw token through internal `X-Refresh-Token`.
- Always returns success.
- Returns cookie `CLEAR` instruction.

### logoutAll

Revokes all sessions for the current user.

Requires bearer access token.

```graphql
mutation LogoutAll {
  logoutAll {
    success
    message
    refreshTokenCookie {
      operation
      name
      maxAgeSeconds
    }
  }
}
```

Notes:

- Revokes all active sessions with reason `LOGOUT_ALL`.
- Returns cookie `CLEAR` instruction for current browser.

### logoutSession

Revokes one specific session owned by the current user.

Requires bearer access token.

```graphql
mutation LogoutSession($input: LogoutSessionInput!) {
  logoutSession(input: $input) {
    success
    message
    refreshTokenCookie {
      operation
      name
      value
      maxAgeSeconds
    }
  }
}
```

Variables:

```json
{
  "input": {
    "sessionId": 1234567890
  }
}
```

Notes:

- Revokes session with reason `SESSION_REVOKED_BY_USER`.
- If revoking the current session, returns cookie `CLEAR`.
- If revoking another device/session, `refreshTokenCookie` is null and the Gateway should not clear the current browser cookie.
- Access token for the revoked session is rejected by protected auth operations.

### requestPasswordReset

Creates and sends a password reset OTP if an active account exists.

```graphql
mutation RequestPasswordReset($input: RequestPasswordResetInput!) {
  requestPasswordReset(input: $input) {
    success
    message
  }
}
```

Variables:

```json
{
  "input": {
    "identifier": "quan@example.com"
  }
}
```

Notes:

- Always returns generic success message to avoid account enumeration.
- Only active accounts receive OTP.
- Applies OTP cooldown and resend rate limit.
- Records `OTP_RESENT` for password reset OTP.

### resetPassword

Resets password using password reset OTP.

```graphql
mutation ResetPassword($input: ResetPasswordInput!) {
  resetPassword(input: $input) {
    success
    message
  }
}
```

Variables:

```json
{
  "input": {
    "identifier": "quan@example.com",
    "otp": "123456",
    "newPassword": "NewPassword123!"
  }
}
```

Notes:

- Only active accounts can reset password.
- OTP failures are audited and rate limited.
- On success, updates password credential.
- Marks OTP used.
- Revokes all user sessions with reason `PASSWORD_RESET`.
- Records `OTP_VERIFIED` and `PASSWORD_RESET`.

### changePassword

Changes password for an authenticated user.

Requires bearer access token.

```graphql
mutation ChangePassword($input: ChangePasswordInput!) {
  changePassword(input: $input) {
    success
    message
  }
}
```

Variables:

```json
{
  "input": {
    "currentPassword": "Password123!",
    "newPassword": "ChangedPassword123!"
  }
}
```

Notes:

- Current password must be valid.
- New password must be at least 8 characters.
- New password must differ from current password.
- Revokes other active sessions with reason `PASSWORD_CHANGED`.
- Keeps current session active when access token has `sid`.
- Records `PASSWORD_CHANGED`.

## GraphQL Types

Important payloads:

```graphql
type RegisterPayload {
  success: Boolean!
  message: String
}

type VerifyEmailPayload {
  success: Boolean!
  message: String
}

type AuthActionPayload {
  success: Boolean!
  message: String
  refreshTokenCookie: GatewayCookieInstruction
}

type LoginPayload {
  accessToken: String!
  refreshToken: String!
  refreshTokenExpiresAt: DateTime!
  refreshTokenCookie: GatewayCookieInstruction!
  user: UserType!
}

type UserType {
  userId: Long!
  email: String!
  username: String!
  dob: Date
  displayName: String!
  status: Short!
}

type SessionType {
  sessionId: Long!
  deviceName: String
  os: String
  browser: String
  ipAddress: String
  expiresAt: DateTime!
  createdAt: DateTime!
  lastSeenAt: DateTime
  revocationReason: String
  revokedAt: DateTime
  isCurrent: Boolean!
}

input GatewaySessionValidationInput {
  userId: Long!
  sessionId: Long!
}

type GatewaySessionValidationPayload {
  isValid: Boolean!
  userId: Long
  sessionId: Long
  username: String
  status: Short
  expiresAt: DateTime
}
```

HotChocolate may expose numeric .NET scalar names depending on schema generation. Query the live schema if exact scalar names matter to a Gateway implementation.

## Common Error Codes

GraphQL errors use `extensions.code`.

Validation and identity:

```text
IDENTIFIER_EXISTS
INVALID_DISPLAY_NAME
INVALID_EMAIL
INVALID_USERNAME
INVALID_DOB
WEAK_PASSWORD
INVALID_CREDENTIALS
ACCOUNT_NOT_FOUND
ACCOUNT_UNAVAILABLE
EMAIL_UNVERIFIED
UNAUTHENTICATED
FORBIDDEN
```

OTP and verification:

```text
INVALID_VERIFICATION_CODE
INVALID_OR_EXPIRED_VERIFICATION_CODE
INVALID_OR_EXPIRED_PASSWORD_RESET_CODE
OTP_COOLDOWN
OTP_RATE_LIMITED
OTP_RESEND_RATE_LIMITED
```

Login and token:

```text
LOGIN_RATE_LIMITED
INVALID_REFRESH_TOKEN
REFRESH_TOKEN_REUSE_DETECTED
```

Password/session:

```text
PASSWORD_UNCHANGED
INVALID_SESSION_ID
SESSION_NOT_FOUND
```

## Audit Actions

Known audit action values:

```text
LOGIN_SUCCESS
LOGIN_FAILURE
REFRESH_TOKEN_ROTATED
REFRESH_TOKEN_REUSE_DETECTED
REVOKED_REFRESH_TOKEN_USED
LOGOUT
LOGOUT_ALL
SESSION_REVOKED
OTP_RESENT
OTP_VERIFICATION_FAILURE
OTP_VERIFIED
PASSWORD_RESET
PASSWORD_CHANGED
```

Audit metadata includes IP address, user agent, and JSON data depending on event.

Examples:

- Login failures include `identifier` and `reason`.
- Login success includes `sessionId` and `identifier`.
- OTP events include `type` and `purpose`.
- Session revoke includes `sessionId` and whether it was current session.

## Security Notes

- Never store raw refresh tokens.
- Never log raw refresh tokens, passwords, OTP values, SMTP passwords, DB passwords, or JWT signing key.
- Refresh token rotation is mandatory on every refresh.
- Reusing an old refresh token from an active session is treated as compromise and revokes all sessions.
- Reusing a token from an already revoked/expired session is rejected but does not revoke all sessions.
- Frontend should not store refresh tokens in localStorage or readable JavaScript state.
- Gateway should set refresh token as `HttpOnly`, `Secure`, and configured `SameSite`.
- Access tokens are short-lived and can be stored by frontend according to Gateway design, but XSS risk should still be considered.
- Other subgraphs should not trust user-supplied identity headers.

## Expected Registration Flow

```text
1. Client submits name, gender, birthdate, location, email, and password to Gateway createUser.
2. Gateway routes createUser to SocialGraph through Fusion.
3. SocialGraph creates the profile object and canonical Snowflake userId.
4. SocialGraph calls Auth POST /internal/users with that userId and X-Gateway-Secret.
5. Auth creates the unverified identity with the supplied userId and stores the password hash.
6. Auth creates the verification OTP hash and sends email when SMTP is enabled.
7. If Auth fails, SocialGraph deletes the new profile object and returns a failed CreateUserPayload.
8. If Auth succeeds, SocialGraph runs Search/Recommendation provisioning best-effort and returns the userId.
9. Client submits identifier + OTP through Gateway verifyEmail.
10. Auth activates the account.
11. Client can now log in.
```

## Expected Login/Refresh Flow With Gateway

```text
1. Client calls Gateway login.
2. Gateway calls Auth login with identifier/password.
3. Auth validates credential and creates session.
4. Auth returns access token, refresh token, and SET cookie instruction.
5. Gateway sets refresh token cookie.
6. Gateway returns access token and user to client.
7. Client uses access token for protected operations.
8. Client calls Gateway refresh when access token expires.
9. Gateway reads refresh token cookie and calls Auth refreshToken.
10. Auth rotates refresh token and returns new SET instruction.
11. Gateway updates cookie and returns new access token.
```

## Expected Logout Flow With Gateway

```text
logout:
  Gateway reads refresh cookie
  Gateway calls Auth logout(refreshToken)
  Gateway clears cookie

logoutAll:
  Gateway calls Auth logoutAll with bearer access token
  Gateway clears cookie

logoutSession:
  Gateway calls Auth logoutSession(sessionId)
  If response refreshTokenCookie.operation == CLEAR, clear current cookie
  If refreshTokenCookie is null, do not touch current cookie
```

## Testing Notes

Recent manual/E2E checks covered:

- legacy direct register + verify email
- internal custom-userId creation used by SocialGraph
- login
- refresh token rotation
- refresh token reuse detection
- revoked-session refresh token rejection
- logout
- logoutAll
- logoutSession
- mySessions
- mySessionHistory
- password reset OTP limit
- password reset success
- change password
- login rate limit
- OTP resend limit
- cookie instruction contract
- internal `validateGatewaySession` contract
- revoked access token rejection
- multi-device session behavior
- Gateway proxy login/refresh/logout cookie behavior

There is no permanent test project yet. Future improvement: create `fakebookAuth.Tests` and move temporary E2E runner logic into `dotnet test`.

## Local Commands

Build:

```powershell
dotnet build .\fakebookAuth\fakebookAuth.csproj --no-restore
```

Run:

```powershell
dotnet run --project .\fakebookAuth\fakebookAuth.csproj
```

If using environment variables:

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

## Known Work Left

- Add permanent automated test project.
- Add proper migration system if the project grows beyond manual `schema.sql` updates.
- Keep exported federation schema and Gateway composition artifacts in sync when the Auth schema changes.
- Consider adding roles/permissions and MFA when product requirements exist.
- Add `appsettings.example.json` and remove real secrets from tracked files.
