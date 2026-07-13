# Authentication Gender And Email-Only Identity Contract

## Scope

Persist the registration gender in Backend Authentication while keeping username ownership exclusively in SocialGraph. Update the internal SocialGraph-to-Auth payload, Authentication schema, API Gateway source schema/Fusion archive, migrations, documentation, and verification suites.

The gender contract is:

- Male = `true`
- Female = `false`
- Existing users may have `null` until their data is updated.

Location remains owned by the social/profile domain and is not added to Authentication.

## Database

`fb.id_user` gains:

```sql
gender boolean NULL
```

The reference `schema.sql` includes the column for new databases. A separate idempotent migration uses `ADD COLUMN IF NOT EXISTS` for existing databases. The column remains nullable for backward compatibility, while new registration inputs require a value.

The identity `username` column and index are removed by `20260714_remove_username.sql`. Authentication identifies accounts by canonical `user_id` and email; SocialGraph owns username/profile data.

## Authentication domain and persistence

- `IdentityUser.Gender` is `bool?` so rows created before the migration remain readable.
- User repository insert statements write gender.
- Every user select maps gender.
- Registration normalization carries the required boolean without converting it to a string.
- Gender and username are not embedded in the JWT. Authorization depends on user id, session id, status, signature, issuer, audience, and token lifetime. This avoids stale profile claims and unnecessary identity data in bearer tokens.

## Public GraphQL contract

`RegisterInput` becomes:

```graphql
input RegisterInput {
  displayName: String!
  dob: Date!
  email: String!
  gender: Boolean!
  password: String!
}
```

Example variables:

```json
{
  "input": {
    "displayName": "Nguyen Van A",
    "dob": "2000-01-01",
    "email": "a@example.com",
    "gender": true,
    "password": "Password123!"
  }
}
```

`UserType` adds nullable output:

```graphql
gender: Boolean
```

The field is returned consistently by `me`, `login`, `refreshToken`, and any operation returning `UserType`.

## Internal identity API

`CreateUserIdentityInput` adds required JSON property:

```json
{
  "userId": 1234567890123456789,
  "email": "a@example.com",
  "password": "Password123!",
  "displayName": "Nguyen Van A",
  "dob": "2000-01-01",
  "gender": true
}
```

The endpoint remains protected by constant-time comparison of `X-Gateway-Secret`. It creates an unverified identity, password credential, hashed OTP, and persisted gender.

## API Gateway

After exporting the Authentication source schema:

- Replace `Gateway/schema/Authentication/schema.graphqls` with the generated schema.
- Confirm `RegisterInput.gender: Boolean!`, `UserType.gender: Boolean`, and that Auth input/output types contain no identity username.
- Recompose `gateway.far` using the existing Authentication schema settings and extensions.
- Confirm the composed archive keeps Auth `register`, `validateGatewaySession`, `paymentPremiumState`, and `setPaymentValidDate` internal.
- Do not modify Gateway JWT, cookie, refresh-token scrubbing, trusted-header, or session-validation behavior.

## Frontend coordination

Frontend registration sends gender through SocialGraph `createUser`. SocialGraph creates the canonical user ID and forwards the same gender to Auth `POST /internal/users`. Auth-only `register` is not a public Gateway mutation.

The registration mapping becomes:

```text
name = firstName + surname
birthdate = YYYY-MM-DD
gender = male ? true : false
location = selected location
email = email
password = password
```

The frontend may consume `UserType.gender` from Auth session responses, while SocialGraph remains the username/profile source of truth. Gateway does not inject `X-Username` into downstream requests.

## Documentation

Update all examples, input/type references, registration-flow descriptions, and security notes where relevant in:

- `Backend-Authentication/README.md`
- `Backend-Authentication/fakebookAuth/AGENT.md`
- `Backend-Authentication/fakebookAuth/AGENT_VIE.md`
- API Gateway documentation and committed Authentication source schema
- The active frontend full-authentication design spec

The six-field SocialGraph `createUser` mutation is the current public Gateway registration contract.

## Detailed verification

### Static and build checks

- Build Backend Authentication with zero errors.
- Export Authentication schema and inspect gender nullability.
- Compose the Gateway Fusion archive.
- Build API Gateway with zero errors.
- Build and lint the coordinated frontend changes.
- Inspect the Fusion archive rather than relying only on the source SDL.

### Database migration checks

- Run both additive migrations twice to prove idempotency.
- Confirm `fb.id_user.gender` exists with PostgreSQL boolean type and nullable compatibility.
- Deploy the username-free Auth contract before dropping the old column in a rolling rollout.
- Run `20260714_remove_username.sql` twice after old Auth instances are drained, then confirm the column and index are absent.
- Confirm a new registered user stores `true` for Male and `false` for Female.

### Direct Authentication calls

- `health` returns `ok`.
- Auth-only `register` accepts Male and Female inputs and rejects a missing gender at GraphQL validation.
- `register` still rejects weak passwords, invalid emails, future DOB values, and duplicate emails.
- `verifyEmail` activates the registered account using a valid OTP and rejects invalid/expired OTP values.
- `login` rejects an unverified user and succeeds after verification.
- Successful `login` returns `user.gender` and a valid access token.
- `me` returns the persisted gender with bearer authentication.
- `refreshToken` rotates the refresh token and preserves `user.gender`.
- `mySessions` and `mySessionHistory` remain operational.
- `changePassword`, password reset, logout session, logout all, and refresh-token reuse protections remain operational.
- `/internal/users` rejects missing/wrong gateway secrets and persists gender with the correct secret.

### Gateway calls

- Gateway schema introspection exposes SocialGraph `CreateUserInput.gender`, keeps Auth `register` hidden, and exposes `UserType.gender` as nullable.
- CreateUser, verify, email-only login, refresh, me, session queries, password operations, and logout operations proxy successfully.
- Gateway sets/rotates/clears the HttpOnly refresh cookie.
- Public GraphQL responses do not expose raw refresh-token or cookie values.
- Spoofed `X-Gateway-Secret`, `X-User-Id`, `X-Session-Id`, legacy `X-Username`, and `X-Refresh-Token` headers are removed at the edge; only user/session IDs are regenerated as trusted identity headers.
- Revoked sessions are rejected after the configured session-cache window.

### Regression evidence

Record the exact commands and summarized results. If SMTP is disabled, obtain OTP hashes/codes through an explicit local test mechanism without logging production secrets or weakening production behavior.
