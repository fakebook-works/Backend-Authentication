# Authentication Profile Ownership Contract

## Goal

Keep Backend-Authentication limited to identity, credentials, verification, sessions, security state, and the current Premium validity used by Payment. SocialGraph is the only source of truth for user profile data.

This design supersedes the earlier plan to persist gender in Authentication.

## Ownership

Authentication owns:

- canonical `user_id` reference
- email and optional future authentication identifiers such as phone
- password credentials
- email verification and password-reset OTP state
- account status, sessions, refresh tokens, JWT issuing, and audit events
- `valid_date` for the current Premium entitlement contract

SocialGraph owns:

- name and username
- birthdate and gender
- location, bio, avatar, background, privacy, verification badge, and social relationships

Auth must not copy SocialGraph profile fields into its database, GraphQL types, JWT claims, trusted headers, or internal provisioning payload.

## Registration Contracts

The frontend contract remains SocialGraph `createUser` with name, gender, birthdate, location, email, and password. SocialGraph creates the profile and canonical user ID first.

SocialGraph then calls Auth:

```http
POST /internal/users
X-Gateway-Secret: <shared secret>
Content-Type: application/json
```

```json
{
  "userId": 1234567890123456789,
  "email": "a@example.com",
  "password": "Password123!"
}
```

The Auth-only GraphQL mutation is hidden by Gateway and has this source contract:

```graphql
input RegisterInput {
  email: String!
  password: String!
}
```

Both paths create only an unverified Auth identity, password credential, and email-verification OTP. SMTP messages use a neutral greeting because Auth does not query SocialGraph during security workflows.

## Read And Token Contracts

Auth user projections contain only Auth-owned fields:

```graphql
type UserType {
  userId: Long!
  email: String!
  validDate: DateTime
  status: Short!
}
```

Access tokens contain protocol and authentication claims such as `iss`, `aud`, `sub`, `user_id`, `sid`, `iat`, `nbf`, `exp`, and `jti`. They contain no username, display name, birthdate, or gender claim.

Frontend views that need profile data query SocialGraph using the canonical user ID.

## Database And Migrations

The final `fb.id_user` schema does not contain `username`, `dob`, `display_name`, or `gender`.

Published migrations remain immutable:

```text
20260713_add_gender.sql
20260713_add_valid_date.sql
20260714_remove_username.sql
20260714_remove_profile_fields.sql
```

`20260713_add_gender.sql` is historical and is superseded by `20260714_remove_profile_fields.sql`. Fresh databases use `schema.sql`, where profile fields are already absent.

For a rolling deployment, deploy the profile-free Auth and SocialGraph caller first, drain old Auth instances, then apply destructive column-removal migrations. For the current pre-production environment, the complete migration sequence can run before starting the new services.

## Gateway Contract

- Gateway keeps Auth `register`, `validateGatewaySession`, `paymentPremiumState`, and `setPaymentValidDate` internal.
- Public registration remains SocialGraph `createUser`.
- Gateway forwards trusted user/session IDs but no profile headers.
- The committed Authentication source schema and `gateway.far` must be regenerated after this change.

## Verification

- Auth schema exposes `RegisterInput` with only email/password and a profile-free `UserType`.
- `/internal/users` accepts only user ID, email, and password from SocialGraph.
- SocialGraph still persists all profile input and uses name for Search indexing.
- Auth SQL inserts/selects do not reference the removed columns.
- Fresh schema omits all removed columns; the new migration is idempotent.
- JWT payload has no profile claims.
- Login, refresh, `me`, OTP resend, password reset, session management, and Payment validity still work.
- Gateway composition keeps SocialGraph profile fields while removing them from Auth `UserType`.
