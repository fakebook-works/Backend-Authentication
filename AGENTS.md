# Authentication service agent rules

When embedded in the Fakebook workspace, also read the root API security contract.

- Auth alone receives the RS256 private key. Do not expose it to Gateway, Upload or logs.
- JWT creation/validation stays in System.IdentityModel.Tokens.Jwt with issuer, audience,
  lifetime, algorithm, key type, kid and token-size validation.
- Legacy HS256 is migration-only; do not configure it unless the rollout explicitly needs it.
- Every BCrypt hash/verify goes through IPasswordHasher and its bounded queue.
- Preserve enumeration-resistant login/resend behavior, OTP/login/password rate limits and
  refresh-token compromise handling.
- Refresh tokens are random, hashed at rest, rotated and never returned publicly.
- Session refresh cannot pass absolute_expires_at; revocation must remain immediate.
- Internal REST uses the shared signing handler and Redis nonce store, fail-closed.
- Runtime DB access uses the auth-scoped role; DDL belongs in migrations.
- Never log passwords, hashes, OTPs, tokens, cookies, email-provider or DB secrets.

Run dotnet test fakebookAuth.sln and add negative tests for every auth/API change.
