-- Indexes for the sign-in path, and removal of two that duplicate existing constraints.
--
-- WHY
--
-- auth.id_credential had no index whatsoever beyond its primary key on credential_id —
-- confirmed against the live database, where id_credential_pkey is the only one present.
-- FindPasswordCredentialAsync runs on every single sign-in:
--   WHERE user_id = ? AND provider = ? ORDER BY created_at DESC LIMIT 1
-- so each login scanned the table.
--
-- auth.id_verification was indexed only on token_hash, which serves OTP submission but
-- not the resend and password-reset paths, which look up by (user_id, type).
--
-- Two indexes duplicate constraints that PostgreSQL already backs with an index:
--   id_user_email_idx              btree (email)      alongside
--   id_user_email_key       UNIQUE btree (email)      from the UNIQUE constraint
--   id_session_refresh_token_replaced_idx  btree (token_hash) WHERE replaced_at IS NOT NULL
--   id_session_refresh_token_pkey   UNIQUE btree (token_hash)
-- The partial index is on that table's primary key column, and the only query reading
-- replaced_at also filters on token_hash, so the primary key already serves it. Both cost
-- write time and space and can never be preferred.
--
-- HOW TO APPLY
--
--   psql "$CONNECTION" -v ON_ERROR_STOP=1 -f 20260727_add_login_path_indexes.sql
--
-- Wrapped in a transaction and idempotent, matching the other migrations here. See
-- SocialGraph's 20260727_add_hot_path_indexes.sql for the CONCURRENTLY variant to use if
-- these tables ever grow large enough for the build lock to matter.

BEGIN;

-- Every sign-in resolves the newest password credential for a user.
CREATE INDEX IF NOT EXISTS id_credential_user_provider_idx
    ON auth.id_credential (user_id, provider, created_at DESC);

-- OTP resend and password reset look up the newest verification of a given type.
CREATE INDEX IF NOT EXISTS id_verification_user_type_time_idx
    ON auth.id_verification (user_id, type, created_at DESC);

-- Duplicates the UNIQUE constraint's index on id_user.email.
DROP INDEX IF EXISTS auth.id_user_email_idx;

-- Partial index on the primary key column of id_session_refresh_token.
DROP INDEX IF EXISTS auth.id_session_refresh_token_replaced_idx;

COMMIT;
