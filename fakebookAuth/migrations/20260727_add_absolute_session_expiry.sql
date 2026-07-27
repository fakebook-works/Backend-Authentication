BEGIN;

-- Sliding refresh-token rotation must never extend a stolen session forever. Existing
-- sessions receive the same 90-day absolute lifetime used by the service default, measured
-- from their original creation time rather than from deployment time.
ALTER TABLE auth.id_session
    ADD COLUMN IF NOT EXISTS absolute_expires_at timestamptz;

UPDATE auth.id_session
SET absolute_expires_at = created_at + interval '90 days'
WHERE absolute_expires_at IS NULL;

ALTER TABLE auth.id_session
    ALTER COLUMN absolute_expires_at SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'ck_id_session_absolute_expiry'
          AND conrelid = 'auth.id_session'::regclass
    ) THEN
        ALTER TABLE auth.id_session
            ADD CONSTRAINT ck_id_session_absolute_expiry
            CHECK (absolute_expires_at >= created_at) NOT VALID;
    END IF;
END
$$;

ALTER TABLE auth.id_session
    VALIDATE CONSTRAINT ck_id_session_absolute_expiry;

COMMIT;
