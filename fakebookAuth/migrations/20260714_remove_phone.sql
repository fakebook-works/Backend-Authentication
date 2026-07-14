BEGIN;

DROP INDEX IF EXISTS fb.id_user_phone_idx;

ALTER TABLE fb.id_user
    DROP COLUMN IF EXISTS phone;

COMMIT;
