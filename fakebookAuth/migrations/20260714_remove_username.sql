BEGIN;

DROP INDEX IF EXISTS fb.id_user_username_idx;

ALTER TABLE fb.id_user
    DROP COLUMN IF EXISTS username;

COMMIT;
