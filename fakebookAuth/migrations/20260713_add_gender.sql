BEGIN;

ALTER TABLE fb.id_user
    ADD COLUMN IF NOT EXISTS gender boolean;

COMMIT;
