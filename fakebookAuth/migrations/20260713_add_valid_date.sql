BEGIN;

ALTER TABLE fb.id_user
    ADD COLUMN IF NOT EXISTS valid_date timestamptz NULL;

COMMIT;
