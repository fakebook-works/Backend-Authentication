BEGIN;

DO $migration$
BEGIN
    IF to_regnamespace('auth') IS NOT NULL THEN
        IF to_regnamespace('fb') IS NOT NULL THEN
            RAISE EXCEPTION 'Cannot rename schema fb to auth because both schemas exist.';
        END IF;

        RETURN;
    END IF;

    IF to_regnamespace('fb') IS NULL THEN
        RAISE EXCEPTION 'Cannot rename schema fb to auth because schema fb does not exist.';
    END IF;

    EXECUTE 'ALTER SCHEMA fb RENAME TO auth';
END
$migration$;

COMMIT;
