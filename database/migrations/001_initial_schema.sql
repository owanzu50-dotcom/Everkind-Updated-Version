-- Initial Supabase/PostgreSQL migration.
-- Run this file after connecting the app to a PostgreSQL database.

BEGIN;

\i ../supabase_schema.sql;

COMMIT;
