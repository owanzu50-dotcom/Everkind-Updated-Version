# Everkind Care System

## Database runtime

Everkind uses the Supabase PostgreSQL project `mkblnunoajgvbpcmylll` in West EU
(Ireland, `eu-west-1`) as its only application runtime database.

The server requires all of the following:

```text
DB_PROVIDER=postgres
DATABASE_MODE=postgres
DATABASE_URL=<Everkind Supabase PostgreSQL URL>
```

Startup fails if PostgreSQL configuration is missing, invalid, points to another
project, or PostgreSQL cannot be reached. The application does not fall back to
SQLite.

`database/everkind.db` is intentionally excluded from Git and retained only as
an offline rollback and legacy migration artifact. It is not an application
runtime database. The `sqlite3` package is a development dependency used only by
the one-time migration and parity-verification script.

Supabase manages database backups. Confirm scheduled backups and restoration in
the Supabase dashboard before removing any offline rollback artifact.

### Remaining SQLite references

- `scripts/migrate-sqlite-to-postgres.cjs`: migration and parity tooling only.
- `server/sql-compat.js` and its tests: PostgreSQL translations for legacy query
  syntax; these do not open SQLite.
- `blockedLegacySqliteInitializer` in `server/app.js`: unused legacy schema
  reference retained for migration provenance; it is never called by startup.
- `sqlite3` development dependency: required only by migration tooling.
- `database/everkind.db`: offline rollback artifact, ignored by Git.

The runtime database adapter contains no SQLite import, connection, read, write,
or automatic fallback path.