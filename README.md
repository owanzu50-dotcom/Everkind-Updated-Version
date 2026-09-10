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

## Render test deployment

The repository includes `render.yaml` for a free Render Web Service in
Frankfurt, close to the Supabase Ireland region. The Blueprint installs
dependencies with `npm ci`, starts the application with `npm start`, and checks
`/api/health`.

Create a new Render Blueprint from this repository and provide these secret
values when prompted:

- `DATABASE_URL`: the existing Everkind Supabase session-pooler URL.
- `ADMIN_EMAIL` and `ADMIN_PASSWORD`: the same administrator credentials used
  by the current application.
- `STAFF_EMAIL` and `STAFF_PASSWORD`: the same default staff credentials used
  by the current application.
- `MFA_ENCRYPTION_KEY`: the current MFA encryption key. If the local
  environment does not define a separate value, use its current
  `SESSION_SECRET` so existing encrypted MFA records remain readable.

Render generates a new `SESSION_SECRET`. Never copy any secret into
`render.yaml` or commit it to Git.

The free service sleeps after inactivity and has an ephemeral filesystem.
Database records remain in Supabase, but locally generated files such as
payslip PDFs do not persist across service restarts. In-memory login sessions
also reset when the service restarts. Use the free deployment only for testing
with non-sensitive data.
