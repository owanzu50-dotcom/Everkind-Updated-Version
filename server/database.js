const fs = require("fs");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const { Pool } = require("pg");
const { getPostgresConnectionOptions } = require("./postgres-config");
const { translatePostgresSql } = require("./sql-compat");

const postgresProviders = new Set(["postgres", "postgresql", "supabase"]);
const configuredProvider = String(process.env.DB_PROVIDER || process.env.DATABASE_MODE || "sqlite")
    .trim()
    .toLowerCase();
const isPostgres = postgresProviders.has(configuredProvider);
const dbPath = path.join(__dirname, "..", "database", "everkind.db");

const identityTables = new Set([
    "admin_users",
    "application_timeline",
    "applications",
    "appointments",
    "audit_events",
    "care_notes",
    "care_reviews",
    "client_accounts",
    "client_notifications",
    "client_password_resets",
    "client_service_requests",
    "mfa_challenges",
    "mfa_recovery_codes",
    "password_history",
    "patient_assignments",
    "patient_documents",
    "patients",
    "payroll_records",
    "payslip_email_log",
    "payslips",
    "permissions",
    "roles",
    "shift_attachments",
    "staff",
    "staff_documents",
    "staff_messages",
    "staff_notifications",
    "staff_password_resets",
    "staff_shift_reminders",
    "staff_shift_visit_notes",
    "staff_shifts",
    "staff_training",
    "subject_requests",
    "website_announcements",
    "website_jobs",
]);

let sqliteDatabase = null;
let postgresPool = null;

if (isPostgres) {
    if (!process.env.DATABASE_URL) {
        throw new Error("DATABASE_URL must be configured when DB_PROVIDER is PostgreSQL.");
    }

    postgresPool = new Pool(getPostgresConnectionOptions({
        max: Number(process.env.PG_POOL_MAX) || 10,
        idleTimeoutMillis: 30000,
        connectionTimeoutMillis: 10000,
    }));
    postgresPool.on("error", (error) => {
        console.error("Unexpected PostgreSQL pool error:", error.message);
    });
} else {
    const dbDir = path.dirname(dbPath);
    if (!fs.existsSync(dbDir)) {
        fs.mkdirSync(dbDir, { recursive: true });
    }

    sqliteDatabase = new sqlite3.Database(dbPath, (error) => {
        if (error) {
            console.error("Database connection error:", error.message);
            return;
        }

        console.log("Connected to SQLite database at", dbPath);
    });
}

const getInsertTable = (sql) => {
    const match = String(sql).match(/^\s*INSERT\s+(?:OR\s+\w+\s+)?INTO\s+["']?([a-zA-Z_][a-zA-Z0-9_]*)/i);
    return match ? match[1].toLowerCase() : null;
};

const runPostgresDb = (queryable, sql, params = []) => {
    let translated = translatePostgresSql(sql);
    const insertTable = getInsertTable(sql);
    if (insertTable && identityTables.has(insertTable) && !/\bRETURNING\b/i.test(translated)) {
        translated = `${translated.trim().replace(/;$/, "")} RETURNING id`;
    }

    return queryable.query(translated, params).then((result) => ({
        lastID: result.rows[0] ? result.rows[0].id : undefined,
        changes: result.rowCount,
    }));
};

const runDb = (sql, params = []) => {
    if (!isPostgres) {
        return new Promise((resolve, reject) => {
            sqliteDatabase.run(sql, params, function onRun(error) {
                if (error) {
                    reject(error);
                    return;
                }

                resolve(this);
            });
        });
    }

    return runPostgresDb(postgresPool, sql, params);
};

const getDb = (sql, params = []) => {
    if (!isPostgres) {
        return new Promise((resolve, reject) => {
            sqliteDatabase.get(sql, params, (error, row) => {
                if (error) {
                    reject(error);
                    return;
                }

                resolve(row);
            });
        });
    }

    return postgresPool.query(translatePostgresSql(sql), params)
        .then((result) => result.rows[0]);
};

const allDb = (sql, params = []) => {
    if (!isPostgres) {
        return new Promise((resolve, reject) => {
            sqliteDatabase.all(sql, params, (error, rows) => {
                if (error) {
                    reject(error);
                    return;
                }

                resolve(rows);
            });
        });
    }

    return postgresPool.query(translatePostgresSql(sql), params)
        .then((result) => result.rows);
};

const backupDatabase = (backupPath) => {
    if (isPostgres) {
        throw new Error("PostgreSQL backups are managed by Supabase and cannot be written as a local SQLite file.");
    }

    return new Promise((resolve, reject) => {
        const backup = sqliteDatabase.backup(backupPath);
        backup.step(-1, (stepError) => {
            backup.finish((finishError) => {
                const error = stepError || finishError;
                if (error) reject(error);
                else resolve();
            });
        });
    });
};

const withTransaction = async (callback) => {
    if (!isPostgres) {
        await runDb("BEGIN IMMEDIATE");
        try {
            const result = await callback({ runDb });
            await runDb("COMMIT");
            return result;
        } catch (error) {
            await runDb("ROLLBACK");
            throw error;
        }
    }

    const client = await postgresPool.connect();
    try {
        await client.query("BEGIN");
        const result = await callback({
            runDb: (sql, params = []) => runPostgresDb(client, sql, params),
        });
        await client.query("COMMIT");
        return result;
    } catch (error) {
        await client.query("ROLLBACK");
        throw error;
    } finally {
        client.release();
    }
};

const validateDatabase = async () => {
    if (!isPostgres) return;

    const result = await postgresPool.query(`
        SELECT to_regclass('public.app_status') AS app_status_table
    `);
    if (!result.rows[0] || result.rows[0].app_status_table !== "app_status") {
        throw new Error("PostgreSQL schema is not initialized. Run the Everkind database migration first.");
    }
};

module.exports = {
    allDb,
    backupDatabase,
    databaseLabel: isPostgres ? "Supabase PostgreSQL" : dbPath,
    dbPath,
    getDb,
    isPostgres,
    runDb,
    validateDatabase,
    withTransaction,
};
