const { Pool } = require("pg");
const { requirePostgresRuntimeConfig } = require("./database-config");
const { getPostgresConnectionOptions } = require("./postgres-config");
const { translatePostgresSql } = require("./sql-compat");

requirePostgresRuntimeConfig();

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

const postgresPool = new Pool(getPostgresConnectionOptions({
    max: Number(process.env.PG_POOL_MAX) || 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000,
}));
postgresPool.on("error", (error) => {
    console.error("Unexpected PostgreSQL pool error:", error.message);
});

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
    return runPostgresDb(postgresPool, sql, params);
};

const getDb = (sql, params = []) => postgresPool.query(translatePostgresSql(sql), params)
    .then((result) => result.rows[0]);

const allDb = (sql, params = []) => postgresPool.query(translatePostgresSql(sql), params)
    .then((result) => result.rows);

const backupDatabase = () => {
    throw new Error("PostgreSQL backups are managed by Supabase. Local SQLite backups are disabled.");
};

const withTransaction = async (callback) => {
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
    databaseLabel: "Supabase PostgreSQL",
    getDb,
    runDb,
    validateDatabase,
    withTransaction,
};
