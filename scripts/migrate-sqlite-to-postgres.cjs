const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const { Pool } = require("pg");
const { getPostgresConnectionOptions } = require("../server/postgres-config");
require("dotenv").config();

const repositoryRoot = path.resolve(__dirname, "..");
const sourcePath = path.resolve(process.env.SQLITE_SOURCE_PATH || path.join(repositoryRoot, "database", "everkind.db"));
const schemaPath = path.resolve(repositoryRoot, "database", "postgres", "001_initial_schema.sql");
const command = process.argv[2];
const supportedCommands = new Set(["generate-schema", "apply-schema", "copy-data", "verify", "migrate"]);

if (!supportedCommands.has(command)) {
    console.error("Usage: node scripts/migrate-sqlite-to-postgres.js <generate-schema|apply-schema|copy-data|verify|migrate>");
    process.exit(1);
}

const quoteIdentifier = (value) => `"${String(value).replace(/"/g, '""')}"`;
const openSqlite = () => new sqlite3.Database(sourcePath, sqlite3.OPEN_READONLY);
const sqliteAll = (db, sql, params = []) => new Promise((resolve, reject) => {
    db.all(sql, params, (error, rows) => error ? reject(error) : resolve(rows));
});
const sqliteGet = (db, sql, params = []) => new Promise((resolve, reject) => {
    db.get(sql, params, (error, row) => error ? reject(error) : resolve(row));
});
const closeSqlite = (db) => new Promise((resolve, reject) => {
    db.close((error) => error ? reject(error) : resolve());
});

const createPool = () => {
    if (!process.env.DATABASE_URL) {
        throw new Error("DATABASE_URL is required for this migration command.");
    }

    return new Pool(getPostgresConnectionOptions({
        max: 2,
        connectionTimeoutMillis: 10000,
    }));
};

const mapColumnType = (sqliteType) => {
    const normalized = String(sqliteType || "TEXT").toUpperCase();
    if (normalized.includes("INT")) return "integer";
    if (normalized.includes("REAL") || normalized.includes("FLOA") || normalized.includes("DOUB")) {
        return "double precision";
    }
    if (normalized.includes("BLOB")) return "bytea";
    return "text";
};

const mapDefault = (column) => {
    if (column.dflt_value === null || column.dflt_value === undefined) return "";
    const value = String(column.dflt_value);
    if (value.toUpperCase() === "CURRENT_TIMESTAMP" && mapColumnType(column.type) === "text") {
        return " DEFAULT (CURRENT_TIMESTAMP::text)";
    }
    return ` DEFAULT ${value}`;
};

const getSchemaMetadata = async (db) => {
    const tableRows = await sqliteAll(
        db,
        "SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    );
    const indexRows = await sqliteAll(
        db,
        "SELECT name, sql FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL ORDER BY name"
    );
    const tables = [];

    for (const tableRow of tableRows) {
        const tableName = tableRow.name;
        const quotedTable = quoteIdentifier(tableName);
        const columns = await sqliteAll(db, `PRAGMA table_info(${quotedTable})`);
        const foreignKeys = await sqliteAll(db, `PRAGMA foreign_key_list(${quotedTable})`);
        const indexes = await sqliteAll(db, `PRAGMA index_list(${quotedTable})`);
        const uniqueConstraints = [];
        for (const index of indexes.filter((item) => item.origin === "u")) {
            const indexColumns = await sqliteAll(db, `PRAGMA index_info(${quoteIdentifier(index.name)})`);
            uniqueConstraints.push(
                indexColumns
                    .sort((left, right) => Number(left.seqno) - Number(right.seqno))
                    .map((column) => column.name)
            );
        }
        const primaryKey = columns
            .filter((column) => Number(column.pk) > 0)
            .sort((left, right) => Number(left.pk) - Number(right.pk));
        const usesIdentity = primaryKey.length === 1
            && mapColumnType(primaryKey[0].type) === "integer"
            && /\bAUTOINCREMENT\b/i.test(tableRow.sql || "");

        tables.push({
            name: tableName,
            sql: tableRow.sql || "",
            columns,
            foreignKeys,
            primaryKey,
            uniqueConstraints,
            usesIdentity,
        });
    }

    return { tables, indexes: indexRows };
};

const compatibilitySql = `
CREATE OR REPLACE FUNCTION public.datetime(value text, VARIADIC modifiers text[])
RETURNS text
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    result_value timestamp without time zone;
    modifier text;
BEGIN
    IF lower(value) = 'now' THEN
        result_value := CURRENT_TIMESTAMP AT TIME ZONE 'UTC';
    ELSIF value ~ '(Z|[+-][0-9]{2}:[0-9]{2})$' THEN
        result_value := value::timestamptz AT TIME ZONE 'UTC';
    ELSE
        result_value := value::timestamp;
    END IF;

    FOREACH modifier IN ARRAY modifiers LOOP
        result_value := result_value + modifier::interval;
    END LOOP;

    RETURN to_char(result_value, 'YYYY-MM-DD HH24:MI:SS');
END;
$$;

CREATE OR REPLACE FUNCTION public.date(value text, VARIADIC modifiers text[])
RETURNS text
LANGUAGE sql
STABLE
AS $$
    SELECT split_part(public.datetime(value, VARIADIC modifiers), ' ', 1);
$$;

CREATE OR REPLACE FUNCTION public.datetime(value text)
RETURNS text
LANGUAGE sql
STABLE
AS $$
    SELECT public.datetime(value, VARIADIC ARRAY[]::text[]);
$$;

CREATE OR REPLACE FUNCTION public.date(value text)
RETURNS text
LANGUAGE sql
STABLE
AS $$
    SELECT public.date(value, VARIADIC ARRAY[]::text[]);
$$;
`;

const generateSchemaSql = async (db) => {
    const { tables, indexes } = await getSchemaMetadata(db);
    const statements = [
        "-- Generated from the canonical Everkind SQLite schema.",
        "-- Application tables are private to the server: no Data API grants or RLS policies are created.",
        "BEGIN;",
        compatibilitySql.trim(),
    ];

    for (const table of tables) {
        const definitions = table.columns.map((column) => {
            let definition = `${quoteIdentifier(column.name)} ${mapColumnType(column.type)}`;
            if (table.usesIdentity && Number(column.pk) === 1) {
                definition += " GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY";
            } else if (table.primaryKey.length === 1 && Number(column.pk) === 1) {
                definition += " PRIMARY KEY";
            }
            if (Number(column.notnull) === 1) definition += " NOT NULL";
            definition += mapDefault(column);
            if (table.name === "app_status" && column.name === "id") definition += " CHECK (id = 1)";
            return definition;
        });

        if (table.primaryKey.length > 1) {
            definitions.push(`PRIMARY KEY (${table.primaryKey.map((column) => quoteIdentifier(column.name)).join(", ")})`);
        }
        for (const uniqueConstraint of table.uniqueConstraints) {
            definitions.push(`UNIQUE (${uniqueConstraint.map(quoteIdentifier).join(", ")})`);
        }

        statements.push(
            `CREATE TABLE ${quoteIdentifier(table.name)} (\n    ${definitions.join(",\n    ")}\n);`
        );
    }

    for (const table of tables) {
        for (const foreignKey of table.foreignKeys) {
            const constraintName = `fk_${table.name}_${foreignKey.from}_${foreignKey.table}_${foreignKey.to}`;
            const onUpdate = foreignKey.on_update && foreignKey.on_update !== "NO ACTION"
                ? ` ON UPDATE ${foreignKey.on_update}`
                : "";
            const onDelete = foreignKey.on_delete && foreignKey.on_delete !== "NO ACTION"
                ? ` ON DELETE ${foreignKey.on_delete}`
                : "";
            statements.push(
                `ALTER TABLE ${quoteIdentifier(table.name)} ADD CONSTRAINT ${quoteIdentifier(constraintName)} `
                + `FOREIGN KEY (${quoteIdentifier(foreignKey.from)}) REFERENCES ${quoteIdentifier(foreignKey.table)} `
                + `(${quoteIdentifier(foreignKey.to)})${onUpdate}${onDelete};`
            );
        }
    }

    for (const index of indexes) {
        statements.push(`${String(index.sql).trim().replace(/;$/, "")};`);
    }

    for (const table of tables) {
        statements.push(`ALTER TABLE ${quoteIdentifier(table.name)} ENABLE ROW LEVEL SECURITY;`);
        statements.push(`REVOKE ALL ON TABLE ${quoteIdentifier(table.name)} FROM anon, authenticated;`);
    }

    statements.push(
        "REVOKE EXECUTE ON FUNCTION public.datetime(text, VARIADIC text[]) FROM PUBLIC, anon, authenticated;",
        "REVOKE EXECUTE ON FUNCTION public.date(text, VARIADIC text[]) FROM PUBLIC, anon, authenticated;",
        "REVOKE EXECUTE ON FUNCTION public.datetime(text) FROM PUBLIC, anon, authenticated;",
        "REVOKE EXECUTE ON FUNCTION public.date(text) FROM PUBLIC, anon, authenticated;",
        "COMMIT;",
        ""
    );

    return statements.join("\n\n");
};

const writeSchema = async () => {
    const db = openSqlite();
    try {
        const schemaSql = await generateSchemaSql(db);
        fs.mkdirSync(path.dirname(schemaPath), { recursive: true });
        fs.writeFileSync(schemaPath, schemaSql, "utf8");
        console.log(`Generated PostgreSQL schema for ${(await getSchemaMetadata(db)).tables.length} tables.`);
    } finally {
        await closeSqlite(db);
    }
};

const applySchema = async (pool) => {
    if (!fs.existsSync(schemaPath)) {
        throw new Error(`Schema migration does not exist at ${schemaPath}.`);
    }

    const existing = await pool.query(`
        SELECT COUNT(*)::integer AS count
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_type = 'BASE TABLE'
          AND table_name NOT LIKE 'pg_%'
    `);
    if (Number(existing.rows[0].count) !== 0) {
        throw new Error("Target public schema is not empty; schema migration stopped without making changes.");
    }

    await pool.query(fs.readFileSync(schemaPath, "utf8"));
    console.log("Applied PostgreSQL schema migration.");
};

const orderTables = (tables) => {
    const tableNames = new Set(tables.map((table) => table.name));
    const remaining = new Map(tables.map((table) => [table.name, table]));
    const ordered = [];

    while (remaining.size > 0) {
        const ready = [...remaining.values()].filter((table) =>
            table.foreignKeys.every((foreignKey) =>
                !tableNames.has(foreignKey.table) || !remaining.has(foreignKey.table)
            )
        );
        if (ready.length === 0) {
            throw new Error(`Unable to resolve table dependency order: ${[...remaining.keys()].join(", ")}`);
        }
        for (const table of ready) {
            ordered.push(table);
            remaining.delete(table.name);
        }
    }

    return ordered;
};

const copyData = async (pool) => {
    const db = openSqlite();
    const client = await pool.connect();
    try {
        const { tables } = await getSchemaMetadata(db);
        const orderedTables = orderTables(tables);
        await client.query("BEGIN");

        for (const table of orderedTables) {
            const targetCount = await client.query(`SELECT COUNT(*)::integer AS count FROM ${quoteIdentifier(table.name)}`);
            if (Number(targetCount.rows[0].count) !== 0) {
                throw new Error(`Target table ${table.name} is not empty; data migration stopped.`);
            }

            const sourceRows = await sqliteAll(db, `SELECT * FROM ${quoteIdentifier(table.name)}`);
            const columnNames = table.columns.map((column) => column.name);
            const columnSql = columnNames.map(quoteIdentifier).join(", ");
            const placeholders = columnNames.map((_, index) => `$${index + 1}`).join(", ");

            for (const row of sourceRows) {
                await client.query(
                    `INSERT INTO ${quoteIdentifier(table.name)} (${columnSql}) VALUES (${placeholders})`,
                    columnNames.map((columnName) => row[columnName])
                );
            }

            if (table.usesIdentity) {
                const idColumn = table.primaryKey[0].name;
                await client.query(`
                    SELECT setval(
                        pg_get_serial_sequence($1, $2),
                        COALESCE((SELECT MAX(${quoteIdentifier(idColumn)}) FROM ${quoteIdentifier(table.name)}), 1),
                        EXISTS(SELECT 1 FROM ${quoteIdentifier(table.name)})
                    )
                `, [`public.${table.name}`, idColumn]);
            }
        }

        await client.query("COMMIT");
        console.log(`Copied ${orderedTables.length} tables in one PostgreSQL transaction.`);
    } catch (error) {
        await client.query("ROLLBACK");
        throw error;
    } finally {
        client.release();
        await closeSqlite(db);
    }
};

const normalizeValue = (value) => {
    if (Buffer.isBuffer(value)) return { type: "buffer", value: value.toString("base64") };
    return value;
};

const hashRows = (rows, columnNames) => {
    const hash = crypto.createHash("sha256");
    const normalizedRows = rows
        .map((row) => JSON.stringify(columnNames.map((columnName) => normalizeValue(row[columnName]))))
        .sort();
    for (const row of normalizedRows) {
        hash.update(row);
        hash.update("\n");
    }
    return hash.digest("hex");
};

const verify = async (pool) => {
    const db = openSqlite();
    try {
        const integrity = await sqliteGet(db, "PRAGMA integrity_check");
        const foreignKeyViolations = await sqliteAll(db, "PRAGMA foreign_key_check");
        if (Object.values(integrity)[0] !== "ok" || foreignKeyViolations.length !== 0) {
            throw new Error("SQLite source integrity validation failed.");
        }

        const { tables } = await getSchemaMetadata(db);
        const results = [];
        for (const table of tables) {
            const columnNames = table.columns.map((column) => column.name);
            const sourceRows = await sqliteAll(db, `SELECT * FROM ${quoteIdentifier(table.name)}`);
            const targetRows = (await pool.query(`SELECT * FROM ${quoteIdentifier(table.name)}`)).rows;
            const sourceHash = hashRows(sourceRows, columnNames);
            const targetHash = hashRows(targetRows, columnNames);
            results.push({
                table: table.name,
                sourceRows: sourceRows.length,
                targetRows: targetRows.length,
                hashesMatch: sourceHash === targetHash,
            });
        }

        const failures = results.filter((result) =>
            result.sourceRows !== result.targetRows || !result.hashesMatch
        );
        if (failures.length > 0) {
            throw new Error(`Migration parity failed for: ${failures.map((failure) => failure.table).join(", ")}`);
        }

        console.log(JSON.stringify({
            verifiedTables: results.length,
            verifiedRows: results.reduce((total, result) => total + result.sourceRows, 0),
            contentHashesMatch: true,
        }));
    } finally {
        await closeSqlite(db);
    }
};

const main = async () => {
    if (command === "generate-schema") {
        await writeSchema();
        return;
    }

    const pool = createPool();
    try {
        if (command === "apply-schema" || command === "migrate") await applySchema(pool);
        if (command === "copy-data" || command === "migrate") await copyData(pool);
        if (command === "verify" || command === "migrate") await verify(pool);
    } finally {
        await pool.end();
    }
};

main().catch((error) => {
    console.error(`Migration failed: ${error.message}`);
    process.exit(1);
});
