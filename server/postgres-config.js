const fs = require("fs");
const path = require("path");

const defaultCaPath = path.join(__dirname, "..", "database", "postgres", "prod-ca-2021.crt");

const resolveCaPath = () => {
    const configuredPath = String(process.env.PGSSLROOTCERT || "").trim();
    if (configuredPath) {
        const resolvedPath = path.resolve(configuredPath);
        if (!fs.existsSync(resolvedPath)) {
            throw new Error(`PGSSLROOTCERT does not exist: ${resolvedPath}`);
        }
        return resolvedPath;
    }

    if (!fs.existsSync(defaultCaPath)) {
        throw new Error(`Supabase PostgreSQL CA certificate does not exist: ${defaultCaPath}`);
    }
    return defaultCaPath;
};

const getPostgresConnectionOptions = (overrides = {}) => ({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        ca: fs.readFileSync(resolveCaPath(), "utf8"),
        rejectUnauthorized: true,
    },
    ...overrides,
});

module.exports = {
    getPostgresConnectionOptions,
};
