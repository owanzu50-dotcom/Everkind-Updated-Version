const expectedSupabaseProjectRef = "mkblnunoajgvbpcmylll";

const requirePostgresRuntimeConfig = (environment = process.env) => {
    const provider = String(environment.DB_PROVIDER || "").trim().toLowerCase();
    const mode = String(environment.DATABASE_MODE || "").trim().toLowerCase();
    const databaseUrl = String(environment.DATABASE_URL || "").trim();

    if (provider !== "postgres" || mode !== "postgres") {
        throw new Error("DB_PROVIDER and DATABASE_MODE must both be set to 'postgres'. SQLite is not a runtime fallback.");
    }
    if (!databaseUrl) {
        throw new Error("DATABASE_URL must be configured for the Everkind Supabase PostgreSQL database.");
    }

    let parsedUrl;
    try {
        parsedUrl = new URL(databaseUrl);
    } catch {
        throw new Error("DATABASE_URL must be a valid PostgreSQL connection URL.");
    }

    if (!["postgres:", "postgresql:"].includes(parsedUrl.protocol)) {
        throw new Error("DATABASE_URL must use the PostgreSQL protocol.");
    }
    const directHost = `db.${expectedSupabaseProjectRef}.supabase.co`;
    const poolerUsername = `postgres.${expectedSupabaseProjectRef}`;
    const targetsDirectProject = parsedUrl.hostname === directHost
        && decodeURIComponent(parsedUrl.username) === "postgres";
    const targetsPoolerProject = parsedUrl.hostname.endsWith(".pooler.supabase.com")
        && decodeURIComponent(parsedUrl.username) === poolerUsername;
    const targetsExpectedProject = targetsDirectProject || targetsPoolerProject;
    if (!targetsExpectedProject) {
        throw new Error(`DATABASE_URL must target Supabase project ${expectedSupabaseProjectRef}.`);
    }

    return {
        databaseUrl,
        projectRef: expectedSupabaseProjectRef,
        provider,
    };
};

module.exports = {
    expectedSupabaseProjectRef,
    requirePostgresRuntimeConfig,
};
