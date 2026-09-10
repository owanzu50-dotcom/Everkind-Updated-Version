const test = require("node:test");
const assert = require("node:assert/strict");
const {
    expectedSupabaseProjectRef,
    requirePostgresRuntimeConfig,
} = require("./database-config");

const validEnvironment = {
    DATABASE_MODE: "postgres",
    DATABASE_URL: `postgresql://postgres.${expectedSupabaseProjectRef}:password@aws-1-eu-west-1.pooler.supabase.com:5432/postgres`,
    DB_PROVIDER: "postgres",
};

test("accepts only the configured Everkind Supabase PostgreSQL runtime", () => {
    const config = requirePostgresRuntimeConfig(validEnvironment);
    assert.equal(config.provider, "postgres");
    assert.equal(config.projectRef, expectedSupabaseProjectRef);
});

test("accepts the Everkind direct Supabase database host", () => {
    const config = requirePostgresRuntimeConfig({
        ...validEnvironment,
        DATABASE_URL: `postgresql://postgres:password@db.${expectedSupabaseProjectRef}.supabase.co:5432/postgres`,
    });
    assert.equal(config.projectRef, expectedSupabaseProjectRef);
});

test("fails closed when provider selection is absent or inconsistent", () => {
    assert.throws(
        () => requirePostgresRuntimeConfig({ ...validEnvironment, DB_PROVIDER: "" }),
        /must both be set to 'postgres'/
    );
    assert.throws(
        () => requirePostgresRuntimeConfig({ ...validEnvironment, DATABASE_MODE: "sqlite" }),
        /SQLite is not a runtime fallback/
    );
});

test("fails closed for missing, invalid, or non-Supabase connection URLs", () => {
    assert.throws(
        () => requirePostgresRuntimeConfig({ ...validEnvironment, DATABASE_URL: "" }),
        /DATABASE_URL must be configured/
    );
    assert.throws(
        () => requirePostgresRuntimeConfig({ ...validEnvironment, DATABASE_URL: "not-a-url" }),
        /valid PostgreSQL connection URL/
    );
    assert.throws(
        () => requirePostgresRuntimeConfig({ ...validEnvironment, DATABASE_URL: "postgresql://localhost/everkind" }),
        new RegExp(expectedSupabaseProjectRef)
    );
});

test("fails closed when a different Supabase project is configured", () => {
    assert.throws(
        () => requirePostgresRuntimeConfig({
            ...validEnvironment,
            DATABASE_URL: "postgresql://postgres.otherproject:password@aws-1-eu-west-1.pooler.supabase.com:5432/postgres",
        }),
        new RegExp(expectedSupabaseProjectRef)
    );
});

test("does not accept the expected project reference in an unrelated URL component", () => {
    assert.throws(
        () => requirePostgresRuntimeConfig({
            ...validEnvironment,
            DATABASE_URL: `postgresql://postgres:${expectedSupabaseProjectRef}@db.otherproject.supabase.co:5432/postgres`,
        }),
        new RegExp(expectedSupabaseProjectRef)
    );
    assert.throws(
        () => requirePostgresRuntimeConfig({
            ...validEnvironment,
            DATABASE_URL: `postgresql://postgres.otherproject:password@aws-1-eu-west-1.pooler.supabase.com:5432/${expectedSupabaseProjectRef}`,
        }),
        new RegExp(expectedSupabaseProjectRef)
    );
});
