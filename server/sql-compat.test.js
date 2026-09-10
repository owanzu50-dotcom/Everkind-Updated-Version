const test = require("node:test");
const assert = require("node:assert/strict");
const { replacePlaceholders, translatePostgresSql } = require("./sql-compat");

test("replaces parameters without changing quoted question marks", () => {
    assert.equal(
        replacePlaceholders("SELECT '?' AS literal, value FROM settings WHERE key = ? AND note = 'it''s ?'"),
        "SELECT '?' AS literal, value FROM settings WHERE key = $1 AND note = 'it''s ?'"
    );
});

test("translates SQLite conflict and aggregate syntax", () => {
    assert.equal(
        translatePostgresSql("INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)"),
        "INSERT INTO role_permissions (role_id, permission_id) VALUES ($1, $2) ON CONFLICT DO NOTHING"
    );
    assert.equal(
        translatePostgresSql("SELECT GROUP_CONCAT(permission_key, ',') FROM permissions"),
        "SELECT STRING_AGG(permission_key, ',') FROM permissions"
    );
});

test("routes SQLite date functions through compatibility functions", () => {
    assert.equal(
        translatePostgresSql("SELECT * FROM shifts WHERE date(start) = date(?) AND datetime(end) > datetime('now')"),
        "SELECT * FROM shifts WHERE public.date(start) = public.date($1) AND public.datetime(end) > public.datetime('now')"
    );
});

test("preserves the two legacy mixed-case patient columns", () => {
    assert.equal(
        translatePostgresSql("SELECT carePlan, nextVisit FROM patients WHERE carePlan IS NOT NULL"),
        'SELECT "carePlan", "nextVisit" FROM patients WHERE "carePlan" IS NOT NULL'
    );
});
