const assert = require("node:assert/strict");
const test = require("node:test");

const {
    ROLE_DEFINITIONS,
    getFallbackPermissionsForRole,
    getRequiredPermission,
    hasPermission,
} = require("./rbac");

test("Super Admin receives every defined permission", () => {
    const permissions = getFallbackPermissionsForRole("super_admin");

    for (const permission of ROLE_DEFINITIONS.super_admin.permissions) {
        assert.equal(hasPermission(permissions, permission), true);
    }
});

test("system roles enforce their intended module boundaries", () => {
    const hr = getFallbackPermissionsForRole("hr");
    const payroll = getFallbackPermissionsForRole("payroll");
    const manager = getFallbackPermissionsForRole("manager");

    assert.equal(hasPermission(hr, "recruitment.manage"), true);
    assert.equal(hasPermission(hr, "staff.edit"), true);
    assert.equal(hasPermission(hr, "staff.approve"), true);
    assert.equal(hasPermission(hr, "payroll.view"), false);
    assert.equal(hasPermission(hr, "users.manage"), false);
    assert.equal(hasPermission(hr, "security.view"), false);

    assert.equal(hasPermission(payroll, "payroll.approve"), true);
    assert.equal(hasPermission(payroll, "payslips.manage"), true);
    assert.equal(hasPermission(payroll, "recruitment.view"), false);
    assert.equal(hasPermission(payroll, "security.manage"), false);

    assert.equal(hasPermission(manager, "scheduling.approve"), true);
    assert.equal(hasPermission(manager, "clients.edit"), true);
    assert.equal(hasPermission(manager, "clients.export"), true);
    assert.equal(hasPermission(manager, "live_tracking.create"), true);
    assert.equal(hasPermission(manager, "payroll.view"), false);
    assert.equal(hasPermission(manager, "users.manage"), false);
});

test("existing portal and API routes map to module and action permissions", () => {
    const cases = [
        ["GET", "/portal/applications", "recruitment.view"],
        ["POST", "/portal/applications/42/hire", "recruitment.approve"],
        ["GET", "/staff", "staff.view"],
        ["GET", "/portal/shifts", "scheduling.view"],
        ["GET", "/api/staff/shifts", "scheduling.view"],
        ["POST", "/api/staff/shifts/42/clock-in", "scheduling.edit"],
        ["POST", "/api/staff/shifts/42/clock-out", "scheduling.edit"],
        ["GET", "/portal/events", "dashboard.view"],
        ["PATCH", "/api/shifts/42", "scheduling.edit"],
        ["GET", "/calendar", "scheduling.view"],
        ["GET", "/api/patients", "clients.view"],
        ["GET", "/portal/client-portal", "facilities.view"],
        ["POST", "/portal/client-requests/42/status", "facilities.edit"],
        ["GET", "/api/dashboard", "dashboard.view"],
        ["GET", "/admin/hr-dashboard", "dashboard.view"],
        ["GET", "/admin/training", "compliance.view"],
        ["GET", "/portal/security/mfa", "security.view"],
        ["POST", "/portal/security/password", "security.view"],
        ["GET", "/admin/payroll/export", "payroll.export"],
        ["POST", "/api/admin/payroll/42/approve", "payroll.approve"],
        ["GET", "/admin/payroll/payslip/42/download", "payslips.export"],
        ["POST", "/admin/settings/users/42/reset-access", "users.edit"],
        ["POST", "/admin/settings/general/security", "security.manage"],
        ["POST", "/api/compliance/retention/run", "system.manage"],
    ];

    for (const [method, path, expected] of cases) {
        assert.equal(getRequiredPermission(method, path), expected, `${method} ${path}`);
    }
});

test("unknown protected routes fail closed", () => {
    assert.equal(getRequiredPermission("GET", "/admin/unmapped-sensitive-feature"), "system.manage");
});
