const ACTIONS = ["view", "create", "edit", "delete", "approve", "export", "manage"];

const MODULES = {
    dashboard: "Dashboard",
    recruitment: "Recruitment & Applications",
    staff: "Staff",
    clients: "Clients & Home Care",
    facilities: "Healthcare Facilities",
    scheduling: "Scheduling & Shifts",
    attendance: "Attendance",
    live_tracking: "Live Tracking",
    compliance: "Compliance, Documents & Training",
    care_reviews: "Care Reviews",
    payroll: "Payroll",
    payslips: "Payslips",
    reports: "Reports",
    settings: "Settings",
    users: "Users",
    roles: "Roles & Permissions",
    security: "Security",
    audit: "Audit Logs",
    system: "System Configuration",
};

const permissionKey = (moduleKey, action) => `${moduleKey}.${action}`;
const allPermissions = Object.keys(MODULES).flatMap((moduleKey) =>
    ACTIONS.map((action) => permissionKey(moduleKey, action))
);

const permissionSet = (...entries) => [...new Set(entries.flat())];
const modulePermissions = (moduleKey, actions = ACTIONS) =>
    actions.map((action) => permissionKey(moduleKey, action));

const ROLE_DEFINITIONS = {
    super_admin: {
        label: "Super Admin",
        description: "Complete access to administration, security, financial, and operational controls.",
        permissions: allPermissions,
    },
    hr: {
        label: "HR",
        description: "Recruitment, onboarding, staff records, training, and HR compliance.",
        permissions: permissionSet(
            modulePermissions("dashboard", ["view"]),
            modulePermissions("recruitment"),
            modulePermissions("staff", ["view", "create", "edit", "approve", "export"]),
            modulePermissions("attendance", ["view"]),
            modulePermissions("compliance", ["view", "create", "edit", "approve", "export"]),
            modulePermissions("reports", ["view", "export"])
        ),
    },
    payroll: {
        label: "Payroll",
        description: "Approved hours, payroll calculations, rates, periods, payslips, and payroll reporting.",
        permissions: permissionSet(
            modulePermissions("dashboard", ["view"]),
            modulePermissions("staff", ["view"]),
            modulePermissions("attendance", ["view", "export"]),
            modulePermissions("payroll"),
            modulePermissions("payslips"),
            modulePermissions("reports", ["view", "export"]),
            modulePermissions("settings", ["view"])
        ),
    },
    manager: {
        label: "Manager",
        description: "Operational staff, client, facility, scheduling, attendance, and live-tracking access.",
        permissions: permissionSet(
            modulePermissions("dashboard", ["view"]),
            modulePermissions("staff", ["view", "edit"]),
            modulePermissions("clients", ["view", "create", "edit", "approve", "export"]),
            modulePermissions("facilities", ["view", "create", "edit", "approve"]),
            modulePermissions("scheduling"),
            modulePermissions("attendance", ["view", "edit", "approve", "export"]),
            modulePermissions("live_tracking", ["view", "create"]),
            modulePermissions("compliance", ["view"]),
            modulePermissions("care_reviews", ["view", "create", "edit", "approve"]),
            modulePermissions("reports", ["view", "export"])
        ),
    },
};

const routeRules = [
    { pattern: /^\/portal\/security(?:\/|$)/, module: "security", fixedAction: "view" },
    { pattern: /^\/admin\/view-as(?:\/|$)/, module: "users", fixedAction: "manage" },
    { pattern: /^\/admin\/settings\/users(?:\/|$)/, module: "users" },
    { pattern: /^\/admin\/settings\/roles(?:\/|$)/, module: "roles" },
    { pattern: /^\/admin\/settings\/security(?:\/|$)/, module: "security" },
    { pattern: /^\/admin\/settings\/system(?:\/|$)/, module: "system" },
    { pattern: /^\/admin\/settings\/audit(?:\/|$)/, module: "audit" },
    { pattern: /^\/admin\/settings\/general\/security(?:\/|$)/, module: "security", fixedAction: "manage" },
    { pattern: /^\/admin\/settings\/general\/payroll(?:\/|$)/, module: "payroll", fixedAction: "manage" },
    { pattern: /^\/admin\/settings\/payroll(?:\/|$)/, module: "payroll", fixedAction: "manage" },
    { pattern: /^\/(?:api\/admin\/)?settings(?:\/|$)/, module: "settings" },
    { pattern: /^\/api\/admin\/settings(?:\/|$)/, module: "settings" },
    { pattern: /^\/admin\/settings(?:\/|$)/, module: "settings" },
    { pattern: /^\/(?:admin\/)?payroll\/payslips(?:\/|$)/, module: "payslips" },
    { pattern: /^\/admin\/payroll\/payslips(?:\/|$)/, module: "payslips" },
    { pattern: /\/payslip/i, module: "payslips" },
    { pattern: /\/payroll/i, module: "payroll" },
    { pattern: /\/applications?(?:\/|$)/i, module: "recruitment" },
    { pattern: /^\/api\/staff\/shifts(?:\/|$)/, module: "scheduling" },
    { pattern: /^\/portal\/shifts(?:\/|$)/, module: "scheduling" },
    { pattern: /^\/portal\/events(?:\/|$)/, module: "dashboard" },
    { pattern: /^\/(?:api\/(?:admin\/)?)?staff(?:\/|$)/, module: "staff" },
    { pattern: /^\/(?:api\/)?patients?(?:\/|$)/, module: "clients" },
    { pattern: /\/home-care-clients?(?:\/|$)/, module: "clients" },
    { pattern: /\/home-visits?(?:\/|$)/, module: "clients" },
    { pattern: /\/care-reviews?(?:\/|$)/, module: "care_reviews" },
    { pattern: /\/(?:client|facility)-portal(?:\/|$)/, module: "facilities" },
    { pattern: /\/client-(?:accounts|requests)(?:\/|$)/, module: "facilities" },
    { pattern: /\/facilit(?:y|ies)(?:\/|$)/, module: "facilities" },
    { pattern: /\/shift-requests?(?:\/|$)/, module: "scheduling" },
    { pattern: /\/open-shifts?(?:\/|$)/, module: "scheduling" },
    { pattern: /\/schedule(?:\/|$)/, module: "scheduling" },
    { pattern: /^\/(?:api|admin)\/shifts?(?:\/|$)/, module: "scheduling" },
    { pattern: /^\/calendar(?:\/|$)/, module: "scheduling" },
    { pattern: /\/live-tracking(?:\/|$)/, module: "live_tracking" },
    { pattern: /\/attendance(?:\/|$)/, module: "attendance" },
    { pattern: /^\/api\/compliance\/(?:patients|retention)(?:\/|$)/, module: "system", fixedAction: "manage" },
    { pattern: /\/compliance(?:\/|$)/, module: "compliance" },
    { pattern: /\/(?:documents|training|onboarding)(?:\/|$)/, module: "compliance" },
    { pattern: /\/reports?(?:\/|$)/, module: "reports" },
    { pattern: /\/(?:website-content|api-keys|database)(?:\/|$)/, module: "system", fixedAction: "manage" },
    { pattern: /^\/admin\/hr-dashboard(?:\/|$)/, module: "dashboard", fixedAction: "view" },
    { pattern: /^\/(?:api\/)?(?:admin|portal)?\/?dashboard(?:\/|$)/, module: "dashboard" },
];

const inferAction = (method, requestPath) => {
    const normalizedMethod = String(method || "GET").toUpperCase();
    const path = String(requestPath || "").toLowerCase();

    if (/(?:\/|^)(?:export|download)(?:\/|$)/.test(path)) return "export";
    if (/(?:\/|^)(?:approve|complete|assign|mark-paid|hire|claim)(?:\/|$)/.test(path)) return "approve";
    if (/(?:\/|^)(?:delete|remove)(?:\/|$)/.test(path) || normalizedMethod === "DELETE") return "delete";
    if (normalizedMethod === "GET" || normalizedMethod === "HEAD") return "view";
    if (normalizedMethod === "PATCH" || normalizedMethod === "PUT") return "edit";
    if (/(?:\/|^)(?:edit|update|status|revert|toggle|reset-access)(?:\/|$)/.test(path)) return "edit";
    if (/\/\d+(?:\/|$)/.test(path)) return "edit";
    return "create";
};

const getRequiredPermission = (method, requestPath) => {
    const path = String(requestPath || "");
    const rule = routeRules.find((candidate) => candidate.pattern.test(path));
    if (!rule) return permissionKey("system", "manage");
    return permissionKey(rule.module, rule.fixedAction || inferAction(method, path));
};

const getFallbackPermissionsForRole = (roleKey) =>
    new Set((ROLE_DEFINITIONS[roleKey] || { permissions: [] }).permissions);

const hasPermission = (permissions, requiredPermission) =>
    permissions instanceof Set && permissions.has(requiredPermission);

module.exports = {
    ACTIONS,
    MODULES,
    ROLE_DEFINITIONS,
    allPermissions,
    getFallbackPermissionsForRole,
    getRequiredPermission,
    hasPermission,
    modulePermissions,
    permissionKey,
};
