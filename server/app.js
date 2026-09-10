require("dotenv").config();
const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const path = require("path");
const https = require("https");
const fs = require("fs");
const bcrypt = require("bcrypt");
const PDFDocument = require("pdfkit");
const nodemailer = require("nodemailer");
const QRCode = require("qrcode");
const {
    allDb,
    backupDatabase,
    databaseLabel,
    dbPath,
    getDb,
    isPostgres,
    runDb,
    validateDatabase,
    withTransaction,
} = require("./database");
const { createMfaSecurity, maskEmail, maskPhone } = require("./mfa");
const {
    ACTIONS: RBAC_ACTIONS,
    MODULES: RBAC_MODULES,
    ROLE_DEFINITIONS,
    allPermissions,
    getFallbackPermissionsForRole,
    getRequiredPermission,
    hasPermission,
} = require("./rbac");

const app = express();
const preferredPort = Number(process.env.PORT) || 3000;
const sessionSecret = process.env.SESSION_SECRET || "everkind-care-system-secret";
const adminEmail = process.env.ADMIN_EMAIL || "admin@everkind.com";
const adminPassword = process.env.ADMIN_PASSWORD || "everkind2026";
const staffDefaultEmail = process.env.STAFF_EMAIL || "staff@everkind.com";
const staffDefaultPassword = process.env.STAFF_PASSWORD || "everkindstaff";
const isProduction = process.env.NODE_ENV === "production";
const trustProxy = process.env.TRUST_PROXY === "1";

// Payslip / email constants
const smtpHost = process.env.SMTP_HOST || "";
const smtpPort = Number(process.env.SMTP_PORT) || 587;
const smtpUser = process.env.SMTP_USER || "";
const smtpPass = process.env.SMTP_PASS || "";
const smtpFrom = process.env.SMTP_FROM || "payroll@everkind.ie";
const twilioAccountSid = process.env.TWILIO_ACCOUNT_SID || "";
const twilioAuthToken = process.env.TWILIO_AUTH_TOKEN || "";
const twilioFromNumber = process.env.TWILIO_FROM_NUMBER || "";
const companyName = process.env.COMPANY_NAME || "Everkind Home Care Ltd";
const companyReg = process.env.COMPANY_REG || "";
const companyErn = process.env.COMPANY_ERN || "";
const companyAddress = process.env.COMPANY_ADDRESS || "Dublin, Ireland";
const companyPhone = process.env.COMPANY_PHONE || "";
const companyEmail = process.env.COMPANY_EMAIL || "payroll@everkind.ie";
const companyWebsite = process.env.COMPANY_WEBSITE || "www.everkind.ie";
const payslipsDir = path.join(__dirname, "..", "uploads", "payslips");
const defaultPublicPhone = "+353 89 985 9907";
const defaultPublicEmail = "Everkind@outlook.ie";
const mfaSecurity = createMfaSecurity({
    encryptionSecret: process.env.MFA_ENCRYPTION_KEY || (isProduction ? "" : sessionSecret),
    issuer: companyName,
});
const mfaChallengeLifetimeMinutes = 10;
const mfaChallengeAttemptLimit = 5;
const mfaResendDelaySeconds = 60;

const loginAttemptWindowMs = 15 * 60 * 1000;
const maxLoginAttemptsPerWindow = 5;
const loginAttempts = new Map();
const defaultPatientRetentionDays = 2190;

const parseRetentionDays = (rawValue) => {
    const parsed = Number(rawValue);
    if (!Number.isInteger(parsed) || parsed < 30 || parsed > 3650) {
        return null;
    }

    return parsed;
};

const legalBasisOptions = new Set(["care_contract", "consent", "legal_obligation", "vital_interest"]);
const consentStatusOptions = new Set(["pending", "granted", "withdrawn", "not_required"]);
const patientStatusOptions = [
    "Active",
    "Scheduled Visit",
    "Visit In Progress",
    "Visit Completed",
    "At Home",
    "In Hospital",
    "On Holiday",
    "Temporarily Suspended",
    "Awaiting Assessment",
    "Discharged",
    "End of Life Care",
    "Deceased",
    "Archived",
];
const careTeamRoles = [
    { key: "primaryCareAssistant", label: "Primary Care Assistant" },
    { key: "secondaryCareAssistant", label: "Secondary Care Assistant" },
    { key: "backupCareAssistant", label: "Backup Care Assistant" },
    { key: "assignedNurse", label: "Assigned Nurse" },
    { key: "assignedCnm", label: "Assigned CNM" },
];
const careNeedCatalog = {
    personalCare: ["Shower Assistance", "Bath Assistance", "Bed Bath", "Washing", "Dressing", "Grooming", "Oral Hygiene", "Toileting", "Continence Care", "Catheter Care", "Stoma Care"],
    mobility: ["Independent", "Mobility Assistance", "Walking Stick", "Walking Frame", "Rollator", "Wheelchair", "Hoist Required", "Standing Aid", "Two Carers Required", "Bed Bound", "Transfer Assistance", "Fall Prevention", "Pressure Area Care"],
    clinicalTasks: ["Medication Prompt", "Medication Administration", "Blood Pressure Monitoring", "Blood Sugar Monitoring", "Insulin Administration", "PEG Feeding", "Oxygen Therapy", "Nebuliser", "Wound Dressing", "Compression Stockings"],
    medicalConditions: ["Dementia Support", "Alzheimer's Disease", "Parkinson's Disease", "Stroke Recovery", "Post Surgery Recovery", "Diabetes", "COPD", "Heart Failure", "Arthritis", "Osteoporosis", "Epilepsy", "Multiple Sclerosis", "Motor Neurone Disease", "Autism", "Learning Disability", "Anxiety", "Depression", "Mental Health Support", "Palliative Care", "End of Life Care"],
    dailyLiving: ["Meal Preparation", "Feeding Assistance", "Hydration Monitoring", "Shopping", "Housekeeping", "Laundry", "Companionship", "Escort to Medical Appointments", "Community Outings", "Overnight Care", "Live-In Care", "Respite Care"],
    risks: ["Falls Risk", "Wandering Risk", "Aggressive Behaviour", "Choking Risk", "Pressure Ulcer Risk", "Smoking Risk", "Infection Control Precautions", "Allergy Alert"],
    communication: ["English Speaking", "Interpreter Required", "Hearing Aid", "Vision Support", "Speech Difficulties", "Cognitive Impairment"],
    lifestyle: ["Vegetarian", "Vegan", "Diabetic Diet", "Soft Diet", "Thickened Fluids", "Religious Requirements", "Cultural Preferences", "Pet in Home", "Female Carer Preferred", "Male Carer Preferred", "No Preference"],
    equipment: ["Hospital Bed", "Hoist", "Wheelchair", "Walking Frame", "Stair Lift", "Commode", "Shower Chair", "Pressure Mattress", "Oxygen Concentrator", "Suction Machine"],
    serviceTypes: ["Personal Care", "Home Care Visit", "Medication Visit", "Nursing Visit", "Welfare Check", "Rehabilitation Support", "Post Hospital Discharge", "Live-In Care", "Overnight Care", "Respite Care", "Palliative Care"],
};
const schedulingPreferenceOptions = {
    preferredDays: ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"],
    preferredTimes: ["Morning", "Afternoon", "Evening", "Night"],
    visitDurations: ["30 mins", "45 mins", "1 hour", "2 hours", "Custom"],
    frequencies: ["Daily", "Weekly", "Alternate Days", "Twice Daily", "Custom"],
    staffPreferences: ["Female Only", "Male Only", "No Preference"],
};
const documentCategories = ["Care Plan", "Risk Assessment", "Consent Form", "Medication Chart", "Hospital Discharge Summary", "GP Letter", "Insurance", "Photos", "Other Documents"];
const staffRoleOptions = ["Care Assistant", "Senior Care Assistant", "Healthcare Assistant", "Registered Nurse", "Clinical Nurse Manager (CNM)", "Team Leader", "Office Administrator", "Scheduler", "Coordinator", "Manager"];
const staffEmploymentTypeOptions = ["Full Time", "Part Time", "Agency", "Relief", "Temporary", "Contract"];
const staffStatusOptions = ["Induction", "Active", "On Leave", "Sick Leave", "Maternity Leave", "Suspended", "Resigned", "Archived"];
const staffQualificationOptions = ["QQI Level 5 Healthcare Support", "QQI Level 5 Community Health Services", "QQI Level 6 Supervisory Management", "QQI Level 6 Healthcare", "Nursing Degree", "Other"];
const staffSkillOptions = ["Dementia Care", "Alzheimer's Care", "Palliative Care", "End of Life Care", "Intellectual Disability", "Autism Support", "Mental Health", "Medication Administration", "PEG Feeding", "Catheter Care", "Stoma Care", "Wound Care", "Diabetes Care", "Epilepsy Support", "Parkinson's Care", "Stroke Rehabilitation", "Post Surgery Care", "Challenging Behaviour", "Learning Disability", "Hoist Trained", "Personal Care", "Companionship", "Night Care", "Live-In Care"];
const staffMandatoryTrainingOptions = ["Introduction to Children First", "Dignity at Work", "Open Disclosure", "Cyber Security", "GDPR", "Manual Handling", "Patient Moving & Handling", "Fire Safety", "Display Screen Equipment", "Infection Prevention & Control", "Hand Hygiene", "PPE", "Basic Life Support (BLS)", "CPR", "Safeguarding Adults", "Dementia Care", "Falls Prevention", "Food Safety HACCP", "Medication Management", "PEG Feeding", "Catheter Care", "Stoma Care"];
const staffCertificationOptions = ["Garda Vetting", "Manual Handling", "Patient Moving & Handling", "Infection Control", "Basic Life Support", "CPR", "Medication Management", "Driving Licence", "NMBI Registration"];
const inductionChecklistTemplates = [
    { key: "documents_verified", label: "Documents verified", description: "Passport, right-to-work, PPS, and required ID checked." },
    { key: "garda_vetting_reviewed", label: "Garda vetting reviewed", description: "Vetting status and renewal dates confirmed." },
    { key: "mandatory_training_started", label: "Mandatory training started", description: "Core training plan issued and booked." },
    { key: "shadow_shift_completed", label: "Shadow shift completed", description: "Initial supervised shift or observational visit completed." },
    { key: "system_access_prepared", label: "System access prepared", description: "Portal, payroll, and internal access set up for go-live." },
    { key: "manager_signoff", label: "Manager sign-off", description: "Final readiness confirmed by the responsible manager." },
];
const recruitmentStageDefinitions = [
    { key: "new", label: "New" },
    { key: "reviewing", label: "Reviewing" },
    { key: "shortlisted", label: "Shortlisted" },
    { key: "interview_scheduled", label: "Interview Scheduled" },
    { key: "interview_completed", label: "Interview Completed" },
    { key: "offer_sent", label: "Offer Sent" },
    { key: "offer_accepted", label: "Offer Accepted" },
    { key: "pre_employment_checks", label: "Pre-employment Checks" },
    { key: "induction", label: "Induction" },
    { key: "approved_employee", label: "Approved Employee" },
    { key: "active_staff", label: "Active Staff" },
    { key: "rejected", label: "Rejected" },
    { key: "archived", label: "Archived" },
];
const legacyRecruitmentStatusAliases = {
    interviewed: "interview_completed",
    hired: "offer_accepted",
};
const staffLanguageOptions = ["English", "French", "Spanish", "Portuguese", "Polish", "Romanian", "Hindi", "Punjabi", "Urdu", "Arabic", "Swahili", "Luganda", "Other"];
const staffAvailabilityDayOptions = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const staffShiftPreferenceOptions = ["Morning", "Afternoon", "Evening", "Night", "Sleepover", "Live-In"];
const staffServiceTypeOptions = ["Home Care", "Healthcare Staffing", "Both"];
const staffDocumentCategories = ["Passport", "Driving Licence", "Visa", "Work Permit", "Employment Contract", "CV", "Qualifications", "Certificates", "NMBI", "Insurance", "References", "Garda Vetting", "Manual Handling", "Patient Handling"];
const clientPortalOrganizationTypes = ["Nursing Home", "Residential Care Home", "Hospital", "Hospice", "Disability Service", "Mental Health Service", "GP Practice", "Community Healthcare Organisation", "Home Care Client", "Private Family", "Other Healthcare Provider"];
const clientPortalServiceRequirementOptions = ["Healthcare Assistants", "Support Workers", "Registered General Nurses", "Intellectual Disability Nurses", "Psychiatric Nurses", "Midwives", "Theatre Nurses", "ICU Nurses", "Agency Staff", "Home Care Staff", "Live-in Carers", "Domestic Support", "Cleaning Staff", "Catering Staff", "Administration Staff", "Other"];
const clientPortalFacilityTypeOptions = ["Nursing Home", "Hospital", "Residential Care", "Intellectual Disability Service", "Mental Health Service", "Community Care", "Home Care", "Hospice", "Rehabilitation Centre", "Other"];
const clientPortalShiftTypeOptions = ["Morning", "Afternoon", "Evening", "Night", "Long Day", "Sleepover", "Live-in"];
const clientPortalRecurringPatternOptions = ["One-time Shift", "Multiple Dates", "Weekly Repeat", "Monthly Repeat"];
const clientPortalRequestRoleOptions = ["Healthcare Assistant", "Support Worker", "Staff Nurse (RGN)", "Psychiatric Nurse (RPN)", "Intellectual Disability Nurse (RNID)", "Children's Nurse", "Midwife", "Social Care Worker", "Senior Care Assistant", "Clinical Nurse Manager", "Live-in Carer", "Other"];
const clientPortalSkillOptions = ["Dementia Care", "Intellectual Disability", "Autism Support", "Challenging Behaviour", "Manual Handling", "Medication Assistance", "PEG Feeding", "Catheter Care", "Stoma Care", "End of Life Care", "Palliative Care", "Bariatric Care", "Parkinson's Care", "Stroke Rehabilitation", "Post-Surgical Recovery", "Mobility Assistance", "Personal Care", "Wound Care", "Diabetes Care", "Pressure Area Care", "Infection Control", "Falls Prevention", "Behaviour Support", "Mental Health Support", "Epilepsy Care", "Tracheostomy Care", "Suctioning", "Oxygen Therapy", "Basic Life Support", "Other"];
const clientPortalTrainingOptions = ["Manual Handling", "Patient Moving & Handling", "Safeguarding", "Infection Prevention", "Medication Management", "CPR / BLS", "Fire Safety", "Food Hygiene", "PEG Training", "Epilepsy Training", "MAPA", "PMVA", "Children First"];
const clientPortalEnglishLevelOptions = ["Basic", "Conversational", "Professional", "Fluent"];
const clientPortalPriorityOptions = ["Routine", "Urgent", "Emergency"];
const clientPortalRegistrationStatuses = ["pending", "more_info_requested", "approved", "rejected", "suspended"];
const clientPortalRequestStatuses = ["pending_review", "reviewing", "request_more_information", "approved", "awaiting_staff", "accepted", "confirmed", "travelling", "checked_in", "on_break", "shift_completed", "cancelled", "no_show", "late_arrival", "checked_out", "rejected"];
const shiftDivisionOptions = ["home-care", "agency-staffing"];

const safeJsonParse = (value, fallback) => {
    if (value === null || value === undefined || value === "") {
        return fallback;
    }
    try {
        return JSON.parse(value);
    } catch (error) {
        return fallback;
    }
};

const normalizeStringList = (value) => {
    const source = Array.isArray(value) ? value : (value ? [value] : []);
    return [...new Set(source.map((item) => String(item || "").trim()).filter(Boolean))];
};

const normalizeDelimitedStringList = (value) => {
    const source = Array.isArray(value) ? value : [value];
    return normalizeStringList(
        source.flatMap((item) => String(item || "")
            .split(/[\n,]+/)
            .map((part) => part.trim())
            .filter(Boolean))
    );
};

const parseJsonArrayField = (value) => {
    const parsed = safeJsonParse(value, []);
    return Array.isArray(parsed) ? normalizeStringList(parsed) : [];
};

const parseJsonObjectField = (value) => {
    const parsed = safeJsonParse(value, {});
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
};

const serializeJsonField = (value) => JSON.stringify(value);

const normalizeInductionChecklist = (value) => {
    const itemsByKey = new Map();
    const parsed = safeJsonParse(value, []);
    const sourceItems = Array.isArray(parsed)
        ? parsed
        : (parsed && typeof parsed === "object" ? Object.values(parsed) : []);

    sourceItems.forEach((item) => {
        if (!item || typeof item !== "object") {
            return;
        }
        const key = String(item.key || "").trim();
        if (!key) {
            return;
        }
        itemsByKey.set(key, {
            key,
            completed: Boolean(item.completed),
            completedAt: String(item.completedAt || "").trim() || null,
            notes: String(item.notes || "").trim(),
        });
    });

    return inductionChecklistTemplates.map((template) => {
        const stored = itemsByKey.get(template.key) || {};
        return {
            key: template.key,
            label: template.label,
            description: template.description,
            completed: Boolean(stored.completed),
            completedAt: stored.completedAt || null,
            notes: stored.notes || "",
        };
    });
};

const buildInductionChecklistSummary = (items) => {
    const total = Array.isArray(items) ? items.length : 0;
    const completed = Array.isArray(items) ? items.filter((item) => item.completed).length : 0;
    return {
        total,
        completed,
        outstanding: Math.max(0, total - completed),
        percent: total ? Math.round((completed / total) * 100) : 0,
    };
};

const toFlagInteger = (value) => ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase()) ? 1 : 0;

const normalizePhoneDigits = (value) => String(value || "").replace(/[^\d+]/g, "");
const emailFormatPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const applicationAvailabilityGroups = {
    days: ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"],
    shifts: ["Day Shifts", "Evening Shifts", "Night Shifts", "Short Days", "Long Days", "12-Hour Shifts"],
    flexibility: ["Weekdays Only", "Weekends Only", "Weekdays & Weekends", "Flexible / Any Shift", "Emergency / Last-Minute Shifts"],
};
const applicationAvailabilityOptions = [
    ...applicationAvailabilityGroups.days,
    ...applicationAvailabilityGroups.shifts,
    ...applicationAvailabilityGroups.flexibility,
];
const applicationAvailabilityOptionSet = new Set(applicationAvailabilityOptions);

const normalizeEmailAddress = (value) => String(value || "").trim().toLowerCase();
const isValidEmailAddress = (value) => emailFormatPattern.test(normalizeEmailAddress(value));

const normalizePhoneForUniqueness = (value) => {
    const raw = String(value || "").trim();
    if (!raw) {
        return "";
    }
    const compact = raw.replace(/[^\d+]/g, "");
    const digitsOnly = compact.replace(/[^\d]/g, "");
    if (!digitsOnly) {
        return "";
    }
    if (digitsOnly.startsWith("353")) {
        return `353${digitsOnly.slice(3)}`;
    }
    if (digitsOnly.startsWith("0")) {
        return `353${digitsOnly.slice(1)}`;
    }
    return digitsOnly;
};

const getActiveIdentityRecords = async () => {
    const [admins, staffMembers, applications] = await Promise.all([
        allDb(
            `SELECT 'admin' AS account_type, id, COALESCE(name, username) AS label,
                    email_normalized AS email, phone_normalized AS phone
             FROM admin_users WHERE is_active = 1`
        ),
        allDb(
            `SELECT 'staff' AS account_type, id,
                    COALESCE(NULLIF(preferred_name, ''), NULLIF(name, ''), email) AS label,
                    email_normalized AS email, phone_normalized AS phone
             FROM staff WHERE COALESCE(is_archived, 0) = 0`
        ),
        allDb(
            `SELECT 'application' AS account_type, id,
                    trim(COALESCE(first_name, '') || ' ' || COALESCE(surname, '')) AS label,
                    email_normalized AS email, phone_normalized AS phone
             FROM applications WHERE archived_at IS NULL`
        ),
    ]);
    return [...admins, ...staffMembers, ...applications];
};

const findIdentityConflicts = async ({ email, phone, excludeType = null, excludeId = null }) => {
    const normalizedEmail = normalizeEmailAddress(email);
    const normalizedPhone = normalizePhoneForUniqueness(phone);
    const records = await getActiveIdentityRecords();
    return records.filter((record) => {
        if (record.account_type === excludeType && Number(record.id) === Number(excludeId)) return false;
        return Boolean(
            (normalizedEmail && record.email === normalizedEmail)
            || (normalizedPhone && record.phone === normalizedPhone)
        );
    });
};

const assertUniqueActiveIdentity = async (identity) => {
    const conflicts = await findIdentityConflicts(identity);
    if (!conflicts.length) {
        return {
            normalizedEmail: normalizeEmailAddress(identity.email),
            normalizedPhone: normalizePhoneForUniqueness(identity.phone),
        };
    }
    const emailConflict = normalizeEmailAddress(identity.email)
        && conflicts.some((record) => record.email === normalizeEmailAddress(identity.email));
    const error = new Error(
        emailConflict
            ? "This email address is already used by an active account or application."
            : "This phone number is already used by an active account or application."
    );
    error.code = emailConflict ? "DUPLICATE_ACTIVE_EMAIL" : "DUPLICATE_ACTIVE_PHONE";
    error.conflicts = conflicts;
    throw error;
};

const getDuplicateIdentityGroups = async () => {
    const records = await getActiveIdentityRecords();
    const groups = [];
    for (const field of ["email", "phone"]) {
        const byValue = new Map();
        for (const record of records) {
            const value = String(record[field] || "");
            if (!value) continue;
            if (!byValue.has(value)) byValue.set(value, []);
            byValue.get(value).push(record);
        }
        for (const [value, matches] of byValue.entries()) {
            if (matches.length > 1) groups.push({ field, value, records: matches });
        }
    }
    return groups;
};

const normalizeApplicationAvailabilitySelections = (value) => {
    const selections = normalizeStringList(Array.isArray(value) ? value : (value ? [value] : []));
    if (!selections.length) {
        return [];
    }
    if (selections.includes("Select All")) {
        return [...applicationAvailabilityOptions];
    }
    return selections.filter((item) => applicationAvailabilityOptionSet.has(item));
};

const parseApplicationAvailability = (value) => {
    const rawValue = String(value || "").trim();
    if (!rawValue) {
        return {
            selections: [],
            grouped: { days: [], shifts: [], flexibility: [] },
            legacyText: "",
            displayText: "No availability provided",
        };
    }

    let selections = [];
    const parsed = safeJsonParse(rawValue, null);
    if (Array.isArray(parsed)) {
        selections = normalizeApplicationAvailabilitySelections(parsed);
    } else if (parsed && typeof parsed === "object") {
        if (Array.isArray(parsed.selections)) {
            selections = normalizeApplicationAvailabilitySelections(parsed.selections);
        } else {
            selections = normalizeApplicationAvailabilitySelections([
                ...(Array.isArray(parsed.days) ? parsed.days : []),
                ...(Array.isArray(parsed.shifts) ? parsed.shifts : []),
                ...(Array.isArray(parsed.flexibility) ? parsed.flexibility : []),
            ]);
        }
    } else {
        selections = normalizeApplicationAvailabilitySelections(normalizeDelimitedStringList(rawValue));
    }

    const grouped = {
        days: applicationAvailabilityGroups.days.filter((option) => selections.includes(option)),
        shifts: applicationAvailabilityGroups.shifts.filter((option) => selections.includes(option)),
        flexibility: applicationAvailabilityGroups.flexibility.filter((option) => selections.includes(option)),
    };

    if (!selections.length) {
        return {
            selections: [],
            grouped,
            legacyText: rawValue,
            displayText: rawValue,
        };
    }

    return {
        selections,
        grouped,
        legacyText: "",
        displayText: selections.join(", "),
    };
};

const buildApplicationNameParts = (payload = {}) => {
    const explicitFirstName = String(payload.first_name || "").trim();
    const explicitSurname = String(payload.surname || payload.last_name || "").trim();
    const fallbackFullName = String(payload.name || "").trim();
    const fallbackParts = fallbackFullName ? fallbackFullName.split(/\s+/).filter(Boolean) : [];
    const firstName = explicitFirstName || fallbackParts[0] || "";
    const surname = explicitSurname || fallbackParts.slice(1).join(" ") || "";
    const fullName = normalizeStringList([firstName, surname]).join(" ") || fallbackFullName;
    return { firstName, surname, fullName };
};

const enforceApplicationUniqueness = async ({
    email,
    phone,
    excludeApplicationId = null,
    excludeStaffId = null,
    excludeAdminId = null,
}) => {
    const normalizedEmail = normalizeEmailAddress(email);
    const normalizedPhone = normalizePhoneForUniqueness(phone);
    const exclusionSql = Number.isInteger(Number(excludeApplicationId)) && Number(excludeApplicationId) > 0 ? "AND id != ?" : "";
    const numericExcludeStaffId = Number.isInteger(Number(excludeStaffId)) && Number(excludeStaffId) > 0 ? Number(excludeStaffId) : null;
    const numericExcludeAdminId = Number.isInteger(Number(excludeAdminId)) && Number(excludeAdminId) > 0 ? Number(excludeAdminId) : null;

    if (normalizedEmail) {
        const emailParams = [normalizedEmail];
        if (exclusionSql) {
            emailParams.push(Number(excludeApplicationId));
        }
        const existingByEmail = await getDb(
            `SELECT id FROM applications WHERE archived_at IS NULL AND COALESCE(email_normalized, '') = ? ${exclusionSql} LIMIT 1`,
            emailParams
        );
        if (existingByEmail) {
            const error = new Error("This email address is already registered. Please use a different email address or contact Everkind if you believe this is an error.");
            error.code = "APPLICATION_DUPLICATE_EMAIL";
            throw error;
        }
        const staffEmailParams = [normalizedEmail];
        let staffEmailSql = "SELECT id FROM staff WHERE COALESCE(is_archived, 0) = 0 AND lower(COALESCE(email, '')) = ?";
        if (numericExcludeStaffId) {
            staffEmailSql += " AND id != ?";
            staffEmailParams.push(numericExcludeStaffId);
        }
        staffEmailSql += " LIMIT 1";
        const existingStaffByEmail = await getDb(staffEmailSql, staffEmailParams);
        if (existingStaffByEmail) {
            const error = new Error("This email address is already registered. Please use a different email address or contact Everkind if you believe this is an error.");
            error.code = "APPLICATION_DUPLICATE_EMAIL";
            throw error;
        }
        const adminEmailParams = [normalizedEmail];
        let adminEmailSql = `SELECT id FROM admin_users
             WHERE is_active = 1 AND COALESCE(email_normalized, lower(username)) = ?`;
        if (numericExcludeAdminId) {
            adminEmailSql += " AND id != ?";
            adminEmailParams.push(numericExcludeAdminId);
        }
        const existingAdminByEmail = await getDb(`${adminEmailSql} LIMIT 1`, adminEmailParams);
        if (existingAdminByEmail) {
            const error = new Error("This email address is already registered. Please use a different email address or contact Everkind if you believe this is an error.");
            error.code = "APPLICATION_DUPLICATE_EMAIL";
            throw error;
        }
    }

    if (normalizedPhone) {
        const phoneParams = [normalizedPhone];
        if (exclusionSql) {
            phoneParams.push(Number(excludeApplicationId));
        }
        const existingByPhone = await getDb(
            `SELECT id FROM applications WHERE archived_at IS NULL AND COALESCE(phone_normalized, '') = ? ${exclusionSql} LIMIT 1`,
            phoneParams
        );
        if (existingByPhone) {
            const error = new Error("This contact number is already registered. Please use a different contact number or contact Everkind if you believe this is an error.");
            error.code = "APPLICATION_DUPLICATE_PHONE";
            throw error;
        }
        const staffPhoneRows = await allDb("SELECT id, phone, mobile_number FROM staff WHERE COALESCE(is_archived, 0) = 0");
        const conflictingStaffPhone = staffPhoneRows.find((staffRow) => {
            const staffId = Number(staffRow.id);
            if (numericExcludeStaffId && staffId === numericExcludeStaffId) {
                return false;
            }
            const normalizedStaffPhone = normalizePhoneForUniqueness(staffRow.mobile_number || staffRow.phone || "");
            return Boolean(normalizedStaffPhone && normalizedStaffPhone === normalizedPhone);
        });
        if (conflictingStaffPhone) {
            const error = new Error("This contact number is already registered. Please use a different contact number or contact Everkind if you believe this is an error.");
            error.code = "APPLICATION_DUPLICATE_PHONE";
            throw error;
        }
        const adminPhoneParams = [normalizedPhone];
        let adminPhoneSql = `SELECT id FROM admin_users
             WHERE is_active = 1 AND COALESCE(phone_normalized, '') = ?`;
        if (numericExcludeAdminId) {
            adminPhoneSql += " AND id != ?";
            adminPhoneParams.push(numericExcludeAdminId);
        }
        const existingAdminByPhone = await getDb(`${adminPhoneSql} LIMIT 1`, adminPhoneParams);
        if (existingAdminByPhone) {
            const error = new Error("This contact number is already registered. Please use a different contact number or contact Everkind if you believe this is an error.");
            error.code = "APPLICATION_DUPLICATE_PHONE";
            throw error;
        }
    }

    return { normalizedEmail, normalizedPhone };
};

const recordDuplicateIdentityAttempt = async (req, error, targetType = "identity") => {
    if (!["APPLICATION_DUPLICATE_EMAIL", "APPLICATION_DUPLICATE_PHONE"].includes(error && error.code)) return;
    await writeAuditEvent(req, {
        ...getActorContext(req),
        action: error.code === "APPLICATION_DUPLICATE_EMAIL" ? "duplicate_email_attempt" : "duplicate_phone_attempt",
        targetType,
        targetIdentifier: "redacted",
        outcome: "denied",
        reason: error.code,
    });
};

const buildPublicContact = () => {
    const preferredPhone = String(companyPhone || "").trim() || defaultPublicPhone;
    const normalizedPhone = normalizePhoneDigits(preferredPhone);
    const phoneHrefValue = normalizedPhone || normalizePhoneDigits(defaultPublicPhone);
    const whatsappDigits = phoneHrefValue.replace(/^\+/, "");
    const preferredEmail = String(companyEmail || "").trim() || defaultPublicEmail;

    return {
        phoneDisplay: preferredPhone,
        phoneHref: `tel:${phoneHrefValue}`,
        whatsappHref: `https://wa.me/${whatsappDigits}`,
        emailDisplay: preferredEmail,
        emailHref: `mailto:${preferredEmail}`,
    };
};

const slugifyValue = (value) => String(value || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "unknown";

const calculateAgeFromDateOfBirth = (value) => {
    const raw = String(value || "").trim();
    if (!raw) {
        return null;
    }
    const birthDate = new Date(`${raw}T12:00:00`);
    if (Number.isNaN(birthDate.getTime())) {
        return null;
    }
    const today = new Date();
    let age = today.getFullYear() - birthDate.getFullYear();
    const monthDelta = today.getMonth() - birthDate.getMonth();
    if (monthDelta < 0 || (monthDelta === 0 && today.getDate() < birthDate.getDate())) {
        age -= 1;
    }
    return age >= 0 ? age : null;
};

const sanitizeRichText = (value) => {
    const input = String(value || "").trim();
    if (!input) {
        return "";
    }
    return input
        .replace(/<\s*script[\s\S]*?>[\s\S]*?<\s*\/script\s*>/gi, "")
        .replace(/<\s*style[\s\S]*?>[\s\S]*?<\s*\/style\s*>/gi, "")
        .replace(/\son[a-z]+\s*=\s*(['"]).*?\1/gi, "")
        .replace(/\s(href|src)\s*=\s*(['"])\s*javascript:[\s\S]*?\2/gi, "")
        .replace(/<(?!\/?(p|br|strong|b|em|i|u|ul|ol|li)\b)[^>]*>/gi, "");
};

const buildPatientAddressText = (parts) => normalizeStringList(parts).join(", ");

const geocodeAddress = (addressText) => new Promise((resolve, reject) => {
    const query = String(addressText || "").trim();
    if (!query) {
        reject(new Error("An address is required."));
        return;
    }

    const request = https.get(
        `https://nominatim.openstreetmap.org/search?format=jsonv2&limit=1&q=${encodeURIComponent(query)}`,
        {
            headers: {
                "User-Agent": "Everkind-Care-System/1.0",
                Accept: "application/json",
            },
        },
        (response) => {
            let data = "";
            response.on("data", (chunk) => {
                data += chunk;
            });
            response.on("end", () => {
                if (response.statusCode && response.statusCode >= 400) {
                    reject(new Error("The geocoding service could not process the address."));
                    return;
                }
                const results = safeJsonParse(data, []);
                if (!Array.isArray(results) || !results.length) {
                    reject(new Error("No GPS result was found for this address."));
                    return;
                }
                resolve(results[0]);
            });
        }
    );

    request.on("error", (error) => reject(error));
});

const emptyPatientCarePlan = () => ({
    dailyRoutine: "",
    personalPreferences: "",
    likes: "",
    dislikes: "",
    communicationNeeds: "",
    diet: "",
    fluids: "",
    behaviourSupport: "",
    riskInformation: "",
    careGoals: "",
});

const createPatientFormState = (patient = null) => {
    const source = patient || {};
    return {
        ...source,
        first_name: source.first_name || "",
        last_name: source.last_name || "",
        preferred_name: source.preferred_name || "",
        photo_url: source.photo_url || source.photoUrl || "",
        date_of_birth: source.date_of_birth || source.dateOfBirth || "",
        age: source.age ?? calculateAgeFromDateOfBirth(source.date_of_birth || source.dateOfBirth || ""),
        gender: source.gender || "",
        marital_status: source.marital_status || "",
        nationality: source.nationality || "",
        pps_number: source.pps_number || "",
        primary_language: source.primary_language || "",
        interpreter_required: Boolean(Number(source.interpreter_required || source.interpreterRequired || 0)),
        address: source.address || "",
        eircode: source.eircode || "",
        county: source.county || "",
        phone: source.phone || "",
        alternative_phone: source.alternative_phone || "",
        email: source.email || "",
        latitude: source.latitude || "",
        longitude: source.longitude || "",
        geofence_radius_meters: Number(source.geofence_radius_meters || source.geofenceRadiusMeters || 100) || 100,
        status: source.status || "Active",
        care_level: source.care_level || source.careLevel || "",
        risk_level: source.risk_level || source.riskLevel || "",
        personalCareNeeds: source.personalCareNeeds || [],
        mobilityNeeds: source.mobilityNeeds || [],
        clinicalTasks: source.clinicalTasks || [],
        medicalConditions: source.medicalConditions || [],
        dailyLivingNeeds: source.dailyLivingNeeds || [],
        riskFlags: source.riskFlags || [],
        communicationNeedsList: source.communicationNeedsList || [],
        lifestylePreferences: source.lifestylePreferences || [],
        equipmentNeeds: source.equipmentNeeds || [],
        serviceTypes: source.serviceTypes || [],
        diagnoses: source.diagnoses || "",
        allergies: source.allergies || "",
        current_medication: source.current_medication || "",
        medication_schedule: source.medication_schedule || "",
        gp_name: source.gp_name || "",
        gp_phone: source.gp_phone || "",
        consultant_name: source.consultant_name || "",
        hospital_name: source.hospital_name || "",
        pharmacy_name: source.pharmacy_name || "",
        vaccination_status: source.vaccination_status || "",
        dnar_status: source.dnar_status || "",
        falls_risk_level: source.falls_risk_level || "",
        infection_risks: source.infection_risks || "",
        emergency_contact_name: source.emergency_contact_name || source.emergencyContactName || "",
        emergency_contact_relationship: source.emergency_contact_relationship || source.emergencyContactRelationship || "",
        emergency_contact_phone: source.emergency_contact_phone || source.emergencyContactPhone || "",
        emergency_contact_alt_phone: source.emergency_contact_alt_phone || "",
        emergency_contact_email: source.emergency_contact_email || "",
        emergency_contact_address: source.emergency_contact_address || "",
        key_safe_code: source.key_safe_code || "",
        door_code: source.door_code || "",
        alarm_code: source.alarm_code || "",
        parking_instructions: source.parking_instructions || "",
        pets: source.pets || "",
        lift_available: Boolean(Number(source.lift_available || 0)),
        stairs: source.stairs || "",
        access_notes: source.access_notes || "",
        carePlanSections: { ...emptyPatientCarePlan(), ...(source.carePlanSections || {}) },
        shift_instructions: source.shift_instructions || "",
        preferredDays: source.preferredDays || [],
        preferredTimes: source.preferredTimes || [],
        visit_duration: source.visit_duration || "",
        custom_visit_duration: source.custom_visit_duration || "",
        visit_frequency: source.visit_frequency || "",
        custom_visit_frequency: source.custom_visit_frequency || "",
        preferred_staff_gender: source.preferred_staff_gender || "",
        internal_notes: source.internal_notes || "",
        assignments: Array.isArray(source.assignments) ? source.assignments : [],
        documents: Array.isArray(source.documents) ? source.documents : [],
        fullAddress: buildPatientAddressText([source.address, source.county, source.eircode]),
    };
};

const patientWritableColumns = [
    "first_name",
    "last_name",
    "preferred_name",
    "photo_url",
    "date_of_birth",
    "age",
    "gender",
    "marital_status",
    "nationality",
    "pps_number",
    "primary_language",
    "interpreter_required",
    "address",
    "eircode",
    "county",
    "phone",
    "alternative_phone",
    "email",
    "latitude",
    "longitude",
    "geofence_radius_meters",
    "status",
    "care_level",
    "risk_level",
    "care_needs_personal_care",
    "care_needs_mobility",
    "care_needs_clinical_tasks",
    "care_needs_medical_conditions",
    "care_needs_daily_living",
    "care_needs_risks",
    "care_needs_communication",
    "care_needs_lifestyle",
    "care_needs_equipment",
    "care_needs_service_types",
    "diagnoses",
    "allergies",
    "current_medication",
    "medication_schedule",
    "gp_name",
    "gp_phone",
    "consultant_name",
    "hospital_name",
    "pharmacy_name",
    "vaccination_status",
    "dnar_status",
    "falls_risk_level",
    "infection_risks",
    "emergency_contact",
    "emergency_contact_name",
    "emergency_contact_relationship",
    "emergency_contact_phone",
    "emergency_contact_alt_phone",
    "emergency_contact_email",
    "emergency_contact_address",
    "key_safe_code",
    "door_code",
    "alarm_code",
    "parking_instructions",
    "pets",
    "lift_available",
    "stairs",
    "access_notes",
    "care_plan_daily_routine",
    "care_plan_preferences",
    "care_plan_likes",
    "care_plan_dislikes",
    "care_plan_communication",
    "care_plan_diet",
    "care_plan_fluids",
    "care_plan_behaviour_support",
    "care_plan_risk_information",
    "care_plan_goals",
    "carePlan",
    "shift_instructions",
    "preferred_days",
    "preferred_times",
    "visit_duration",
    "custom_visit_duration",
    "visit_frequency",
    "custom_visit_frequency",
    "preferred_staff_gender",
    "internal_notes",
    "condition",
];

const buildPatientExportPackage = async (patientId) => {
    const patient = await getDb("SELECT * FROM patients WHERE id = ?", [patientId]);
    if (!patient) {
        return null;
    }

    const notes = await allDb(
        "SELECT id, author, note, severity, created_at FROM care_notes WHERE patient_id = ? ORDER BY created_at DESC",
        [patientId]
    );
    const shifts = await allDb(
        `SELECT id, staff_id, shift_date, scheduled_start, scheduled_end, actual_clock_in, actual_clock_out, status
         FROM staff_shifts
         WHERE patient_id = ?
         ORDER BY scheduled_start DESC`,
        [patientId]
    );
    const appointments = await allDb(
        `SELECT id, staff_id, title, start, end, notes, status, created_at
         FROM appointments
         WHERE patient_id = ?
         ORDER BY start DESC`,
        [patientId]
    );

    return {
        exportedAt: new Date().toISOString(),
        patient: mapPatientRow(patient),
        careNotes: notes,
        shifts,
        appointments,
    };
};

const ensureColumn = async (tableName, columnName, columnDefinition) => {
    const columns = await allDb(`PRAGMA table_info(${tableName})`);
    const exists = columns.some((column) => column.name === columnName);

    if (!exists) {
        await runDb(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${columnDefinition}`);
    }
};

const ensureColumns = async (tableName, columns) => {
    for (const [columnName, columnDefinition] of columns) {
        await ensureColumn(tableName, columnName, columnDefinition);
    }
};

const ensureProductionSecurity = () => {
    if (!isProduction) {
        return;
    }

    if (sessionSecret === "everkind-care-system-secret") {
        throw new Error("SESSION_SECRET must be set in production.");
    }

    if (adminPassword === "everkind2026") {
        throw new Error("ADMIN_PASSWORD must be set in production.");
    }

    if (staffDefaultPassword === "everkindstaff") {
        throw new Error("STAFF_PASSWORD must be set in production.");
    }
};

const getActorContext = (req) => {
    if (req.session && req.session.isAdmin) {
        return {
            actorType: "admin",
            actorIdentifier: req.session.adminEmail || adminEmail,
            actorRole: req.session.adminRole || null,
        };
    }

    if (req.session && req.session.isStaff) {
        return {
            actorType: "staff",
            actorIdentifier: req.session.staffId ? String(req.session.staffId) : (req.session.staffName || "staff"),
        };
    }

    if (req.session && req.session.isClient) {
        return {
            actorType: "client",
            actorIdentifier: req.session.clientAccountId ? String(req.session.clientAccountId) : (req.session.clientAccountEmail || "client"),
        };
    }

    return { actorType: "anonymous", actorIdentifier: null };
};

const writeAuditEvent = async (req, {
    action,
    targetType = null,
    targetIdentifier = null,
    outcome,
    reason = null,
    actorType,
    actorIdentifier,
    actorRole,
    metadata = null,
}) => {
    const actorContext = getActorContext(req);
    await runDb(
        `INSERT INTO audit_events
         (actor_type, actor_identifier, actor_role, action, target_type, target_identifier, outcome, reason, metadata, ip_address, user_agent)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
            actorType || actorContext.actorType,
            actorIdentifier || actorContext.actorIdentifier,
            actorRole || actorContext.actorRole || null,
            action,
            targetType,
            targetIdentifier,
            outcome,
            reason,
            metadata ? (typeof metadata === "string" ? metadata : serializeJsonField(metadata)) : null,
            String(req.ip || ""),
            String(req.get("user-agent") || ""),
        ]
    );
};

const normalizeAdminRole = (role) => {
    const normalized = String(role || "").trim().toLowerCase();
    return normalized === "admin" || !normalized ? "super_admin" : normalized;
};

let securityPolicyCache = { loadedAt: 0, values: null };
const getSecurityPolicy = async () => {
    const now = Date.now();
    if (securityPolicyCache.values && now - securityPolicyCache.loadedAt < 30_000) {
        return securityPolicyCache.values;
    }
    const rows = await allDb(
        `SELECT key, value FROM system_settings WHERE key IN (
            'security_session_timeout_minutes', 'security_password_min_length',
            'mfa_global_enabled', 'mfa_role_super_admin', 'mfa_role_hr',
            'mfa_role_payroll', 'mfa_role_manager', 'mfa_role_staff'
        )`
    );
    const stored = Object.fromEntries(rows.map((row) => [row.key, row.value]));
    const sessionTimeoutMinutes = Math.min(480, Math.max(5, Number(stored.security_session_timeout_minutes) || 30));
    const passwordMinimumLength = Math.min(128, Math.max(12, Number(stored.security_password_min_length) || 12));
    const mfaRoleRequirements = {
        super_admin: stored.mfa_role_super_admin !== "0",
        hr: stored.mfa_role_hr !== "0",
        payroll: stored.mfa_role_payroll !== "0",
        manager: stored.mfa_role_manager !== "0",
        staff: stored.mfa_role_staff === "1",
    };
    securityPolicyCache = {
        loadedAt: now,
        values: {
            sessionTimeoutMinutes,
            passwordMinimumLength,
            mfaGlobalEnabled: stored.mfa_global_enabled === "1",
            mfaRoleRequirements,
        },
    };
    return securityPolicyCache.values;
};

const isSmsMfaConfigured = () => Boolean(twilioAccountSid && twilioAuthToken && twilioFromNumber);
const isEmailMfaConfigured = () => Boolean(smtpHost && smtpUser && smtpPass && smtpFrom);
const isAuthenticatorMfaConfigured = () => Boolean(process.env.MFA_ENCRYPTION_KEY || !isProduction);

const getMfaAccount = async (accountType, accountId) => {
    if (accountType === "admin") {
        const account = await getDb(
            `SELECT admin_users.id, admin_users.name, admin_users.username AS email,
                    admin_users.phone, admin_users.password_hash, admin_users.is_active,
                    admin_users.email_verified, admin_users.phone_verified,
                    admin_users.mfa_enabled, admin_users.mfa_preferred_method,
                    admin_users.totp_secret_encrypted, admin_users.totp_verified_at,
                    admin_users.mfa_reset_required, admin_users.mfa_version,
                    COALESCE(roles.role_key, admin_users.role) AS role
             FROM admin_users
             LEFT JOIN user_roles
                ON user_roles.admin_user_id = admin_users.id
               AND user_roles.is_primary = 1
             LEFT JOIN roles ON roles.id = user_roles.role_id
             WHERE admin_users.id = ?`,
            [accountId]
        );
        return account ? { ...account, accountType: "admin" } : null;
    }
    if (accountType === "staff") {
        const account = await getDb(
            `SELECT id, COALESCE(NULLIF(preferred_name, ''), NULLIF(name, ''), email) AS name,
                    email, COALESCE(NULLIF(mobile_number, ''), phone) AS phone,
                    password_hash, status, employment_status, portal_login_enabled, portal_login_suspended,
                    portal_login_deactivated, email_verified, phone_verified,
                    mfa_enabled, mfa_preferred_method, totp_secret_encrypted,
                    totp_verified_at, mfa_reset_required, mfa_version
             FROM staff WHERE id = ?`,
            [accountId]
        );
        return account ? { ...account, accountType: "staff", role: "staff" } : null;
    }
    return null;
};

const getMfaMethods = async (account) => {
    if (!account) return [];
    const recoveryRow = await getDb(
        `SELECT COUNT(*) AS count FROM mfa_recovery_codes
         WHERE account_type = ? AND account_id = ? AND used_at IS NULL`,
        [account.accountType, account.id]
    );
    const methods = [];
    if (account.totp_verified_at && account.totp_secret_encrypted) {
        methods.push({
            key: "authenticator",
            label: "Authenticator App",
            detail: "Use the 6-digit code from your authenticator app.",
        });
    }
    if (Number(account.email_verified) === 1 && account.email && isEmailMfaConfigured()) {
        methods.push({
            key: "email",
            label: "Email",
            detail: `Send a verification code to ${maskEmail(account.email)}.`,
        });
    }
    if (Number(account.phone_verified) === 1 && account.phone && isSmsMfaConfigured()) {
        methods.push({
            key: "sms",
            label: "SMS",
            detail: `Send a verification code to ${maskPhone(account.phone)}.`,
        });
    }
    if (Number(recoveryRow?.count || 0) > 0) {
        methods.push({
            key: "recovery",
            label: "Recovery code",
            detail: "Use one of your saved one-time recovery codes.",
        });
    }
    return methods;
};

const isMfaRequiredForAccount = async (account) => {
    const policy = await getSecurityPolicy();
    if (!policy.mfaGlobalEnabled) return false;
    return Boolean(policy.mfaRoleRequirements[account.role] || Number(account.mfa_enabled) === 1);
};

const seedRbacData = async () => {
    for (const [roleKey, role] of Object.entries(ROLE_DEFINITIONS)) {
        await runDb(
            `INSERT INTO roles (role_key, label, description, is_system)
             VALUES (?, ?, ?, 1)
             ON CONFLICT(role_key) DO UPDATE SET
                label = excluded.label,
                description = excluded.description,
                is_system = 1`,
            [roleKey, role.label, role.description]
        );
    }

    for (const permission of allPermissions) {
        const [moduleKey, action] = permission.split(".");
        await runDb(
            `INSERT INTO permissions (permission_key, module_key, action, description)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(permission_key) DO UPDATE SET
                module_key = excluded.module_key,
                action = excluded.action,
                description = excluded.description`,
            [permission, moduleKey, action, `${RBAC_MODULES[moduleKey]}: ${action}`]
        );
    }

    for (const [roleKey, role] of Object.entries(ROLE_DEFINITIONS)) {
        const roleRow = await getDb("SELECT id FROM roles WHERE role_key = ?", [roleKey]);
        await runDb("DELETE FROM role_permissions WHERE role_id = ?", [roleRow.id]);
        for (const permissionKey of role.permissions) {
            const permissionRow = await getDb(
                "SELECT id FROM permissions WHERE permission_key = ?",
                [permissionKey]
            );
            await runDb(
                "INSERT OR IGNORE INTO role_permissions (role_id, permission_id) VALUES (?, ?)",
                [roleRow.id, permissionRow.id]
            );
        }
    }

    const adminUsers = await allDb("SELECT id, role FROM admin_users");
    for (const adminUser of adminUsers) {
        const roleKey = normalizeAdminRole(adminUser.role);
        const roleRow = await getDb("SELECT id FROM roles WHERE role_key = ?", [roleKey]);
        if (!roleRow) continue;
        await runDb("UPDATE admin_users SET role = ? WHERE id = ?", [roleKey, adminUser.id]);
        const assignment = await getDb(
            "SELECT admin_user_id FROM user_roles WHERE admin_user_id = ? AND is_primary = 1",
            [adminUser.id]
        );
        if (!assignment) {
            await runDb(
                `INSERT OR IGNORE INTO user_roles
                 (admin_user_id, role_id, scope_type, scope_value, is_primary)
                 VALUES (?, ?, 'global', '', 1)`,
                [adminUser.id, roleRow.id]
            );
        }
    }
};

const ensureAdminAndRbacData = async () => {
    const normalizedAdminEmail = String(adminEmail || "").trim().toLowerCase();
    const adminRecord = await getDb(
        "SELECT * FROM admin_users WHERE lower(username) = ? ORDER BY id LIMIT 1",
        [normalizedAdminEmail]
    );
    if (!adminRecord) {
        const adminHash = await bcrypt.hash(adminPassword, 10);
        await runDb(
            "INSERT INTO admin_users (username, password_hash, role, name, department, is_active) VALUES (?, ?, 'super_admin', 'Administrator', 'Administration', 1)",
            [adminEmail, adminHash]
        );
    } else {
        const passwordMatches = Boolean(adminRecord.password_hash)
            && (await bcrypt.compare(adminPassword, adminRecord.password_hash));
        if (!adminRecord.password_hash || !passwordMatches) {
            const adminHash = await bcrypt.hash(adminPassword, 10);
            await runDb(
                "UPDATE admin_users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                [adminHash, adminRecord.id]
            );
        }
    }

    await runDb(
        `UPDATE admin_users
         SET role = CASE WHEN role IS NULL OR trim(role) = '' OR lower(role) = 'admin' THEN 'super_admin' ELSE lower(role) END,
             name = COALESCE(NULLIF(name, ''), CASE WHEN lower(username) = lower(?) THEN 'Administrator' ELSE username END),
             department = COALESCE(NULLIF(department, ''), 'Administration'),
             is_active = COALESCE(is_active, 1),
             auth_version = COALESCE(auth_version, 1)`,
        [adminEmail]
    );
    await seedRbacData();
};

const loadAdminAccessContext = async (adminUser, previewRole = null) => {
    const roleRows = await allDb(
        `SELECT roles.id, roles.role_key, roles.label, user_roles.scope_type, user_roles.scope_value, user_roles.is_primary
         FROM user_roles
         JOIN roles ON roles.id = user_roles.role_id
         WHERE user_roles.admin_user_id = ?
         ORDER BY user_roles.is_primary DESC, roles.label ASC`,
        [adminUser.id]
    );

    const fallbackRole = normalizeAdminRole(adminUser.role);
    const actualRole = roleRows.find((role) => Number(role.is_primary) === 1)?.role_key
        || roleRows[0]?.role_key
        || fallbackRole;
    const actualRoleLabel = roleRows.find((role) => role.role_key === actualRole)?.label
        || ROLE_DEFINITIONS[actualRole]?.label
        || actualRole;
    const roleIds = roleRows.map((role) => role.id);
    let actualPermissions;

    if (roleIds.length) {
        const placeholders = roleIds.map(() => "?").join(",");
        const permissionRows = await allDb(
            `SELECT DISTINCT permissions.permission_key
             FROM role_permissions
             JOIN permissions ON permissions.id = role_permissions.permission_id
             WHERE role_permissions.role_id IN (${placeholders})`,
            roleIds
        );
        actualPermissions = new Set(permissionRows.map((row) => row.permission_key));
    } else {
        actualPermissions = getFallbackPermissionsForRole(actualRole);
    }

    const requestedPreviewRole = String(previewRole || "").trim().toLowerCase();
    const canPreview = actualRole === "super_admin";
    const effectiveRole = canPreview && (ROLE_DEFINITIONS[requestedPreviewRole] || requestedPreviewRole === "staff")
        ? requestedPreviewRole
        : actualRole;
    const permissions = effectiveRole === actualRole
        ? actualPermissions
        : getFallbackPermissionsForRole(effectiveRole);

    return {
        adminUserId: adminUser.id,
        actualRole,
        actualRoleLabel,
        effectiveRole,
        effectiveRoleLabel: effectiveRole === "staff"
            ? "Staff"
            : (ROLE_DEFINITIONS[effectiveRole]?.label || effectiveRole),
        isPreview: effectiveRole !== actualRole,
        permissions,
        actualPermissions,
        roles: roleRows,
    };
};

const getLoginAttemptKey = (req, email) => {
    const ipAddress = String(req.ip || "unknown");
    return `${ipAddress}:${String(email || "").trim().toLowerCase()}`;
};

const getLoginThrottleStatus = (req, email) => {
    const key = getLoginAttemptKey(req, email);
    const now = Date.now();
    const attemptRecord = loginAttempts.get(key);

    if (!attemptRecord) {
        return { throttled: false, retryAfterSeconds: 0 };
    }

    if (attemptRecord.windowStart + loginAttemptWindowMs < now) {
        loginAttempts.delete(key);
        return { throttled: false, retryAfterSeconds: 0 };
    }

    if (attemptRecord.count < maxLoginAttemptsPerWindow) {
        return { throttled: false, retryAfterSeconds: 0 };
    }

    return {
        throttled: true,
        retryAfterSeconds: Math.ceil((attemptRecord.windowStart + loginAttemptWindowMs - now) / 1000),
    };
};

const registerFailedLogin = (req, email) => {
    const key = getLoginAttemptKey(req, email);
    const now = Date.now();
    const current = loginAttempts.get(key);

    if (!current || current.windowStart + loginAttemptWindowMs < now) {
        loginAttempts.set(key, { count: 1, windowStart: now });
        return;
    }

    loginAttempts.set(key, { count: current.count + 1, windowStart: current.windowStart });
};

const clearFailedLogins = (req, email) => {
    loginAttempts.delete(getLoginAttemptKey(req, email));
};

const regenerateSession = (req) => new Promise((resolve, reject) => {
    req.session.regenerate((error) => {
        if (error) {
            reject(error);
            return;
        }

        resolve();
    });
});

const destroySession = (req) => new Promise((resolve, reject) => {
    req.session.destroy((error) => {
        if (error) {
            reject(error);
            return;
        }

        resolve();
    });
});

const getDistanceInMeters = (lat1, lng1, lat2, lng2) => {
    const toRad = (value) => (value * Math.PI) / 180;
    const earthRadiusMeters = 6371000;
    const dLat = toRad(lat2 - lat1);
    const dLng = toRad(lng2 - lng1);
    const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
    return earthRadiusMeters * (2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)));
};

const formatName = (firstName, lastName) => {
    const parts = [firstName, lastName].filter(Boolean);
    return parts.length ? parts.join(" ") : "Unknown";
};

const slugify = (value) => String(value || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, ".")
    .replace(/^\.|\.$/g, "") || "staff";

const mapPatientRow = (patient) => {
    if (!patient) {
        return patient;
    }

    const carePlanSections = {
        dailyRoutine: patient.care_plan_daily_routine || "",
        personalPreferences: patient.care_plan_preferences || "",
        likes: patient.care_plan_likes || "",
        dislikes: patient.care_plan_dislikes || "",
        communicationNeeds: patient.care_plan_communication || "",
        diet: patient.care_plan_diet || "",
        fluids: patient.care_plan_fluids || "",
        behaviourSupport: patient.care_plan_behaviour_support || "",
        riskInformation: patient.care_plan_risk_information || "",
        careGoals: patient.care_plan_goals || "",
    };
    const derivedAge = patient.age ?? calculateAgeFromDateOfBirth(patient.date_of_birth);

    return {
        ...patient,
        name: patient.name || formatName(patient.first_name, patient.last_name),
        age: derivedAge,
        clientId: patient.home_care_client_id || `HC-${String(patient.id || "").padStart(5, "0")}`,
        preferredName: patient.preferred_name || "",
        photoUrl: patient.photo_url || "",
        dateOfBirth: patient.date_of_birth || "",
        maritalStatus: patient.marital_status || "",
        nationality: patient.nationality || "",
        ppsNumber: patient.pps_number || "",
        primaryLanguage: patient.primary_language || "",
        interpreterRequired: Boolean(Number(patient.interpreter_required || 0)),
        alternativePhone: patient.alternative_phone || "",
        county: patient.county || "",
        condition: patient.condition || patient.diagnoses || patient.care_level || "Needs review",
        carePlan: patient.carePlan || Object.values(carePlanSections).filter(Boolean).join("\n\n") || "Care plan pending",
        carePlanSections,
        nextVisit: patient.nextVisit || patient.next_visit || null,
        legalBasis: patient.legal_basis || "care_contract",
        consentStatus: patient.consent_status || "pending",
        consentRecordedAt: patient.consent_recorded_at || null,
        consentRecordedBy: patient.consent_recorded_by || null,
        dataRetentionUntil: patient.data_retention_until || null,
        isArchived: Boolean(Number(patient.is_archived || 0)),
        eircode: patient.eircode || "",
        emergencyContactName: patient.emergency_contact_name || "",
        emergencyContactRelationship: patient.emergency_contact_relationship || "",
        emergencyContactPhone: patient.emergency_contact_phone || "",
        emergencyContactAltPhone: patient.emergency_contact_alt_phone || "",
        emergencyContactEmail: patient.emergency_contact_email || "",
        emergencyContactAddress: patient.emergency_contact_address || "",
        geofenceRadiusMeters: Number(patient.geofence_radius_meters || 100) || 100,
        statusClass: slugifyValue(patient.status || "Active"),
        personalCareNeeds: parseJsonArrayField(patient.care_needs_personal_care),
        mobilityNeeds: parseJsonArrayField(patient.care_needs_mobility),
        clinicalTasks: parseJsonArrayField(patient.care_needs_clinical_tasks),
        medicalConditions: parseJsonArrayField(patient.care_needs_medical_conditions),
        dailyLivingNeeds: parseJsonArrayField(patient.care_needs_daily_living),
        riskFlags: parseJsonArrayField(patient.care_needs_risks),
        communicationNeedsList: parseJsonArrayField(patient.care_needs_communication),
        lifestylePreferences: parseJsonArrayField(patient.care_needs_lifestyle),
        equipmentNeeds: parseJsonArrayField(patient.care_needs_equipment),
        serviceTypes: parseJsonArrayField(patient.care_needs_service_types),
        current_medication: patient.current_medication || "",
        medication_schedule: patient.medication_schedule || "",
        gp_name: patient.gp_name || "",
        gp_phone: patient.gp_phone || "",
        consultant_name: patient.consultant_name || "",
        hospital_name: patient.hospital_name || "",
        pharmacy_name: patient.pharmacy_name || "",
        vaccination_status: patient.vaccination_status || "",
        dnar_status: patient.dnar_status || "",
        falls_risk_level: patient.falls_risk_level || patient.risk_level || "",
        infection_risks: patient.infection_risks || "",
        key_safe_code: patient.key_safe_code || "",
        door_code: patient.door_code || "",
        alarm_code: patient.alarm_code || "",
        parking_instructions: patient.parking_instructions || "",
        pets: patient.pets || "",
        lift_available: Boolean(Number(patient.lift_available || 0)),
        stairs: patient.stairs || "",
        access_notes: patient.access_notes || "",
        shift_instructions: patient.shift_instructions || "",
        preferredDays: parseJsonArrayField(patient.preferred_days),
        preferredTimes: parseJsonArrayField(patient.preferred_times),
        visit_duration: patient.visit_duration || "",
        custom_visit_duration: patient.custom_visit_duration || "",
        visit_frequency: patient.visit_frequency || "",
        custom_visit_frequency: patient.custom_visit_frequency || "",
        preferred_staff_gender: patient.preferred_staff_gender || "",
        internal_notes: patient.internal_notes || "",
    };
};

const getActiveStaffMembers = async () => (await allDb(
    "SELECT * FROM staff WHERE lower(COALESCE(status, 'active')) NOT IN ('suspended', 'inactive', 'archived') ORDER BY first_name, last_name"
)).map(mapStaffRow);

const getPatientAssignments = async (patientId) => allDb(
    `SELECT pa.*, s.first_name, s.last_name, s.name, s.role, s.status, s.email, s.phone
     FROM patient_assignments pa
     LEFT JOIN staff s ON s.id = pa.staff_id
     WHERE pa.patient_id = ?
     ORDER BY pa.assignment_role`,
    [patientId]
);

const getAssignedPatientsForStaff = async (staffId) => (await allDb(
    `SELECT p.*, pa.assignment_role
     FROM patient_assignments pa
     INNER JOIN patients p ON p.id = pa.patient_id
     WHERE pa.staff_id = ? AND COALESCE(p.is_archived, 0) = 0
     ORDER BY p.last_name, p.first_name`,
    [staffId]
)).map(mapPatientRow);

const syncPatientAssignments = async (patientId, assignments) => {
    await runDb("DELETE FROM patient_assignments WHERE patient_id = ?", [patientId]);
    for (const assignment of assignments) {
        if (!assignment.staffId) {
            continue;
        }
        await runDb(
            `INSERT INTO patient_assignments (patient_id, staff_id, assignment_role)
             VALUES (?, ?, ?)`,
            [patientId, assignment.staffId, assignment.assignmentRole]
        );
    }
};

const parsePatientDocuments = (value) => {
    const parsed = safeJsonParse(value, []);
    if (!Array.isArray(parsed)) {
        return [];
    }

    return parsed
        .map((entry) => ({
            id: entry && entry.id ? Number(entry.id) : null,
            title: String((entry && entry.title) || "").trim(),
            category: documentCategories.includes(String((entry && entry.category) || "").trim())
                ? String(entry.category).trim()
                : "Other Documents",
            fileName: String((entry && entry.fileName) || "").trim(),
            mimeType: String((entry && entry.mimeType) || "application/octet-stream").trim(),
            dataUrl: String((entry && entry.dataUrl) || "").trim(),
            isStaffVisible: Boolean(entry && entry.isStaffVisible),
        }))
        .filter((entry) => entry.title && entry.fileName && entry.dataUrl);
};

const syncPatientDocuments = async (patientId, documents, uploadedBy) => {
    await runDb("DELETE FROM patient_documents WHERE patient_id = ?", [patientId]);
    for (const document of documents) {
        await runDb(
            `INSERT INTO patient_documents (patient_id, title, category, file_name, mime_type, data_url, is_staff_visible, uploaded_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                patientId,
                document.title,
                document.category,
                document.fileName,
                document.mimeType,
                document.dataUrl,
                document.isStaffVisible ? 1 : 0,
                uploadedBy || null,
            ]
        );
    }
};

const buildPatientPayloadFromBody = (body) => {
    const carePlanDailyRoutine = sanitizeRichText(body.care_plan_daily_routine);
    const carePlanPreferences = sanitizeRichText(body.care_plan_preferences);
    const carePlanLikes = sanitizeRichText(body.care_plan_likes);
    const carePlanDislikes = sanitizeRichText(body.care_plan_dislikes);
    const carePlanCommunication = sanitizeRichText(body.care_plan_communication);
    const carePlanDiet = sanitizeRichText(body.care_plan_diet);
    const carePlanFluids = sanitizeRichText(body.care_plan_fluids);
    const carePlanBehaviour = sanitizeRichText(body.care_plan_behaviour_support);
    const carePlanRiskInfo = sanitizeRichText(body.care_plan_risk_information);
    const carePlanGoals = sanitizeRichText(body.care_plan_goals);
    const shiftInstructions = sanitizeRichText(body.shift_instructions);
    const dateOfBirth = String(body.date_of_birth || "").trim();
    const careLevel = String(body.care_level || "").trim();
    const diagnoses = String(body.diagnoses || "").trim();
    const assignments = careTeamRoles
        .map((role) => ({
            assignmentRole: role.key,
            assignmentLabel: role.label,
            staffId: Number(body[`${role.key}_staff_id`]) || null,
        }))
        .filter((assignment) => assignment.staffId);

    return {
        first_name: String(body.first_name || "").trim(),
        last_name: String(body.last_name || "").trim(),
        preferred_name: String(body.preferred_name || "").trim(),
        photo_url: String(body.photo_url || "").trim(),
        date_of_birth: dateOfBirth,
        age: calculateAgeFromDateOfBirth(dateOfBirth),
        gender: String(body.gender || "").trim(),
        marital_status: String(body.marital_status || "").trim(),
        nationality: String(body.nationality || "").trim(),
        pps_number: String(body.pps_number || "").trim(),
        primary_language: String(body.primary_language || "").trim(),
        interpreter_required: toFlagInteger(body.interpreter_required),
        address: String(body.address || "").trim(),
        eircode: String(body.eircode || "").trim().toUpperCase(),
        county: String(body.county || "").trim(),
        phone: String(body.phone || "").trim(),
        alternative_phone: String(body.alternative_phone || "").trim(),
        email: String(body.email || "").trim().toLowerCase(),
        latitude: body.latitude !== undefined && String(body.latitude).trim() !== "" ? Number(body.latitude) : null,
        longitude: body.longitude !== undefined && String(body.longitude).trim() !== "" ? Number(body.longitude) : null,
        geofence_radius_meters: Math.max(25, Number(body.geofence_radius_meters) || 100),
        status: patientStatusOptions.includes(String(body.status || "").trim()) ? String(body.status).trim() : "Active",
        care_level: careLevel,
        risk_level: String(body.risk_level || body.falls_risk_level || "").trim(),
        care_needs_personal_care: serializeJsonField(normalizeStringList(body.personal_care_needs)),
        care_needs_mobility: serializeJsonField(normalizeStringList(body.mobility_needs)),
        care_needs_clinical_tasks: serializeJsonField(normalizeStringList(body.clinical_task_needs)),
        care_needs_medical_conditions: serializeJsonField(normalizeStringList(body.medical_condition_needs)),
        care_needs_daily_living: serializeJsonField(normalizeStringList(body.daily_living_needs)),
        care_needs_risks: serializeJsonField(normalizeStringList(body.risk_needs)),
        care_needs_communication: serializeJsonField(normalizeStringList(body.communication_needs)),
        care_needs_lifestyle: serializeJsonField(normalizeStringList(body.lifestyle_needs)),
        care_needs_equipment: serializeJsonField(normalizeStringList(body.equipment_needs)),
        care_needs_service_types: serializeJsonField(normalizeStringList(body.service_type_needs)),
        diagnoses,
        condition: diagnoses || careLevel,
        allergies: String(body.allergies || "").trim(),
        current_medication: String(body.current_medication || "").trim(),
        medication_schedule: String(body.medication_schedule || "").trim(),
        gp_name: String(body.gp_name || "").trim(),
        gp_phone: String(body.gp_phone || "").trim(),
        consultant_name: String(body.consultant_name || "").trim(),
        hospital_name: String(body.hospital_name || "").trim(),
        pharmacy_name: String(body.pharmacy_name || "").trim(),
        vaccination_status: String(body.vaccination_status || "").trim(),
        dnar_status: String(body.dnar_status || "").trim(),
        falls_risk_level: String(body.falls_risk_level || "").trim(),
        infection_risks: String(body.infection_risks || "").trim(),
        emergency_contact_name: String(body.emergency_contact_name || "").trim(),
        emergency_contact_relationship: String(body.emergency_contact_relationship || "").trim(),
        emergency_contact_phone: String(body.emergency_contact_phone || "").trim(),
        emergency_contact_alt_phone: String(body.emergency_contact_alt_phone || "").trim(),
        emergency_contact_email: String(body.emergency_contact_email || "").trim().toLowerCase(),
        emergency_contact_address: String(body.emergency_contact_address || "").trim(),
        emergency_contact: String(body.emergency_contact_name || "").trim(),
        key_safe_code: String(body.key_safe_code || "").trim(),
        door_code: String(body.door_code || "").trim(),
        alarm_code: String(body.alarm_code || "").trim(),
        parking_instructions: String(body.parking_instructions || "").trim(),
        pets: String(body.pets || "").trim(),
        lift_available: toFlagInteger(body.lift_available),
        stairs: String(body.stairs || "").trim(),
        access_notes: String(body.access_notes || "").trim(),
        care_plan_daily_routine: carePlanDailyRoutine,
        care_plan_preferences: carePlanPreferences,
        care_plan_likes: carePlanLikes,
        care_plan_dislikes: carePlanDislikes,
        care_plan_communication: carePlanCommunication,
        care_plan_diet: carePlanDiet,
        care_plan_fluids: carePlanFluids,
        care_plan_behaviour_support: carePlanBehaviour,
        care_plan_risk_information: carePlanRiskInfo,
        care_plan_goals: carePlanGoals,
        carePlan: [carePlanDailyRoutine, carePlanPreferences, carePlanLikes, carePlanDislikes, carePlanCommunication, carePlanDiet, carePlanFluids, carePlanBehaviour, carePlanRiskInfo, carePlanGoals].filter(Boolean).join("\n\n"),
        shift_instructions: shiftInstructions,
        preferred_days: serializeJsonField(normalizeStringList(body.preferred_days)),
        preferred_times: serializeJsonField(normalizeStringList(body.preferred_times)),
        visit_duration: String(body.visit_duration || "").trim(),
        custom_visit_duration: String(body.custom_visit_duration || "").trim(),
        visit_frequency: String(body.visit_frequency || "").trim(),
        custom_visit_frequency: String(body.custom_visit_frequency || "").trim(),
        preferred_staff_gender: String(body.preferred_staff_gender || "").trim(),
        internal_notes: String(body.internal_notes || "").trim(),
        assignments,
        documents: parsePatientDocuments(body.documents_payload),
    };
};

const validatePatientPayload = (payload) => {
    if (!payload.first_name || !payload.last_name) {
        return "First name and last name are required.";
    }
    if (!payload.date_of_birth) {
        return "Date of birth is required.";
    }
    if (!payload.address) {
        return "Home address is required.";
    }
    if (!payload.phone) {
        return "Phone number is required.";
    }
    if (!Number.isFinite(payload.latitude) || !Number.isFinite(payload.longitude)) {
        return "A valid GPS location is required.";
    }
    return null;
};

const buildPatientStatusNotification = (status, patientName) => {
    switch (status) {
    case "In Hospital":
        return `${patientName} has been marked as in hospital. Future visits have been paused pending review.`;
    case "On Holiday":
        return `${patientName} is on holiday. Future visits have been paused until the client returns.`;
    case "Discharged":
        return `${patientName} has been discharged. New schedules are blocked while historical records remain available.`;
    case "Deceased":
        return `${patientName} has been marked as deceased. Future visits have been cancelled and the record archived.`;
    case "Archived":
        return `${patientName} has been archived and removed from active lists.`;
    default:
        return `${patientName}'s client status is now ${status}.`;
    }
};

const applyPatientStatusAutomation = async (patientId, status, patientName, staffIds) => {
    const normalizedStatus = String(status || "");
    const futureShiftFilter = "patient_id = ? AND datetime(COALESCE(scheduled_start, shift_date)) >= datetime('now') AND status IN ('scheduled', 'clocked_in', 'clocked_out')";
    if (normalizedStatus === "In Hospital" || normalizedStatus === "On Holiday") {
        await runDb(`UPDATE staff_shifts SET status = 'cancelled' WHERE ${futureShiftFilter}`, [patientId]);
    }
    if (normalizedStatus === "Deceased") {
        await runDb(`UPDATE staff_shifts SET status = 'cancelled' WHERE ${futureShiftFilter}`, [patientId]);
        await runDb(
            `UPDATE patients
             SET is_archived = 1,
                 archived_at = datetime('now')
             WHERE id = ?`,
            [patientId]
        );
    }
    if (normalizedStatus === "Archived") {
        await runDb(
            `UPDATE patients
             SET is_archived = 1,
                 archived_at = datetime('now')
             WHERE id = ?`,
            [patientId]
        );
    }
    if (normalizedStatus !== "Archived" && normalizedStatus !== "Deceased") {
        await runDb(
            `UPDATE patients
             SET is_archived = CASE WHEN ? = 'Archived' THEN 1 ELSE COALESCE(is_archived, 0) END
             WHERE id = ?`,
            [normalizedStatus, patientId]
        );
    }

    const notificationMessage = buildPatientStatusNotification(normalizedStatus, patientName);
    for (const staffId of staffIds) {
        await queueStaffNotification(staffId, "Client status updated", notificationMessage, "shift", "/portal/home");
    }
    emitPortalEvent("patient_update", { action: "status_changed", patientId: Number(patientId), status: normalizedStatus });
};

const parseStaffRecordCollection = (value, fallbackItems = []) => {
    const parsed = safeJsonParse(value, null);
    if (Array.isArray(parsed)) {
        return parsed
            .map((entry) => ({
                item: String((entry && entry.item) || "").trim(),
                completed: Boolean(entry && entry.completed),
                issueDate: String((entry && entry.issueDate) || "").trim(),
                expiryDate: String((entry && entry.expiryDate) || "").trim(),
                reminderDays: Number(entry && entry.reminderDays) || 30,
                trafficLight: ["Green", "Amber", "Red"].includes(String(entry && entry.trafficLight)) ? String(entry.trafficLight) : "Amber",
                certificateData: String((entry && entry.certificateData) || "").trim(),
                certificateName: String((entry && entry.certificateName) || "").trim(),
            }))
            .filter((entry) => entry.item);
    }

    return normalizeStringList(fallbackItems).map((item) => ({
        item,
        completed: false,
        issueDate: "",
        expiryDate: "",
        reminderDays: 30,
        trafficLight: "Amber",
        certificateData: "",
        certificateName: "",
    }));
};

const isExpirySoon = (value, windowDays = 30) => {
    const raw = String(value || "").trim();
    if (!raw) {
        return false;
    }
    const expiry = new Date(`${raw}T23:59:59`);
    if (Number.isNaN(expiry.getTime())) {
        return false;
    }
    const now = new Date();
    const days = Math.ceil((expiry.getTime() - now.getTime()) / (24 * 60 * 60 * 1000));
    return days >= 0 && days <= windowDays;
};

const buildStaffComplianceSnapshot = (trainingRecords, certificationRecords, visaExpiryDate, nmbiExpiryDate, gardaVettingStatus) => {
    const normalizedTraining = Array.isArray(trainingRecords) ? trainingRecords : [];
    const normalizedCerts = Array.isArray(certificationRecords) ? certificationRecords : [];
    const completedCount = normalizedTraining.filter((item) => item.completed).length;
    const outstandingCount = Math.max(normalizedTraining.length - completedCount, 0);
    const certificateExpiringCount = normalizedCerts.filter((item) => isExpirySoon(item.expiryDate, Number(item.reminderDays) || 30)).length;
    const overallCompliance = normalizedTraining.length ? Math.round((completedCount / normalizedTraining.length) * 100) : 100;

    return {
        overallCompliance,
        trainingCompleted: completedCount,
        trainingOutstanding: outstandingCount,
        certificatesExpiring: certificateExpiringCount,
        gardaVettingStatus: gardaVettingStatus || "Pending",
        visaStatus: visaExpiryDate ? (isExpirySoon(visaExpiryDate, 30) ? "Expiring Soon" : "Active") : "Not required",
        nmbiStatus: nmbiExpiryDate ? (isExpirySoon(nmbiExpiryDate, 30) ? "Expiring Soon" : "Active") : "Pending",
        trafficLight: overallCompliance >= 90 ? "Green" : overallCompliance >= 60 ? "Amber" : "Red",
    };
};

const buildStaffProfilePayload = (body = {}, existingStaff = null) => {
    const explicitFirstName = String(body.first_name || "").trim();
    const explicitLastName = String(body.last_name || "").trim();
    const composedName = normalizeStringList([explicitFirstName, explicitLastName]).join(" ");
    const fullName = String(body.name || composedName).trim();
    const [firstName, ...lastNameParts] = fullName.split(/\s+/);
    const lastName = explicitLastName || lastNameParts.join(" ") || "";
    const role = String(body.role || "").trim() || "Care Assistant";
    const status = staffStatusOptions.includes(String(body.status || "")) ? String(body.status) : "Active";
    const email = String(body.email || "").trim().toLowerCase();
    const phone = String(body.mobile_number || body.phone || "").trim();
    const homeAddress = String(body.home_address || body.address || "").trim();
    const emergencyContactName = String(body.emergency_contact_name || body.emergency_contact || "").trim();
    const mandatoryTraining = normalizeStringList(Array.isArray(body.mandatory_training) ? body.mandatory_training : (body.mandatory_training ? [body.mandatory_training] : []));
    const skills = normalizeStringList(Array.isArray(body.skills_specialities) ? body.skills_specialities : (body.skills_specialities ? [body.skills_specialities] : []));
    const languages = normalizeStringList(Array.isArray(body.languages) ? body.languages : (body.languages ? [body.languages] : []));
    const availabilityDays = normalizeStringList(Array.isArray(body.availability_days) ? body.availability_days : (body.availability_days ? [body.availability_days] : []));
    const shiftPreferences = normalizeStringList(Array.isArray(body.shift_preferences) ? body.shift_preferences : (body.shift_preferences ? [body.shift_preferences] : []));
    const serviceTypes = normalizeStringList(Array.isArray(body.service_types) ? body.service_types : (body.service_types ? [body.service_types] : []))
        .filter((value) => staffServiceTypeOptions.includes(value));
    const qualifications = normalizeStringList(Array.isArray(body.qqi_qualifications) ? body.qqi_qualifications : (body.qqi_qualifications ? [body.qqi_qualifications] : []));
    const professionalRegistration = normalizeStringList(Array.isArray(body.professional_registration) ? body.professional_registration : (body.professional_registration ? [body.professional_registration] : []));
    const otherQualifications = normalizeDelimitedStringList(body.other_qualifications);
    const additionalCertifications = normalizeStringList(Array.isArray(body.additional_certifications) ? body.additional_certifications : (body.additional_certifications ? [body.additional_certifications] : []));
    const trainingRecords = parseStaffRecordCollection(body.training_records_json, mandatoryTraining);
    const certificationRecords = parseStaffRecordCollection(body.certification_records_json, additionalCertifications);
    const assignedClientIds = normalizeStringList(Array.isArray(body.assigned_client_ids) ? body.assigned_client_ids : (body.assigned_client_ids ? [body.assigned_client_ids] : []));
    const portalLoginEnabled = status === "Active" ? 1 : 0;
    const nmbiExpiryDate = String(body.nmbi_expiry_date || "").trim();
    const gardaVettingStatus = String(body.garda_vetting_status || "Pending").trim();
    const complianceSummary = buildStaffComplianceSnapshot(
        trainingRecords,
        certificationRecords,
        String(body.visa_expiry_date || "").trim(),
        nmbiExpiryDate,
        gardaVettingStatus
    );

    return {
        name: fullName,
        firstName: explicitFirstName || firstName || fullName,
        lastName,
        role,
        email,
        phone,
        status,
        homeAddress,
        emergencyContactName,
        availability: String(body.availability || "").trim(),
        managerName: String(body.manager_name || "").trim(),
        startDate: String(body.start_date || "").trim() || null,
        endDate: String(body.end_date || "").trim() || null,
        employeeNumber: String(body.employee_number || "").trim() || (existingStaff ? existingStaff.employeeNumber : ""),
        preferredName: String(body.preferred_name || "").trim(),
        profilePhoto: String(body.profile_photo || "").trim(),
        dateOfBirth: String(body.date_of_birth || "").trim() || null,
        gender: String(body.gender || "").trim(),
        nationality: String(body.nationality || "").trim(),
        ppsNumber: String(body.pps_number || "").trim(),
        drivingLicenceNumber: String(body.driving_licence_number || "").trim(),
        drivingLicenceCategories: serializeJsonField(normalizeDelimitedStringList(body.driving_licence_categories)),
        ownVehicle: toFlagInteger(body.own_vehicle),
        rightToWork: String(body.right_to_work || "").trim(),
        visaType: String(body.visa_type || "").trim(),
        visaExpiryDate: String(body.visa_expiry_date || "").trim() || null,
        passportNumber: String(body.passport_number || "").trim(),
        passportExpiryDate: String(body.passport_expiry_date || "").trim() || null,
        alternativePhone: String(body.alternative_phone || "").trim(),
        eircode: String(body.eircode || "").trim(),
        county: String(body.county || "").trim(),
        emergencyContactRelationship: String(body.emergency_contact_relationship || "").trim(),
        emergencyContactPhone: String(body.emergency_contact_phone || "").trim(),
        emergencyContactEmail: String(body.emergency_contact_email || "").trim(),
        employmentType: String(body.employment_type || "").trim() || "Full Time",
        employmentStatus: status,
        hourlyRate: String(body.hourly_rate || "").trim(),
        payrollNumber: String(body.payroll_number || "").trim(),
        branch: String(body.branch || "").trim(),
        managerName: String(body.manager_name || "").trim(),
        qqiQualifications: serializeJsonField(qualifications),
        professionalRegistration: serializeJsonField(professionalRegistration),
        otherQualifications: serializeJsonField(otherQualifications),
        skillsSpecialities: serializeJsonField(skills),
        mandatoryTraining: serializeJsonField(mandatoryTraining),
        additionalCertifications: serializeJsonField(additionalCertifications),
        trainingRecords: serializeJsonField(trainingRecords),
        certificationRecords: serializeJsonField(certificationRecords),
        languages: serializeJsonField(languages),
        availabilityDays: serializeJsonField(availabilityDays),
        shiftPreferences: serializeJsonField(shiftPreferences),
        weekendAvailability: toFlagInteger(body.weekend_availability),
        bankHolidays: toFlagInteger(body.bank_holidays),
        maxWeeklyHours: String(body.max_weekly_hours || "").trim(),
        preferredWorkingArea: String(body.preferred_working_area || "").trim(),
        internalNotes: String(body.internal_notes || "").trim(),
        staffNotes: String(body.staff_notes || "").trim(),
        complianceSummary: serializeJsonField(complianceSummary),
        nmbiNumber: String(body.nmbi_number || "").trim(),
        nmbiExpiryDate: nmbiExpiryDate || null,
        gardaVettingStatus,
        gardaVettingExpiryDate: String(body.garda_vetting_expiry_date || "").trim() || null,
        portalLoginEnabled,
        portalLoginSuspended: toFlagInteger(body.portal_login_suspended),
        portalLoginDeactivated: toFlagInteger(body.portal_login_deactivated),
        welcomeEmailSent: toFlagInteger(body.welcome_email_sent),
        forcePasswordReset: toFlagInteger(body.force_password_reset),
        assignedClientIds,
        shift: String(body.shift_preference || body.shift || "").trim() || "Morning",
        serviceTypes: serializeJsonField(serviceTypes.length ? serviceTypes : ["Both"]),
    };
};

const mapStaffRow = (member) => {
    if (!member) {
        return member;
    }

    const parsedMandatoryTraining = parseJsonArrayField(member.mandatory_training);
    const parsedSkills = parseJsonArrayField(member.skills_specialities);
    const parsedLanguages = parseJsonArrayField(member.languages);
    const parsedAvailabilityDays = parseJsonArrayField(member.availability_days);
    const parsedShiftPreferences = parseJsonArrayField(member.shift_preferences);
    const parsedServiceTypes = parseStaffServiceTypes(member.service_types);
    const parsedComplianceSummary = parseJsonObjectField(member.compliance_summary);
    const parsedTrainingRecords = parseStaffRecordCollection(member.training_records, []);
    const parsedCertificationRecords = parseStaffRecordCollection(member.certification_records, []);
    const inductionChecklist = normalizeInductionChecklist(member.induction_checklist);

    const normalizedStatus = String(member.status || "Active").trim().toLowerCase();
    const resolvedName = member.name || formatName(member.first_name, member.last_name);
    return {
        ...member,
        name: resolvedName,
        displayNameWithStatus: formatStaffDisplayName(resolvedName, normalizedStatus),
        role: member.role || "Care Assistant",
        shift: member.shift || "Unassigned",
        status: member.status || "Active",
        firstName: member.first_name || "",
        lastName: member.last_name || "",
        preferredName: member.preferred_name || "",
        profilePhoto: member.profile_photo || "",
        dateOfBirth: member.date_of_birth || "",
        employeeNumber: member.employee_number || "",
        drivingLicenceNumber: member.driving_licence_number || "",
        drivingLicenceCategories: parseJsonArrayField(member.driving_licence_categories),
        ownVehicle: Boolean(Number(member.own_vehicle || 0)),
        rightToWork: member.right_to_work || "",
        visaType: member.visa_type || "",
        visaExpiryDate: member.visa_expiry_date || "",
        passportNumber: member.passport_number || "",
        passportExpiryDate: member.passport_expiry_date || "",
        mobileNumber: member.mobile_number || member.phone || "",
        alternativePhone: member.alternative_phone || "",
        homeAddress: member.home_address || member.address || "",
        eircode: member.eircode || "",
        county: member.county || "",
        emergencyContactName: member.emergency_contact_name || member.emergency_contact || "",
        emergencyContactRelationship: member.emergency_contact_relationship || "",
        emergencyContactPhone: member.emergency_contact_phone || "",
        emergencyContactEmail: member.emergency_contact_email || "",
        employmentType: member.employment_type || "Full Time",
        employmentStatus: member.employment_status || member.status || "Active",
        hourlyRate: member.hourly_rate || "",
        payrollNumber: member.payroll_number || "",
        branch: member.branch || "",
        managerName: member.manager_name || "",
        startDate: member.start_date || "",
        endDate: member.end_date || "",
        qqiQualifications: parseJsonArrayField(member.qqi_qualifications),
        professionalRegistration: parseJsonArrayField(member.professional_registration),
        otherQualifications: parseJsonArrayField(member.other_qualifications),
        skillsSpecialities: parsedSkills,
        mandatoryTraining: parsedMandatoryTraining,
        additionalCertifications: parseJsonArrayField(member.additional_certifications),
        trainingRecords: parsedTrainingRecords,
        certificationRecords: parsedCertificationRecords,
        languages: parsedLanguages,
        availabilityDays: parsedAvailabilityDays,
        shiftPreferences: parsedShiftPreferences,
        serviceTypes: parsedServiceTypes,
        weekendAvailability: Boolean(Number(member.weekend_availability || 0)),
        bankHolidays: Boolean(Number(member.bank_holidays || 0)),
        maxWeeklyHours: member.max_weekly_hours || "",
        preferredWorkingArea: member.preferred_working_area || "",
        internalNotes: member.internal_notes || "",
        staffNotes: member.staff_notes || "",
        complianceSummary: parsedComplianceSummary,
        inductionChecklist,
        inductionChecklistSummary: buildInductionChecklistSummary(inductionChecklist),
        nmbiNumber: member.nmbi_number || "",
        nmbiExpiryDate: member.nmbi_expiry_date || "",
        gardaVettingStatus: member.garda_vetting_status || "Pending",
        gardaVettingExpiryDate: member.garda_vetting_expiry_date || "",
        portalLoginEnabled: Boolean(Number(member.portal_login_enabled ?? 1)),
        portalLoginSuspended: Boolean(Number(member.portal_login_suspended || 0)),
        portalLoginDeactivated: Boolean(Number(member.portal_login_deactivated || 0)),
        welcomeEmailSent: Boolean(Number(member.welcome_email_sent || 0)),
        forcePasswordReset: Boolean(Number(member.force_password_reset || 0)),
        appLockEnabled: Boolean(Number(member.app_lock_enabled || 0)),
        appLockMethod: member.app_lock_method || "",
        reminderLeadMinutes: Number(member.reminder_lead_minutes || 60),
        notifyShiftReminders: Boolean(Number(member.notify_shift_reminders ?? 1)),
        notifyNewShift: Boolean(Number(member.notify_new_shift ?? 1)),
        notifyOpenShift: Boolean(Number(member.notify_open_shift ?? 1)),
        notifyAnnouncements: Boolean(Number(member.notify_announcements ?? 1)),
        notifyTrainingReminders: Boolean(Number(member.notify_training_reminders ?? 1)),
        notifyComplianceAlerts: Boolean(Number(member.notify_compliance_alerts ?? 1)),
        notifyScheduleChanges: Boolean(Number(member.notify_schedule_changes ?? 1)),
    };
};

const mapAppointmentRow = (appointment) => {
    if (!appointment) {
        return appointment;
    }

    const staffName = formatStaffDisplayName(
        appointment.staff_name || appointment.staffName || "",
        appointment.staff_status || appointment.staffStatus || ""
    );
    return {
        ...appointment,
        client: appointment.client || appointment.patient_name || "Patient",
        date: appointment.date || (appointment.start ? new Date(appointment.start).toISOString().slice(0, 10) : null),
        time: appointment.time || (appointment.start ? new Date(appointment.start).toISOString().slice(11, 16) : null),
        type: appointment.type || appointment.title || "Visit",
        notes: appointment.notes || "No additional notes.",
        staff_name: staffName,
        staffName,
    };
};

const getBusinessDateKey = (value = new Date()) => {
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) {
        return "";
    }
    const formatter = new Intl.DateTimeFormat("en-CA", { timeZone: "Europe/Dublin", year: "numeric", month: "2-digit", day: "2-digit" });
    const parts = formatter.formatToParts(date);
    const mapped = {};
    for (const part of parts) {
        if (part.type !== "literal") {
            mapped[part.type] = part.value;
        }
    }
    return mapped.year && mapped.month && mapped.day ? `${mapped.year}-${mapped.month}-${mapped.day}` : "";
};

const getEffectiveShiftState = (shift, now = new Date(), gracePeriodMinutes = 15) => {
    if (!shift) {
        return "scheduled";
    }

    const rawStatus = String(shift.status || "").trim().toLowerCase();
    const scheduledStartValue = shift.scheduledStart || shift.scheduled_start || shift.shift_date || shift.start || "";
    const scheduledEndValue = shift.scheduledEnd || shift.scheduled_end || shift.end || "";
    const scheduledStart = scheduledStartValue ? new Date(normalizeDateTimeString(scheduledStartValue)) : null;
    const scheduledEnd = scheduledEndValue ? new Date(normalizeDateTimeString(scheduledEndValue)) : null;
    const hasClockIn = Boolean(shift.actual_clock_in || shift.actualClockIn);
    const hasClockOut = Boolean(shift.actual_clock_out || shift.actualClockOut);
    const hasValidStart = scheduledStart && !Number.isNaN(scheduledStart.getTime());
    const hasValidEnd = scheduledEnd && !Number.isNaN(scheduledEnd.getTime());
    const currentBusinessDate = getBusinessDateKey(now);
    const shiftBusinessDate = hasValidStart ? getBusinessDateKey(scheduledStart) : "";
    const shiftHasEnded = hasValidEnd
        ? scheduledEnd.getTime() <= now.getTime()
        : Boolean(shiftBusinessDate && shiftBusinessDate < currentBusinessDate);

    if (rawStatus === "cancelled") {
        return "cancelled";
    }
    if (["no_show", "missed", "absent", "unworked"].includes(rawStatus)) {
        return "missed";
    }
    if (hasClockIn && hasClockOut) {
        return "completed";
    }
    if (hasClockIn !== hasClockOut) {
        if (!hasClockIn || shiftHasEnded) {
            return "attendance_exception";
        }
        if (["on_break", "break"].includes(rawStatus)) {
            return "break";
        }
        return "clocked_in";
    }
    if (!hasValidStart) {
        return "scheduled";
    }

    if (shiftBusinessDate > currentBusinessDate || scheduledStart.getTime() > now.getTime()) {
        return "scheduled";
    }
    if (shiftHasEnded || shiftBusinessDate < currentBusinessDate) {
        return "missed";
    }

    const graceCutoff = scheduledStart.getTime() + (gracePeriodMinutes * 60 * 1000);
    return now.getTime() > graceCutoff ? "running_late" : "not_clocked_in";
};

const isAvailableOpenShift = (shift, now = new Date()) => Boolean(
    shift
    && Number(shift.is_open || shift.isOpen || 0) === 1
    && !(shift.staff_id || shift.staffId)
    && getEffectiveShiftState(shift, now) === "scheduled"
);

const mapShiftRow = (shift, referenceTime = new Date(), gracePeriodMinutes = 15) => {
    if (!shift) {
        return shift;
    }
    const now = referenceTime instanceof Date ? referenceTime : new Date();
    const division = getShiftDivision(shift);
    const hasAssignedStaff = Boolean(shift.staff_id || shift.staffId);
    const isOpen = Boolean(Number(shift.is_open || shift.isOpen || 0));
    const effectiveStatus = getEffectiveShiftState(shift, now, gracePeriodMinutes);
    let operationalStatus = "assigned";
    if (isOpen && !hasAssignedStaff && effectiveStatus === "scheduled") {
        operationalStatus = "open";
    } else if (effectiveStatus === "clocked_in") {
        operationalStatus = "on_duty";
    } else {
        operationalStatus = effectiveStatus;
    }
    const statusLabel = effectiveStatus === "clocked_in" ? "On Duty"
        : effectiveStatus === "not_clocked_in" ? "Not Clocked In"
            : effectiveStatus === "running_late" ? "Running Late"
                : effectiveStatus === "attendance_exception"
                    ? (shift.actual_clock_in || shift.actualClockIn ? "Missing Clock-Out" : "Attendance Exception")
                    : effectiveStatus === "missed" ? "Missed / No Show"
                        : effectiveStatus.charAt(0).toUpperCase() + effectiveStatus.slice(1).replace(/_/g, " ");
    const statusClass = effectiveStatus === "clocked_in" || effectiveStatus === "break" ? "clocked_in"
        : ["not_clocked_in", "running_late", "attendance_exception", "missed"].includes(effectiveStatus) ? "no_show"
            : effectiveStatus;
    const divisionLabel = division === "agency-staffing" ? "🏥 AGENCY" : "🏠 HOME CARE";
    const homeCareClientName = shift.home_care_client_name || shift.patient_name || shift.patientName || shift.external_client_label || "Home Care Client";
    const facilityName = shift.facility_name || shift.organization_name || shift.external_client_label || "Healthcare Facility";
    const roleRequired = shift.role_required || shift.staff_required || shift.role || shift.service_type || shift.serviceType || "";
    const requirementLabel = shift.shift_requirements || shift.care_instructions || shift.notes || shift.service_type || shift.serviceType || "Not specified";

    return {
        ...shift,
        serviceDivision: division,
        serviceDivisionLabel: divisionLabel,
        serviceDivisionClass: division === "agency-staffing" ? "agency" : "home-care",
        shiftCode: shift.shift_code || shift.shiftCode || null,
        homeCareClientName,
        facilityName,
        displayEntityName: division === "agency-staffing" ? facilityName : homeCareClientName,
        operationalStatus,
        roleRequired,
        requirementLabel,
        requiredSkills: parseJsonArrayField(shift.required_skills),
        requiredTraining: parseJsonArrayField(shift.required_training),
        patientName: shift.patientName || shift.patient_name || shift.external_client_label || "Patient",
        staffName: formatStaffDisplayName(
            shift.staffName || shift.staff_name || "",
            shift.staffStatus || shift.staff_status || ""
        ),
        patientId: shift.patient_id || shift.patientId || null,
        staffId: shift.staff_id || shift.staffId || null,
        clientAccountId: shift.client_account_id || shift.clientAccountId || null,
        clientRequestId: shift.client_request_id || shift.clientRequestId || null,
        scheduledStart: shift.scheduled_start || shift.start || null,
        scheduledEnd: shift.scheduled_end || shift.end || null,
        storedStatus: shift.storedStatus || shift.status || "scheduled",
        status: effectiveStatus,
        statusLabel,
        statusClass,
        serviceType: shift.service_type || shift.serviceType || "Personal Care",
        notes: shift.notes || "",
        careInstructions: shift.care_instructions || shift.notes || "",
        address: shift.address || shift.location_address || shift.facility_address || "",
        county: shift.county || shift.location_county || shift.facility_county || "",
        eircode: shift.eircode || shift.location_eircode || "",
        latitude: shift.latitude || shift.external_latitude || null,
        longitude: shift.longitude || shift.external_longitude || null,
    };
};

const shiftMatchesScheduleStatus = (shift, statusFilter) => {
    if (!statusFilter || statusFilter === "all") {
        return true;
    }
    if (statusFilter === "open") {
        return shift.operationalStatus === "open";
    }
    if (statusFilter === "assigned" || statusFilter === "scheduled") {
        return shift.status === "scheduled" && shift.operationalStatus !== "open";
    }
    if (statusFilter === "in_progress") {
        return ["not_clocked_in", "running_late", "clocked_in", "break"].includes(shift.status);
    }
    if (statusFilter === "on_duty") {
        return shift.status === "clocked_in";
    }
    return shift.status === statusFilter;
};

const buildScheduleSummary = (shifts) => {
    const scheduled = shifts.filter((shift) => shiftMatchesScheduleStatus(shift, "scheduled")).length;
    return {
        all: shifts.length,
        homeCare: shifts.filter((shift) => shift.serviceDivision === "home-care").length,
        agency: shifts.filter((shift) => shift.serviceDivision === "agency-staffing").length,
        open: shifts.filter((shift) => shift.operationalStatus === "open").length,
        scheduled,
        assigned: scheduled,
        inProgress: shifts.filter((shift) => shiftMatchesScheduleStatus(shift, "in_progress")).length,
        completed: shifts.filter((shift) => shift.status === "completed").length,
        missed: shifts.filter((shift) => shift.status === "missed").length,
        attendanceExceptions: shifts.filter((shift) => shift.status === "attendance_exception").length,
        cancelled: shifts.filter((shift) => shift.status === "cancelled").length,
    };
};

const isEmergencyTrackingShift = (shift) => {
    const rawStatus = String(shift.storedStatus || shift.status || "").trim().toLowerCase();
    return rawStatus.includes("emergency")
        || rawStatus.includes("sos")
        || String(shift.notes || "").toLowerCase().includes("sos");
};

const isActiveLiveTrackingShift = (shift) => !["completed", "missed", "attendance_exception", "cancelled"].includes(shift.status)
    && (isEmergencyTrackingShift(shift) || ["not_clocked_in", "running_late", "clocked_in", "break"].includes(shift.status));

const isCountableTodayShift = (shift) => ["scheduled", "not_clocked_in", "running_late", "clocked_in", "break", "completed", "attendance_exception"].includes(shift.status);

const getShiftBusinessDateKey = (shift) => {
    const value = shift.scheduledStart || shift.scheduled_start || shift.shiftDate || shift.shift_date || "";
    const text = String(value).trim();
    if (/^\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2}(?::\d{2})?)?$/.test(text)) {
        return text.slice(0, 10);
    }
    return getBusinessDateKey(normalizeDateTimeString(value));
};

const getOperationalShiftCounts = async (now = new Date()) => {
    const candidateRows = await allDb(`
        SELECT staff_id, shift_date, scheduled_start, scheduled_end,
               actual_clock_in, actual_clock_out, status, is_open,
               service_division, notes
        FROM staff_shifts
        WHERE COALESCE(is_open, 0) = 0
    `);
    const shifts = candidateRows.map((shift) => mapShiftRow(shift, now));
    const currentBusinessDate = getBusinessDateKey(now);
    const todayShifts = shifts.filter((shift) => getShiftBusinessDateKey(shift) === currentBusinessDate);

    return {
        homeVisits: todayShifts.filter((shift) => shift.serviceDivision === "home-care" && isCountableTodayShift(shift)).length,
        scheduled: shifts.filter((shift) => shift.staffId && shiftMatchesScheduleStatus(shift, "scheduled")).length,
        liveTracking: todayShifts.filter((shift) => shift.staffId && isActiveLiveTrackingShift(shift)).length,
        todayShifts: todayShifts.filter(isCountableTodayShift).length,
    };
};

const getAvailableOpenShiftCount = async (now = new Date()) => {
    const rows = await allDb(`
        SELECT staff_id, shift_date, scheduled_start, scheduled_end,
               actual_clock_in, actual_clock_out, status, is_open
        FROM staff_shifts
        WHERE COALESCE(is_open, 0) = 1
          AND staff_id IS NULL
    `);
    return rows.filter((shift) => isAvailableOpenShift(shift, now)).length;
};

const getDashboardShiftCollections = async (now = new Date()) => {
    const selectDashboardShift = `
        SELECT ss.*,
               COALESCE(p.first_name || ' ' || p.last_name, ss.external_client_label, 'Client') AS patient_name,
               s.first_name || ' ' || s.last_name AS staff_name,
               s.status AS staff_status
        FROM staff_shifts ss
        LEFT JOIN patients p ON p.id = ss.patient_id
        LEFT JOIN staff s ON s.id = ss.staff_id
    `;
    const [recentRows, scheduledCandidates] = await Promise.all([
        allDb(`${selectDashboardShift} ORDER BY ss.created_at DESC LIMIT 4`),
        allDb(`${selectDashboardShift}
            WHERE ss.staff_id IS NOT NULL
              AND COALESCE(ss.is_open, 0) = 0
            ORDER BY COALESCE(ss.scheduled_start, ss.shift_date) ASC`),
    ]);

    const recentActivity = recentRows.map((row) => {
        const shift = mapShiftRow(row, now);
        const isLive = ["clocked_in", "break"].includes(shift.status);
        return {
            type: isLive ? "Live shift" : shift.statusLabel,
            statusClass: shift.statusClass,
            label: shift.patientName || "Patient",
            detail: shift.staffName ? `${shift.staffName} · ${shift.statusLabel}` : shift.statusLabel,
        };
    });
    const upcomingVisits = scheduledCandidates
        .map((row) => mapShiftRow(row, now))
        .filter((shift) => shiftMatchesScheduleStatus(shift, "scheduled"))
        .slice(0, 5)
        .map((shift) => ({
            ...shift,
            staff_name: shift.staffName,
            client: shift.patientName || "Patient",
            date: shift.scheduledStart ? shift.scheduledStart.slice(0, 10) : "Today",
            time: shift.scheduledStart ? shift.scheduledStart.slice(11, 16) : "TBC",
            type: "Scheduled shift",
        }));

    return { recentActivity, upcomingVisits };
};

const getValidStaffHourlyRate = async (staffId) => {
    const numericStaffId = Number(staffId);
    if (!Number.isInteger(numericStaffId) || numericStaffId <= 0) {
        throw new Error("A valid staff member is required to freeze the shift pay rate.");
    }
    const staffMember = await getDb("SELECT hourly_rate FROM staff WHERE id = ?", [numericStaffId]);
    const hasHourlyRate = staffMember
        && staffMember.hourly_rate !== null
        && staffMember.hourly_rate !== undefined
        && String(staffMember.hourly_rate).trim() !== "";
    const hourlyRate = Number(staffMember && staffMember.hourly_rate);
    if (!hasHourlyRate || !Number.isFinite(hourlyRate) || hourlyRate < 0) {
        throw new Error("Set a valid hourly rate for the staff member before assigning this shift.");
    }
    return hourlyRate;
};

const snapshotShiftPayRate = async (shiftId, staffId, assignedHourlyRate = null) => {
    const numericShiftId = Number(shiftId);
    const numericStaffId = Number(staffId);
    if (!Number.isInteger(numericShiftId) || numericShiftId <= 0 || !Number.isInteger(numericStaffId) || numericStaffId <= 0) {
        return;
    }
    const hourlyRate = assignedHourlyRate === null
        ? await getValidStaffHourlyRate(numericStaffId)
        : Number(assignedHourlyRate);
    if (!Number.isFinite(hourlyRate) || hourlyRate < 0) {
        throw new Error("Set a valid hourly rate for the staff member before assigning this shift.");
    }
    await runDb(
        `UPDATE staff_shifts
         SET pay_rate = ?, pay_rate_source = 'staff_rate_at_assignment'
         WHERE id = ?
           AND actual_clock_in IS NULL
           AND COALESCE(payroll_status, 'draft') = 'draft'`,
        [hourlyRate, numericShiftId]
    );
};

const mapClientAccountRow = (account) => {
    if (!account) {
        return account;
    }

    const displayName = String(account.organization_name || "").trim() || formatName(account.contact_first_name, account.contact_last_name) || "Facility account";
    return {
        ...account,
        displayName,
        accountId: account.facility_id || `FAC-${String(account.id || "").padStart(5, "0")}`,
        serviceRequirements: parseJsonArrayField(account.service_requirements),
        preferredShiftTypes: parseJsonArrayField(account.preferred_shift_types),
        favouriteStaffIds: parseJsonArrayField(account.favourite_staff_ids).map((value) => Number(value)).filter((value) => Number.isFinite(value)),
        statusClass: slugifyValue(account.status || "pending"),
        gpsLatitude: account.gps_latitude ?? "",
        gpsLongitude: account.gps_longitude ?? "",
    };
};

const mapClientRequestRow = (request) => {
    if (!request) {
        return request;
    }

    return {
        ...request,
        clientAccountId: request.client_account_id || request.clientAccountId || null,
        quantityRequired: Number(request.quantity_required || request.quantityRequired || 1) || 1,
        requiredSkills: parseJsonArrayField(request.required_skills),
        requiredTraining: parseJsonArrayField(request.required_training),
        multipleDates: parseJsonArrayField(request.multiple_dates),
        breakDurationMinutes: Number(request.break_duration_minutes || 0) || 0,
        totalPaidHours: parseFloatOrNull(request.total_paid_hours),
        minimumExperienceYears: parseFloatOrNull(request.minimum_experience_years),
        drivingLicenceRequired: Boolean(Number(request.driving_licence_required || 0)),
        ownVehicleRequired: Boolean(Number(request.own_vehicle_required || 0)),
        uniformRequired: Boolean(Number(request.uniform_required || 0)),
        parkingAvailable: Boolean(Number(request.parking_available || 0)),
        smokingHousehold: Boolean(Number(request.smoking_household || 0)),
        petsOnPremises: Boolean(Number(request.pets_on_premises || 0)),
        assignedStaff: request.assigned_staff_name ? {
            name: request.assigned_staff_name,
            role: request.assigned_staff_role || "",
            profilePhoto: request.assigned_staff_photo || "",
            experienceYears: request.assigned_staff_experience_years || "",
            qqiQualifications: parseJsonArrayField(request.assigned_staff_qqi_qualifications),
            nmbiNumber: request.assigned_staff_nmbi_number || "",
            mandatoryTraining: parseJsonArrayField(request.assigned_staff_mandatory_training),
            additionalCertifications: parseJsonArrayField(request.assigned_staff_additional_certifications),
            languages: parseJsonArrayField(request.assigned_staff_languages),
        } : null,
        statusClass: slugifyValue(request.status || "open"),
        clientName: request.organization_name || request.client_name || request.clientName || "Client",
        contactName: formatName(request.contact_first_name, request.contact_last_name),
    };
};

const mapShiftStatusToClientRequestStatus = (shiftStatus) => {
    const normalized = String(shiftStatus || "").trim().toLowerCase();
    if (normalized === "scheduled") {
        return "confirmed";
    }
    if (normalized === "clocked_in") {
        return "checked_in";
    }
    if (normalized === "clocked_out") {
        return "checked_out";
    }
    if (normalized === "completed") {
        return "shift_completed";
    }
    if (normalized === "cancelled") {
        return "cancelled";
    }
    if (normalized === "no_show") {
        return "no_show";
    }
    return "";
};

const roleAliasMap = {
    "Healthcare Assistant": ["Care Assistant", "Senior Care Assistant", "Healthcare Assistant"],
    "Support Worker": ["Support Worker", "Care Assistant", "Healthcare Assistant"],
    "Staff Nurse (RGN)": ["Registered Nurse", "Staff Nurse (RGN)"],
    "Psychiatric Nurse (RPN)": ["Psychiatric Nurse", "Psychiatric Nurse (RPN)", "Registered Nurse"],
    "Intellectual Disability Nurse (RNID)": ["Intellectual Disability Nurse", "Intellectual Disability Nurse (RNID)", "Registered Nurse"],
    "Children's Nurse": ["Children's Nurse", "Registered Nurse"],
    "Midwife": ["Midwife", "Registered Nurse"],
    "Social Care Worker": ["Social Care Worker", "Support Worker"],
    "Senior Care Assistant": ["Senior Care Assistant", "Care Assistant", "Healthcare Assistant"],
    "Clinical Nurse Manager": ["Clinical Nurse Manager", "Clinical Nurse Manager (CNM)", "Registered Nurse"],
    "Live-in Carer": ["Live-In Care", "Care Assistant", "Healthcare Assistant"],
};

const normalizeRoleName = (value) => String(value || "").trim().toLowerCase();

const matchesRequiredRole = (staffMember, requiredRole) => {
    const required = String(requiredRole || "").trim();
    if (!required || required.toLowerCase() === "other") {
        return true;
    }
    const aliases = roleAliasMap[required] || [required];
    const staffRole = normalizeRoleName(staffMember.role);
    return aliases.some((alias) => normalizeRoleName(alias) === staffRole);
};

const isDateExpired = (value) => {
    const raw = String(value || "").trim();
    if (!raw) {
        return false;
    }
    const expiry = new Date(`${raw}T23:59:59`);
    if (Number.isNaN(expiry.getTime())) {
        return false;
    }
    return expiry.getTime() < Date.now();
};

const normalizeTrainingName = (value) => String(value || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();

const staffMeetsRequestRequirements = async ({ staffMember, shift, request }) => {
    if (!staffMember || !request) {
        return { eligible: false, reasons: ["Request details are unavailable."] };
    }

    const reasons = [];
    if (isStaffLoginBlocked(staffMember)) {
        reasons.push("Staff account is not active for portal work.");
    }
    if (!matchesRequiredRole(staffMember, request.staff_required)) {
        reasons.push("Required profession does not match this request.");
    }
    const gardaStatus = String(staffMember.gardaVettingStatus || "").trim().toLowerCase();
    if (gardaStatus && !["approved", "valid", "complete", "completed", "active", "clear"].includes(gardaStatus)) {
        reasons.push("Garda vetting status is not valid.");
    }
    if (isDateExpired(staffMember.gardaVettingExpiryDate)) {
        reasons.push("Garda vetting has expired.");
    }
    if (request.staff_required && request.staff_required.toLowerCase().includes("nurse")) {
        if (!String(staffMember.nmbiNumber || "").trim()) {
            reasons.push("NMBI registration is required for this nursing shift.");
        }
        if (isDateExpired(staffMember.nmbiExpiryDate)) {
            reasons.push("NMBI registration has expired.");
        }
    }

    const requiredSkills = parseJsonArrayField(request.required_skills).map(normalizeTrainingName);
    const availableSkills = [...staffMember.skillsSpecialities, ...staffMember.additionalCertifications].map(normalizeTrainingName);
    requiredSkills.forEach((requiredSkill) => {
        if (!availableSkills.includes(requiredSkill)) {
            reasons.push(`Missing required care need/skill: ${requiredSkill}.`);
        }
    });

    const requiredTraining = parseJsonArrayField(request.required_training).map(normalizeTrainingName);
    const availableTraining = [...staffMember.mandatoryTraining, ...staffMember.additionalCertifications].map(normalizeTrainingName);
    requiredTraining.forEach((training) => {
        if (!availableTraining.includes(training)) {
            reasons.push(`Missing required training: ${training}.`);
        }
    });

    const minExperience = parseFloatOrNull(request.minimum_experience_years);
    const staffExperience = parseFloatOrNull(staffMember.experience_years);
    if (Number.isFinite(minExperience) && minExperience > 0 && (!Number.isFinite(staffExperience) || staffExperience < minExperience)) {
        reasons.push(`Minimum ${minExperience} years experience required.`);
    }

    if (Boolean(Number(request.driving_licence_required || 0)) && !String(staffMember.drivingLicenceNumber || "").trim()) {
        reasons.push("Driving licence is required.");
    }
    if (Boolean(Number(request.own_vehicle_required || 0)) && !Boolean(staffMember.ownVehicle)) {
        reasons.push("Own vehicle is required.");
    }
    if (String(request.language_requirement || "").trim()) {
        const requiredLanguage = normalizeTrainingName(request.language_requirement);
        const availableLanguages = (staffMember.languages || []).map(normalizeTrainingName);
        if (!availableLanguages.includes(requiredLanguage)) {
            reasons.push(`Language requirement not met: ${request.language_requirement}.`);
        }
    }

    const shiftDateKey = toDateKey(shift.scheduled_start || shift.scheduledStart);
    const weekday = shiftDateKey ? new Date(`${shiftDateKey}T12:00:00`).toLocaleDateString("en-IE", { weekday: "long" }) : "";
    if (weekday && Array.isArray(staffMember.availabilityDays) && staffMember.availabilityDays.length && !staffMember.availabilityDays.includes(weekday)) {
        reasons.push(`Not available on ${weekday}.`);
    }
    if (Array.isArray(staffMember.shiftPreferences) && staffMember.shiftPreferences.length) {
        const preferenceMatches = staffMember.shiftPreferences.includes(String(request.shift_type || "")) || staffMember.shiftPreferences.includes(parseShiftTypeFromStartTime(request.start_time));
        if (!preferenceMatches) {
            reasons.push("Shift type preference does not match.");
        }
    }

    const conflictingShift = await getDb(
        `SELECT id
         FROM staff_shifts
         WHERE staff_id = ?
           AND COALESCE(is_open, 0) = 0
           AND id <> ?
           AND status NOT IN ('cancelled', 'no_show', 'completed')
           AND datetime(COALESCE(scheduled_start, '')) < datetime(?)
           AND datetime(COALESCE(scheduled_end, '')) > datetime(?)
         LIMIT 1`,
        [
            Number(staffMember.id),
            Number(shift.id),
            toSqliteTimestamp(shift.scheduled_end || shift.scheduledEnd || ""),
            toSqliteTimestamp(shift.scheduled_start || shift.scheduledStart || ""),
        ]
    );
    if (conflictingShift) {
        reasons.push("Another assigned shift overlaps this time.");
    }

    return { eligible: reasons.length === 0, reasons };
};

const syncClientRequestStatusFromShift = async ({ shiftId, shiftStatus, notifyTitle = "", notifyBody = "" }) => {
    const status = mapShiftStatusToClientRequestStatus(shiftStatus);
    if (!status) {
        return;
    }
    const shiftRow = await getDb("SELECT id, client_request_id, client_account_id, staff_id FROM staff_shifts WHERE id = ?", [Number(shiftId)]);
    if (!shiftRow || !shiftRow.client_request_id) {
        return;
    }
    await runDb(
        "UPDATE client_service_requests SET status = ?, assigned_staff_id = COALESCE(assigned_staff_id, ?), scheduled_shift_id = COALESCE(scheduled_shift_id, ?), updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        [status, shiftRow.staff_id || null, shiftRow.id, Number(shiftRow.client_request_id)]
    );
    if (notifyTitle && notifyBody && shiftRow.client_account_id) {
        await queueClientNotification(Number(shiftRow.client_account_id), notifyTitle, notifyBody, "request", "/facility-portal/requests");
    }
    emitPortalEvent("client_request", { requestId: Number(shiftRow.client_request_id), status }, { adminOnly: true });
};

const buildClientAccountPayload = (body = {}, existingAccount = null) => {
    const organizationType = clientPortalOrganizationTypes.includes(String(body.organization_type || "").trim())
        ? String(body.organization_type).trim()
        : "Other Healthcare Provider";
    const status = clientPortalRegistrationStatuses.includes(String(body.status || "").trim())
        ? String(body.status).trim()
        : (existingAccount ? String(existingAccount.status || "pending") : "pending");
    return {
        organizationName: String(body.organization_name || "").trim(),
        tradingName: String(body.trading_name || "").trim(),
        organizationType,
        registrationNumber: String(body.registration_number || "").trim(),
        hiqaRegistrationNumber: String(body.hiqa_registration_number || "").trim(),
        hseContractNumber: String(body.hse_contract_number || "").trim(),
        vatNumber: String(body.vat_number || "").trim(),
        website: String(body.website || "").trim(),
        contactFirstName: String(body.contact_first_name || "").trim(),
        contactLastName: String(body.contact_last_name || "").trim(),
        contactJobTitle: String(body.contact_job_title || "").trim(),
        email: String(body.email || "").trim().toLowerCase(),
        mobileNumber: String(body.mobile_number || "").trim(),
        officeTelephone: String(body.office_telephone || "").trim(),
        addressLine1: String(body.address_line_1 || "").trim(),
        addressLine2: String(body.address_line_2 || "").trim(),
        town: String(body.town || "").trim(),
        county: String(body.county || "").trim(),
        eircode: String(body.eircode || "").trim(),
        gpsLatitude: String(body.gps_latitude || "").trim(),
        gpsLongitude: String(body.gps_longitude || "").trim(),
        serviceRequirements: normalizeStringList(Array.isArray(body.service_requirements) ? body.service_requirements : (body.service_requirements ? [body.service_requirements] : [])),
        numberOfBeds: String(body.number_of_beds || "").trim(),
        numberOfResidents: String(body.number_of_residents || "").trim(),
        numberOfUnits: String(body.number_of_units || "").trim(),
        existingStaffNumbers: String(body.existing_staff_numbers || "").trim(),
        currentStaffingProvider: String(body.current_staffing_provider || "").trim(),
        preferredShiftTypes: normalizeStringList(Array.isArray(body.preferred_shift_types) ? body.preferred_shift_types : (body.preferred_shift_types ? [body.preferred_shift_types] : [])),
        gdprAgreement: toFlagInteger(body.gdpr_agreement),
        privacyAgreement: toFlagInteger(body.privacy_agreement),
        termsAgreement: toFlagInteger(body.terms_agreement),
        hiqaComplianceAgreement: toFlagInteger(body.hiqa_compliance_agreement),
        authorisedRepresentative: toFlagInteger(body.authorised_representative),
        status,
        reviewNotes: String(body.review_notes || "").trim(),
    };
};

const buildClientRequestPayload = (body = {}, clientAccount = null) => {
    const startTime = String(body.start_time || "").trim();
    const endTime = String(body.end_time || "").trim();
    const breakDurationMinutes = Math.max(0, parseIntegerOrNull(body.break_duration_minutes) || 0);
    const paidHours = parseFloatOrNull(body.total_paid_hours) ?? calculatePaidHours(startTime, endTime, breakDurationMinutes);
    return {
        facilityName: String(body.facility_name || clientAccount?.organization_name || "").trim(),
        facilityType: clientPortalFacilityTypeOptions.includes(String(body.facility_type || "").trim())
            ? String(body.facility_type).trim()
            : (clientAccount?.organization_type || "Other"),
        facilityAddress: String(body.facility_address || clientAccount?.address_line_1 || "").trim(),
        facilityCounty: String(body.facility_county || clientAccount?.county || "").trim(),
        facilityEircode: String(body.facility_eircode || clientAccount?.eircode || "").trim(),
        facilityGpsLatitude: parseFloatOrNull(body.facility_gps_latitude ?? clientAccount?.gps_latitude),
        facilityGpsLongitude: parseFloatOrNull(body.facility_gps_longitude ?? clientAccount?.gps_longitude),
        contactPerson: String(body.contact_person || formatName(clientAccount?.contact_first_name, clientAccount?.contact_last_name) || "").trim(),
        contactPosition: String(body.contact_position || clientAccount?.contact_job_title || "").trim(),
        contactPhone: String(body.contact_phone || clientAccount?.mobile_number || "").trim(),
        contactEmail: String(body.contact_email || clientAccount?.email || "").trim().toLowerCase(),
        emergencyContact: String(body.emergency_contact || "").trim(),
        staffRequired: clientPortalRequestRoleOptions.includes(String(body.staff_required || "").trim())
            ? String(body.staff_required).trim()
            : "Healthcare Assistant",
        quantityRequired: Math.max(1, Number(body.quantity_required || 1) || 1),
        shiftType: clientPortalShiftTypeOptions.includes(String(body.shift_type || "").trim())
            ? String(body.shift_type).trim()
            : (parseShiftTypeFromStartTime(startTime) || "Morning"),
        recurringPattern: clientPortalRecurringPatternOptions.includes(String(body.recurring_pattern || "").trim())
            ? String(body.recurring_pattern).trim()
            : "One-time Shift",
        multipleDates: normalizeStringList(Array.isArray(body.multiple_dates) ? body.multiple_dates : (body.multiple_dates ? [body.multiple_dates] : [])),
        weeklyRepeatDay: String(body.weekly_repeat_day || "").trim(),
        monthlyRepeatDate: parseIntegerOrNull(body.monthly_repeat_date),
        shiftDate: String(body.shift_date || "").trim() || nowIsoDate(),
        startTime,
        endTime,
        breakDurationMinutes,
        totalPaidHours: paidHours,
        hourlyRate: parseFloatOrNull(body.hourly_rate),
        wardUnit: String(body.ward_unit || "").trim(),
        residentIdentifier: String(body.resident_identifier || "").trim(),
        roomNumber: String(body.room_number || "").trim(),
        residentUnit: String(body.resident_unit || "").trim(),
        requiredSkills: normalizeStringList(Array.isArray(body.required_skills) ? body.required_skills : (body.required_skills ? [body.required_skills] : [])),
        requiredTraining: normalizeStringList(Array.isArray(body.required_training) ? body.required_training : (body.required_training ? [body.required_training] : [])),
        minimumExperienceYears: parseFloatOrNull(body.minimum_experience_years),
        healthcareSettingRequired: String(body.healthcare_setting_required || "").trim(),
        drivingLicenceRequired: toBooleanFromCheckbox(body.driving_licence_required),
        ownVehicleRequired: toBooleanFromCheckbox(body.own_vehicle_required),
        englishLanguageLevel: clientPortalEnglishLevelOptions.includes(String(body.english_language_level || "").trim())
            ? String(body.english_language_level).trim()
            : "",
        additionalCertifications: String(body.additional_certifications || "").trim(),
        notes: String(body.notes || "").trim(),
        uniformRequired: toBooleanFromCheckbox(body.uniform_required),
        parkingAvailable: toBooleanFromCheckbox(body.parking_available),
        smokingHousehold: toBooleanFromCheckbox(body.smoking_household),
        petsOnPremises: toBooleanFromCheckbox(body.pets_on_premises),
        specialInstructions: String(body.special_instructions || "").trim(),
        priority: clientPortalPriorityOptions.includes(String(body.priority || "").trim())
            ? String(body.priority).trim()
            : "Routine",
        languageRequirement: String(body.language_requirement || "").trim(),
        travelRadiusKm: parseFloatOrNull(body.travel_radius_km),
        clientAccountId: clientAccount ? Number(clientAccount.id) : null,
    };
};

const getClientAuthState = (account) => {
    if (!account) {
        return { allowed: false, message: "No facility account was found for that email address." };
    }
    const status = String(account.status || "pending").trim().toLowerCase();
    if (status === "pending" || status === "more_info_requested") {
        return { allowed: false, message: "Your facility portal registration is still awaiting approval." };
    }
    if (status === "rejected") {
        return { allowed: false, message: "This facility portal registration has been declined. Please contact Everkind for support." };
    }
    if (status === "suspended") {
        return { allowed: false, message: "This facility portal account is suspended. Please contact Everkind." };
    }
    if (status !== "approved") {
        return { allowed: false, message: "This facility portal account is not active yet." };
    }
    if (!Boolean(Number(account.portal_login_enabled ?? 0))) {
        return { allowed: false, message: "Facility portal login has not been enabled yet for this account." };
    }
    if (Boolean(Number(account.portal_login_suspended || 0)) || Boolean(Number(account.portal_login_deactivated || 0))) {
        return { allowed: false, message: "This facility portal account is currently unavailable. Please contact Everkind." };
    }
    return { allowed: true, message: "" };
};

const blockedStaffStatuses = new Set(["suspended", "inactive", "archived", "resigned"]);
const legacyActiveStaffStatuses = new Set(["available", "on duty"]);
const portalEnabledStaffStatuses = new Set(["active", "induction"]);

const formatStaffDisplayName = (name, status) => {
    const resolvedName = String(name || "").trim() || "Staff member";
    const normalizedStatus = String(status || "").trim().toLowerCase();
    return normalizedStatus === "induction" ? `${resolvedName} (Induction)` : resolvedName;
};

const normalizeStaffEmploymentStatus = (staffMember) => {
    const normalizedStatus = String(staffMember && (staffMember.employment_status || staffMember.status) || "").trim().toLowerCase();
    if (legacyActiveStaffStatuses.has(normalizedStatus)) {
        return "active";
    }
    return normalizedStatus;
};

const isStaffLoginBlocked = (staffMember) => {
    if (!staffMember) {
        return true;
    }
    const normalizedStatus = normalizeStaffEmploymentStatus(staffMember);
    if (!portalEnabledStaffStatuses.has(normalizedStatus)) {
        return true;
    }
    if (blockedStaffStatuses.has(normalizedStatus)) {
        return true;
    }
    if (!Boolean(Number(staffMember.portal_login_enabled ?? 1))) {
        return true;
    }
    if (Boolean(Number(staffMember.portal_login_suspended || 0))) {
        return true;
    }
    if (Boolean(Number(staffMember.portal_login_deactivated || 0))) {
        return true;
    }
    return false;
};

const createResetCode = () => String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
const hashPassword = (value) => bcrypt.hash(value, 10);
const assertPasswordNotReused = async ({ accountType, accountId, password, currentPasswordHash = null }) => {
    if (currentPasswordHash && await bcrypt.compare(password, currentPasswordHash)) {
        const error = new Error("Choose a password you have not used recently.");
        error.code = "PASSWORD_REUSED";
        throw error;
    }
    const historyRows = await allDb(
        `SELECT password_hash FROM password_history
         WHERE account_type = ? AND account_id = ?
         ORDER BY created_at DESC, id DESC LIMIT 6`,
        [accountType, accountId]
    );
    for (const row of historyRows) {
        if (await bcrypt.compare(password, row.password_hash)) {
            const error = new Error("Choose a password you have not used recently.");
            error.code = "PASSWORD_REUSED";
            throw error;
        }
    }
};
const recordPasswordHistory = async (accountType, accountId, passwordHash) => {
    if (!passwordHash) return;
    await runDb(
        "INSERT INTO password_history (account_type, account_id, password_hash) VALUES (?, ?, ?)",
        [accountType, accountId, passwordHash]
    );
    await runDb(
        `DELETE FROM password_history
         WHERE account_type = ? AND account_id = ? AND id NOT IN (
            SELECT id FROM password_history
            WHERE account_type = ? AND account_id = ?
            ORDER BY created_at DESC, id DESC LIMIT 6
         )`,
        [accountType, accountId, accountType, accountId]
    );
};
const createTemporaryPassword = (length = 12) => {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";
    let result = "";
    for (let index = 0; index < length; index += 1) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
};

const toSqliteTimestamp = (value) => String(value || "").replace("T", " ").slice(0, 19);

const parseIntegerOrNull = (value) => {
    if (value === null || value === undefined || String(value).trim() === "") {
        return null;
    }
    const parsed = Number.parseInt(String(value).trim(), 10);
    return Number.isFinite(parsed) ? parsed : null;
};

const parseFloatOrNull = (value) => {
    if (value === null || value === undefined || String(value).trim() === "") {
        return null;
    }
    const parsed = Number.parseFloat(String(value).trim());
    return Number.isFinite(parsed) ? parsed : null;
};

const toBooleanFromCheckbox = (value) => ["1", "true", "yes", "on"].includes(String(value || "").trim().toLowerCase());

const calculatePaidHours = (startTime, endTime, breakMinutes) => {
    const start = String(startTime || "").trim();
    const end = String(endTime || "").trim();
    if (!start || !end || !start.includes(":") || !end.includes(":")) {
        return null;
    }
    const [startHour, startMinute] = start.split(":").map((part) => Number.parseInt(part, 10));
    const [endHour, endMinute] = end.split(":").map((part) => Number.parseInt(part, 10));
    if (![startHour, startMinute, endHour, endMinute].every((part) => Number.isFinite(part))) {
        return null;
    }
    let durationMinutes = (endHour * 60 + endMinute) - (startHour * 60 + startMinute);
    if (durationMinutes <= 0) {
        durationMinutes += 24 * 60;
    }
    const breakDuration = Math.max(0, Number.parseInt(String(breakMinutes || "0"), 10) || 0);
    const paidMinutes = Math.max(0, durationMinutes - breakDuration);
    return Math.round((paidMinutes / 60) * 100) / 100;
};

const parseShiftTypeFromStartTime = (startTime) => {
    const hour = Number.parseInt(String(startTime || "").split(":")[0], 10);
    if (!Number.isFinite(hour)) {
        return "";
    }
    if (hour >= 6 && hour < 12) {
        return "Morning";
    }
    if (hour >= 12 && hour < 17) {
        return "Afternoon";
    }
    if (hour >= 17 && hour < 22) {
        return "Evening";
    }
    return "Night";
};

const nowIsoDate = () => new Date().toISOString().slice(0, 10);

const parseStaffServiceTypes = (value) => {
    const parsed = parseJsonArrayField(value);
    const normalized = normalizeStringList(parsed).filter((entry) => staffServiceTypeOptions.includes(entry));
    if (!normalized.length) {
        return ["Both"];
    }
    if (normalized.includes("Both")) {
        return ["Both"];
    }
    return normalized;
};

const staffCanWorkDivision = (staffMember, division) => {
    const serviceTypes = parseStaffServiceTypes(staffMember && staffMember.service_types ? staffMember.service_types : (staffMember && staffMember.serviceTypes ? serializeJsonField(staffMember.serviceTypes) : null));
    if (serviceTypes.includes("Both")) {
        return true;
    }
    if (division === "home-care") {
        return serviceTypes.includes("Home Care");
    }
    if (division === "healthcare-staffing" || division === "agency-staffing") {
        return serviceTypes.includes("Healthcare Staffing");
    }
    return true;
};

const getShiftDivision = (shift) => {
    const explicitDivision = String(shift.service_division || shift.serviceDivision || "").trim().toLowerCase();
    if (shiftDivisionOptions.includes(explicitDivision)) {
        return explicitDivision;
    }
    if (Number(shift.client_account_id || shift.clientAccountId || 0) > 0 || String(shift.request_source || "").toLowerCase() === "client_portal") {
        return "agency-staffing";
    }
    return "home-care";
};

const buildShiftCode = (division, shiftId) => {
    const prefix = division === "agency-staffing" ? "AGS" : "HCV";
    return `${prefix}-${String(Number(shiftId) || 0).padStart(6, "0")}`;
};

const filterShiftsForStaffDivision = (staffMember, shifts = []) => shifts.filter((shift) => staffCanWorkDivision(staffMember, getShiftDivision(shift)));

const normalizeDateTimeString = (value) => {
    const raw = String(value || "").trim();
    if (!raw) {
        return "";
    }
    if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?$/.test(raw)) {
        return raw.replace(" ", "T");
    }
    return raw;
};

const getWeekRange = (baseDate = new Date()) => {
    const current = new Date(baseDate);
    current.setHours(0, 0, 0, 0);
    const day = current.getDay();
    const mondayOffset = day === 0 ? -6 : 1 - day;
    const start = new Date(current);
    start.setDate(current.getDate() + mondayOffset);
    const end = new Date(start);
    end.setDate(start.getDate() + 6);
    return { start, end };
};

const toDateKey = (value) => {
    const date = new Date(normalizeDateTimeString(value));
    if (Number.isNaN(date.getTime())) {
        return "";
    }
    return date.toISOString().slice(0, 10);
};

const formatWeekLabel = (start, end) => {
    const startLabel = start.toLocaleDateString("en-IE", { day: "numeric", month: "short" });
    const endLabel = end.toLocaleDateString("en-IE", { day: "numeric", month: "short", year: "numeric" });
    return `${startLabel} - ${endLabel}`;
};

const queueStaffNotification = async (staffId, title, body, type = "info", linkUrl = null) => {
    await runDb(
        `INSERT INTO staff_notifications (staff_id, title, body, type, link_url)
         VALUES (?, ?, ?, ?, ?)`,
        [staffId, title, body, type, linkUrl]
    );
    emitPortalEvent("notification", { staffId: Number(staffId), title, type, linkUrl }, { staffIds: [Number(staffId)] });
};

const queueClientNotification = async (clientAccountId, title, body, type = "info", linkUrl = null) => {
    await runDb(
        `INSERT INTO client_notifications (client_account_id, title, body, type, link_url)
         VALUES (?, ?, ?, ?, ?)`,
        [clientAccountId, title, body, type, linkUrl]
    );
};

const portalEventClients = new Set();

const emitPortalEvent = (type, payload = {}, options = {}) => {
    const staffIds = Array.isArray(options.staffIds) ? new Set(options.staffIds.map((value) => Number(value))) : null;
    const adminOnly = Boolean(options.adminOnly);
    const staffOnly = Boolean(options.staffOnly);
    const message = `data: ${JSON.stringify({ type, payload, emittedAt: new Date().toISOString() })}\n\n`;

    for (const client of portalEventClients) {
        if (adminOnly && !client.isAdmin) {
            continue;
        }
        if (staffOnly && client.isAdmin) {
            continue;
        }
        if (staffIds && (!client.staffId || !staffIds.has(client.staffId))) {
            continue;
        }

        try {
            client.res.write(message);
        } catch (error) {
            portalEventClients.delete(client);
        }
    }
};

const normalizeReminderLeadMinutes = (value) => {
    const allowed = new Set([15, 30, 60, 120]);
    const minutes = Number(value);
    return allowed.has(minutes) ? minutes : 60;
};

const queueDueShiftReminders = async (staffMember) => {
    if (!staffMember || !staffMember.id || !staffMember.notifyShiftReminders) {
        return;
    }

    const reminderLeadMinutes = normalizeReminderLeadMinutes(staffMember.reminderLeadMinutes);
    const now = new Date();
    const upcomingShifts = (await allDb(
        `SELECT ss.*, p.first_name || ' ' || p.last_name AS patient_name
         FROM staff_shifts ss
         LEFT JOIN patients p ON p.id = ss.patient_id
         WHERE ss.staff_id = ?
           AND ss.status = 'scheduled'
           AND ss.scheduled_start IS NOT NULL
           AND datetime(ss.scheduled_start) >= datetime('now')
           AND datetime(ss.scheduled_start) <= datetime('now', '+2 hours')
         ORDER BY ss.scheduled_start ASC`,
        [staffMember.id]
    )).map(mapShiftRow);

    for (const shift of upcomingShifts) {
        const shiftStart = new Date(normalizeDateTimeString(shift.scheduledStart));
        if (Number.isNaN(shiftStart.getTime())) {
            continue;
        }
        const minutesUntilShift = Math.floor((shiftStart.getTime() - now.getTime()) / 60000);
        if (minutesUntilShift < 0 || minutesUntilShift > reminderLeadMinutes) {
            continue;
        }

        const existingReminder = await getDb(
            `SELECT id FROM staff_shift_reminders
             WHERE shift_id = ? AND staff_id = ? AND reminder_type = 'shift_start' AND reminder_minutes = ?`,
            [shift.id, staffMember.id, reminderLeadMinutes]
        );
        if (existingReminder) {
            continue;
        }

        const startTimeLabel = (shift.scheduledStart || "").slice(11, 16) || "scheduled time";
        await queueStaffNotification(
            staffMember.id,
            "Shift reminder",
            `You have a ${shift.serviceType} visit with ${shift.patientName} at ${startTimeLabel}. Please remember to clock in when you arrive.`,
            "shift",
            `/portal/shifts/${shift.id}`
        );
        await runDb(
            `INSERT INTO staff_shift_reminders (shift_id, staff_id, reminder_type, reminder_minutes)
             VALUES (?, ?, 'shift_start', ?)`,
            [shift.id, staffMember.id, reminderLeadMinutes]
        );
    }
};

const createShiftFromClientRequest = async ({ clientAccount, clientRequest, staffId = null, isOpen = false }) => {
    const assignedHourlyRate = staffId ? await getValidStaffHourlyRate(staffId) : null;
    const scheduledStart = `${clientRequest.shift_date} ${clientRequest.start_time}`;
    const scheduledEnd = `${clientRequest.shift_date} ${clientRequest.end_time}`;
    const clientName = clientRequest.facility_name || clientAccount.organization_name || mapClientAccountRow(clientAccount).displayName;
    const structuredNotes = [
        `Client Request #${clientRequest.id}`,
        `Facility: ${clientRequest.facility_name || clientName}`,
        `Facility Type: ${clientRequest.facility_type || clientAccount.organization_type || "Other"}`,
        `Address: ${clientRequest.facility_address || clientAccount.address_line_1 || ""}, ${clientRequest.facility_county || clientAccount.county || ""} ${clientRequest.facility_eircode || clientAccount.eircode || ""}`.trim(),
        `Contact: ${clientRequest.contact_person || formatName(clientAccount.contact_first_name, clientAccount.contact_last_name) || "N/A"} (${clientRequest.contact_position || "Primary contact"})`,
        `Phone: ${clientRequest.contact_phone || clientAccount.mobile_number || "N/A"} · Email: ${clientRequest.contact_email || clientAccount.email || "N/A"}`,
        `Priority: ${clientRequest.priority || "Routine"}`,
        `Staff Required: ${clientRequest.staff_required || "Healthcare Assistant"} x${Number(clientRequest.quantity_required || 1)}`,
        `Care Needs: ${parseJsonArrayField(clientRequest.required_skills).join(", ") || "None specified"}`,
        `Training Required: ${parseJsonArrayField(clientRequest.required_training).join(", ") || "None specified"}`,
        `Minimum Experience: ${clientRequest.minimum_experience_years || "Not specified"} year(s)`,
        `Driving Licence Required: ${Boolean(Number(clientRequest.driving_licence_required || 0)) ? "Yes" : "No"}`,
        `Own Vehicle Required: ${Boolean(Number(clientRequest.own_vehicle_required || 0)) ? "Yes" : "No"}`,
        `Language Requirement: ${clientRequest.language_requirement || "None"}`,
        `Uniform Required: ${Boolean(Number(clientRequest.uniform_required || 0)) ? "Yes" : "No"}`,
        `Parking Available: ${Boolean(Number(clientRequest.parking_available || 0)) ? "Yes" : "No"}`,
        `Emergency Contact: ${clientRequest.emergency_contact || "Not provided"}`,
        clientRequest.notes ? `Client Notes: ${clientRequest.notes}` : "",
        clientRequest.special_instructions ? `Special Instructions: ${clientRequest.special_instructions}` : "",
    ].filter(Boolean).join("\n");
    const result = await runDb(
        `INSERT INTO staff_shifts
         (patient_id, staff_id, client_account_id, client_request_id, request_source, service_division, external_client_label, location_address, location_town, location_county, location_eircode, external_latitude, external_longitude, external_geofence_radius_meters, ward_unit, shift_date, scheduled_start, scheduled_end, service_type, notes, care_instructions, status, is_open, facility_type, role_required, shift_requirements, break_duration_minutes, quantity_required, contact_person)
         VALUES (NULL, ?, ?, ?, 'client_portal', 'agency-staffing', ?, ?, ?, ?, ?, ?, ?, 100, ?, ?, ?, ?, ?, ?, ?, 'scheduled', ?, ?, ?, ?, ?, ?, ?)`,
        [
            staffId,
            Number(clientAccount.id),
            Number(clientRequest.id),
            clientName,
            clientRequest.facility_address || clientAccount.address_line_1 || "",
            clientAccount.town || "",
            clientRequest.facility_county || clientAccount.county || "",
            clientRequest.facility_eircode || clientAccount.eircode || "",
            parseFloatOrNull(clientRequest.facility_gps_latitude ?? clientAccount.gps_latitude),
            parseFloatOrNull(clientRequest.facility_gps_longitude ?? clientAccount.gps_longitude),
            clientRequest.ward_unit || "",
            clientRequest.shift_date,
            scheduledStart,
            scheduledEnd,
            clientRequest.staff_required || "Healthcare Assistant",
            structuredNotes,
            structuredNotes,
            isOpen ? 1 : 0,
            clientRequest.facility_type || clientAccount.organization_type || "Other",
            clientRequest.staff_required || "Healthcare Assistant",
            [
                parseJsonArrayField(clientRequest.required_skills).join(", "),
                parseJsonArrayField(clientRequest.required_training).join(", "),
                clientRequest.special_instructions || "",
            ].filter(Boolean).join(" | "),
            Number(clientRequest.break_duration_minutes || 0) || 0,
            Number(clientRequest.quantity_required || 1) || 1,
            clientRequest.contact_person || formatName(clientAccount.contact_first_name, clientAccount.contact_last_name) || "",
        ]
    );
    await runDb("UPDATE staff_shifts SET shift_code = ? WHERE id = ?", [buildShiftCode("agency-staffing", result.lastID), Number(result.lastID)]);
    if (staffId) {
        await snapshotShiftPayRate(result.lastID, staffId, assignedHourlyRate);
    }

    if (staffId) {
        const staffMember = mapStaffRow(await getDb("SELECT * FROM staff WHERE id = ?", [Number(staffId)]));
        if (staffMember && staffMember.notifyNewShift) {
            await queueStaffNotification(
                Number(staffId),
                "New facility portal shift assigned",
                `A ${clientRequest.staff_required} shift for ${clientName} has been added to your schedule.`,
                "shift",
                `/portal/shifts/${result.lastID}`
            );
        }
    }

    if (isOpen) {
        const staffRows = (await allDb("SELECT * FROM staff WHERE lower(COALESCE(status, 'active')) NOT IN ('suspended', 'inactive', 'archived', 'resigned')")).map(mapStaffRow);
        for (const member of staffRows) {
            if (!staffCanWorkDivision(member, "healthcare-staffing")) {
                continue;
            }
            const eligibility = await staffMeetsRequestRequirements({
                staffMember: member,
                shift: {
                    id: Number(result.lastID),
                    scheduled_start: scheduledStart,
                    scheduled_end: scheduledEnd,
                },
                request: clientRequest,
            });
            if (member.notifyOpenShift && eligibility.eligible) {
                await queueStaffNotification(
                    member.id,
                    "New facility request shift available",
                    `A ${clientRequest.staff_required} shift for ${clientName} is now available for pickup.`,
                    "shift",
                    "/portal/staff-open-shifts"
                );
            }
        }
    }

    emitPortalEvent("shift_update", { action: isOpen ? "client_request_published" : "client_request_scheduled", shiftId: Number(result.lastID) }, { adminOnly: true });
    return Number(result.lastID);
};

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "..", "views"));
app.disable("x-powered-by");
if (trustProxy) {
    app.set("trust proxy", 1);
}
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("Permissions-Policy", "geolocation=(self)");
    if (isProduction) {
        res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }

    next();
});
app.use(
    session({
        name: "everkind.sid",
        secret: sessionSecret,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: "lax",
            secure: isProduction,
            maxAge: 8 * 60 * 60 * 1000,
        },
    })
);
app.use(express.static(path.join(__dirname, "..", "public")));
app.use(async (req, res, next) => {
    res.locals.staffPortalCounts = { openShifts: 0, notifications: 0, messages: 0 };
    res.locals.clientPortalCounts = { notifications: 0, openRequests: 0 };
    res.locals.adminPortalCounts = { homeVisits: 0, shiftRequests: 0, openShifts: 0, schedule: 0, facilityPortal: 0, liveTracking: 0 };
    res.locals.announcements = [];
    res.locals.publishedJobs = [];
    res.locals.websiteContact = buildPublicContact();

    try {
        const [announcements, publishedJobs] = await Promise.all([
            allDb(`
                SELECT *
                FROM website_announcements
                WHERE COALESCE(enabled, 1) = 1
                  AND (start_date IS NULL OR datetime(start_date) <= datetime('now'))
                  AND (end_date IS NULL OR datetime(end_date) >= datetime('now'))
                ORDER BY CASE priority
                    WHEN 'urgent' THEN 0
                    WHEN 'high' THEN 1
                    ELSE 2
                END, created_at DESC
            `),
            allDb(`
                SELECT *
                FROM website_jobs
                WHERE COALESCE(archived, 0) = 0
                  AND COALESCE(published, 1) = 1
                ORDER BY CASE WHEN COALESCE(featured, 0) = 1 THEN 0 ELSE 1 END, created_at DESC
            `),
        ]);
        res.locals.announcements = Array.isArray(announcements) ? announcements : [];
        res.locals.publishedJobs = Array.isArray(publishedJobs) ? publishedJobs : [];
    } catch (error) {
        console.error("Error loading website content:", error.message);
    }

    try {
        const now = new Date();
        const [shiftRequestsRow, openShiftsRow, operationalShiftCounts, facilityRegistrationsRow] = await Promise.all([
            getDb("SELECT COUNT(*) AS count FROM client_service_requests WHERE status IN ('pending_review', 'reviewing', 'request_more_information')"),
            getAvailableOpenShiftCount(now),
            getOperationalShiftCounts(now),
            getDb("SELECT COUNT(*) AS count FROM client_accounts WHERE status IN ('pending', 'more_info_requested', 'suspended')"),
        ]);
        res.locals.adminPortalCounts = {
            homeVisits: Number(operationalShiftCounts.homeVisits || 0),
            shiftRequests: Number(shiftRequestsRow ? shiftRequestsRow.count : 0),
            openShifts: Number(openShiftsRow || 0),
            schedule: Number(operationalShiftCounts.scheduled || 0),
            facilityPortal: Number(facilityRegistrationsRow ? facilityRegistrationsRow.count : 0),
            liveTracking: Number(operationalShiftCounts.liveTracking || 0),
        };
    } catch (error) {
        console.error("Error loading admin portal badge counts:", error.message);
    }

    if (!req.session || !req.session.isStaff || !req.session.staffId) {
        if (!req.session || !req.session.isClient || !req.session.clientAccountId) {
            return next();
        }
        try {
            const clientAccountId = Number(req.session.clientAccountId);
            const [notificationRow, requestRow] = await Promise.all([
                getDb(
                    "SELECT COUNT(*) AS count FROM client_notifications WHERE client_account_id = ? AND COALESCE(is_read, 0) = 0",
                    [clientAccountId]
                ),
                getDb(
                    "SELECT COUNT(*) AS count FROM client_service_requests WHERE client_account_id = ? AND status IN ('pending_review', 'reviewing', 'request_more_information', 'approved', 'awaiting_staff', 'accepted', 'confirmed', 'travelling', 'checked_in', 'on_break')",
                    [clientAccountId]
                ),
            ]);
            res.locals.clientPortalCounts = {
                notifications: Number(notificationRow ? notificationRow.count : 0),
                openRequests: Number(requestRow ? requestRow.count : 0),
            };
        } catch (error) {
            console.error("Error loading facility portal badge counts:", error.message);
        }
        return next();
    }

    try {
        const staffId = Number(req.session.staffId);
        const staffMember = mapStaffRow(await getDb("SELECT * FROM staff WHERE id = ?", [staffId]));
        const [openShiftRows, notificationRow, messageRow] = await Promise.all([
            allDb(`SELECT id, staff_id, service_division, client_account_id, request_source,
                          shift_date, scheduled_start, scheduled_end, actual_clock_in, actual_clock_out, status, is_open
                   FROM staff_shifts
                   WHERE COALESCE(is_open, 0) = 1 AND staff_id IS NULL`),
            getDb(
                "SELECT COUNT(*) AS count FROM staff_notifications WHERE staff_id = ? AND deleted_at IS NULL AND COALESCE(is_read, 0) = 0",
                [staffId]
            ),
            getDb(
                "SELECT COUNT(*) AS count FROM staff_messages WHERE staff_id = ? AND archived_at IS NULL AND sender_type = 'admin' AND COALESCE(is_read, 0) = 0",
                [staffId]
            ),
        ]);
        const openShiftCount = (openShiftRows || []).filter((shift) => (
            isAvailableOpenShift(shift)
            && staffCanWorkDivision(staffMember, getShiftDivision(shift))
        )).length;

        res.locals.staffPortalCounts = {
            openShifts: Number(openShiftCount),
            notifications: Number(notificationRow ? notificationRow.count : 0),
            messages: Number(messageRow ? messageRow.count : 0),
        };
        return next();
    } catch (error) {
        console.error("Error loading staff portal badge counts:", error.message);
        return next();
    }
});

const getSessionAdminValidation = async (req) => {
    if (!req.session.isAdmin) {
        return { valid: false, adminUser: null, reason: "admin_role_required" };
    }
    const adminUser = await getDb(
        "SELECT * FROM admin_users WHERE id = ? OR lower(username) = lower(?) ORDER BY id LIMIT 1",
        [Number(req.session.adminUserId) || -1, req.session.adminEmail || ""]
    );
    if (!adminUser) {
        return { valid: false, adminUser: null, reason: "admin_account_missing" };
    }
    if (Number(adminUser.is_active) !== 1) {
        return { valid: false, adminUser, reason: "admin_account_disabled" };
    }
    if (Number(req.session.adminAuthVersion || 0) !== Number(adminUser.auth_version || 1)) {
        return { valid: false, adminUser, reason: "admin_access_reset" };
    }
    return { valid: true, adminUser, reason: null };
};

const requirePortal = async (req, res, next) => {
    if (!req.session.isStaff && !req.session.isAdmin) {
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "portal_access_denied",
            targetType: "route",
            targetIdentifier: req.path,
            outcome: "denied",
            reason: "not_authenticated",
        });
        if (req.path.startsWith("/api/")) {
            return res.status(401).json({ success: false, message: "Authentication is required." });
        }
        return res.redirect("/portal/login?error=Please sign in to access the staff portal.");
    }

    const securityPolicy = await getSecurityPolicy();
    const now = Date.now();
    const lastActivityAt = Number(req.session.lastActivityAt || now);
    if (now - lastActivityAt > securityPolicy.sessionTimeoutMinutes * 60 * 1000) {
        await writeAuditEvent(req, {
            action: "session_expired",
            targetType: "session",
            outcome: "denied",
            reason: `inactive_${securityPolicy.sessionTimeoutMinutes}_minutes`,
        });
        await new Promise((resolve) => req.session.destroy(resolve));
        if (req.path.startsWith("/api/")) {
            return res.status(401).json({ success: false, message: "Your session has expired. Please sign in again." });
        }
        return res.redirect("/portal/login?error=" + encodeURIComponent("Your session expired. Please sign in again."));
    }
    req.session.lastActivityAt = now;

    if (req.session.isAdmin) {
        const validation = await getSessionAdminValidation(req);
        if (!validation.valid) {
            await writeAuditEvent(req, {
                action: "admin_access_denied",
                targetType: "route",
                targetIdentifier: req.path,
                outcome: "denied",
                reason: validation.reason,
            });
            req.session.isAdmin = false;
            req.session.adminPreviewRole = null;
            if (!req.session.isStaff) {
                if (req.path.startsWith("/api/")) {
                    return res.status(403).json({
                        success: false,
                        message: "Your administrator access is no longer active.",
                    });
                }
                return res.status(403).render("access-denied", {
                    title: "Access denied",
                    message: "Your administrator access is no longer active. Please sign in again or contact a Super Admin.",
                    requiredPermission: null,
                    currentRole: req.session.adminRole || "Administrator",
                    currentStaffName: req.session.adminName || "Administrator",
                    currentStaffEmail: req.session.adminEmail || "",
                    isAdmin: false,
                });
            }
        } else {
            req.portalAdminUser = validation.adminUser;
        }
    }

    if (req.session.isStaff && req.session.staffId) {
        const staffSessionAccount = await getDb(
            `SELECT id, mfa_version, portal_login_enabled, portal_login_suspended,
                    portal_login_deactivated, status
             FROM staff WHERE id = ?`,
            [Number(req.session.staffId)]
        );
        const staffSessionValid = staffSessionAccount
            && !isStaffLoginBlocked(staffSessionAccount)
            && Number(req.session.staffMfaVersion || 0) === Number(staffSessionAccount.mfa_version || 1);
        if (!staffSessionValid) {
            await writeAuditEvent(req, {
                ...getActorContext(req),
                action: "staff_access_denied",
                targetType: "route",
                targetIdentifier: req.path,
                outcome: "denied",
                reason: staffSessionAccount ? "staff_security_reset" : "staff_account_missing",
            });
            req.session.isStaff = false;
            req.session.staffId = null;
            if (!req.session.isAdmin) {
                if (req.path.startsWith("/api/")) {
                    return res.status(403).json({ success: false, message: "Your staff session is no longer active." });
                }
                return res.redirect("/portal/login?error=" + encodeURIComponent("Your staff session is no longer active. Please sign in again."));
            }
        }
    }

    const previewBypassPaths = new Set([
        "/admin/preview/staff",
        "/admin/view-as/exit",
        "/api/admin/logout",
    ]);
    if (req.session.isAdmin && !previewBypassPaths.has(req.path)) {
        const access = await loadAdminAccessContext(req.portalAdminUser, req.session.adminPreviewRole);
        res.locals.adminAccess = access;
        res.locals.can = (permission) => hasPermission(access.permissions, permission);
        const requiredPermission = getRequiredPermission(req.method, req.path);
        if (!hasPermission(access.permissions, requiredPermission)) {
            const isPreview = Boolean(req.session.adminPreviewRole);
            await writeAuditEvent(req, {
                action: "access_denied",
                targetType: "route",
                targetIdentifier: requiredPermission,
                outcome: "denied",
                reason: isPreview
                    ? `preview_role_${req.session.adminPreviewRole}_does_not_grant_permission`
                    : `role_${access.actualRole}_does_not_grant_permission`,
                metadata: { method: req.method, path: req.path },
            });
            if (req.path.startsWith("/api/")) {
                return res.status(403).json({
                    success: false,
                    message: isPreview
                        ? "This action is not available in role preview mode."
                        : "Your administrator role does not permit this action.",
                    requiredPermission,
                });
            }
            return res.status(403).render("access-denied", {
                title: "Access denied",
                message: isPreview
                    ? "This page is not available in role preview mode."
                    : "Your administrator role does not permit access to this page.",
                requiredPermission,
                currentRole: access.effectiveRoleLabel,
                currentStaffName: req.session.adminName || "Administrator",
                currentStaffEmail: req.session.adminEmail || "",
                isAdmin: true,
            });
        }
    }

    return next();
};

const requireAdmin = async (req, res, next) => {
    if (!req.session.isAdmin) {
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "admin_access_denied",
            targetType: "route",
            targetIdentifier: req.path,
            outcome: "denied",
            reason: "admin_role_required",
        });
        if (req.path.startsWith("/api/")) {
            return res.status(403).json({ success: false, message: "Administrator access is required." });
        }
        return res.status(403).render("access-denied", {
            title: "Access denied",
            message: "Administrator access is required.",
            requiredPermission: null,
            currentRole: "Staff",
            currentStaffName: req.session.staffName || "Staff member",
            currentStaffEmail: req.session.staffEmail || "",
            isAdmin: false,
        });
    }

    const adminUser = await getDb(
        "SELECT * FROM admin_users WHERE id = ? OR lower(username) = lower(?) ORDER BY id LIMIT 1",
        [Number(req.session.adminUserId) || -1, req.session.adminEmail || ""]
    );
    const currentAuthVersion = Number(adminUser?.auth_version || 1);
    const sessionAuthVersion = Number(req.session.adminAuthVersion || 0);

    if (!adminUser || Number(adminUser.is_active) !== 1 || sessionAuthVersion !== currentAuthVersion) {
        await writeAuditEvent(req, {
            action: "admin_access_denied",
            targetType: "route",
            targetIdentifier: req.path,
            outcome: "denied",
            reason: !adminUser
                ? "admin_account_missing"
                : Number(adminUser.is_active) !== 1
                    ? "admin_account_disabled"
                    : "admin_access_reset",
        });
        req.session.isAdmin = false;
        if (req.path.startsWith("/api/")) {
            return res.status(403).json({ success: false, message: "Your administrator access is no longer active." });
        }
        return res.status(403).render("access-denied", {
            title: "Access denied",
            message: "Your administrator access is no longer active. Please sign in again or contact a Super Admin.",
            requiredPermission: null,
            currentRole: req.session.adminRole || "Administrator",
            currentStaffName: req.session.adminName || "Administrator",
            currentStaffEmail: req.session.adminEmail || "",
            isAdmin: false,
        });
    }

    req.session.adminUserId = adminUser.id;
    req.session.adminAuthVersion = currentAuthVersion;
    const access = await loadAdminAccessContext(adminUser, req.session.adminPreviewRole);
    req.session.adminRole = access.actualRole;
    const requiredPermission = getRequiredPermission(req.method, req.path);
    const permissionsToCheck = req.path === "/admin/view-as/exit"
        ? access.actualPermissions
        : access.permissions;

    res.locals.adminAccess = access;
    res.locals.can = (permission) => hasPermission(access.permissions, permission);
    res.locals.rbacModules = RBAC_MODULES;
    res.locals.rbacActions = RBAC_ACTIONS;

    if (!hasPermission(permissionsToCheck, requiredPermission)) {
        await writeAuditEvent(req, {
            action: "access_denied",
            targetType: "permission",
            targetIdentifier: requiredPermission,
            outcome: "denied",
            reason: access.isPreview
                ? `preview_role_${access.effectiveRole}_does_not_grant_permission`
                : `role_${access.actualRole}_does_not_grant_permission`,
            metadata: {
                method: req.method,
                path: req.path,
                actualRole: access.actualRole,
                effectiveRole: access.effectiveRole,
            },
        });
        if (req.path.startsWith("/api/")) {
            return res.status(403).json({
                success: false,
                message: "You do not have permission to perform this action.",
                requiredPermission,
            });
        }
        return res.status(403).render("access-denied", {
            title: "Access denied",
            message: "Your role does not permit access to this page or action.",
            requiredPermission,
            currentRole: access.effectiveRoleLabel,
            currentStaffName: adminUser.name || req.session.adminName || "Administrator",
            currentStaffEmail: adminUser.username,
            isAdmin: true,
            adminAccess: access,
        });
    }

    return next();
};

const requireSuperAdmin = async (req, res, next) => {
    const access = res.locals.adminAccess;
    if (access && access.actualRole === "super_admin" && !access.isPreview) return next();
    await writeAuditEvent(req, {
        ...getActorContext(req),
        action: "access_denied",
        targetType: "permission",
        targetIdentifier: "super_admin",
        outcome: "denied",
        reason: "super_admin_required",
    });
    if (req.path.startsWith("/api/")) {
        return res.status(403).json({ success: false, message: "Super Admin access is required." });
    }
    return res.status(403).render("access-denied", {
        title: "Access denied",
        message: "Only a Super Admin can perform this action.",
        requiredPermission: "super_admin",
        currentRole: access ? access.effectiveRoleLabel : "Administrator",
        currentStaffName: req.session.adminName || "Administrator",
        currentStaffEmail: req.session.adminEmail || "",
        isAdmin: true,
    });
};

const requireStaffOnly = async (req, res, next) => {
    if (!req.session.isStaff || !req.session.staffId) {
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "staff_portal_access_denied",
            targetType: "route",
            targetIdentifier: req.path,
            outcome: "denied",
            reason: "staff_role_required",
        });
        if (req.path.startsWith("/api/")) {
            return res.status(403).json({ success: false, message: "Staff access is required." });
        }
        return res.redirect("/portal/login?error=Please sign in with a staff account.");
    }

    return next();
};

const requireClientPortal = async (req, res, next) => {
    if (!req.session.isClient || !req.session.clientAccountId) {
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "client_portal_access_denied",
            targetType: "route",
            targetIdentifier: req.path,
            outcome: "denied",
            reason: "client_role_required",
        });
        if (req.path.startsWith("/api/")) {
            return res.status(403).json({ success: false, message: "Facility portal access is required." });
        }
        return res.redirect("/facility-portal/login?error=Please sign in with a facility account.");
    }
    return next();
};

app.get("/portal/events", requirePortal, (req, res) => {
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders();

    const client = {
        res,
        isAdmin: Boolean(req.session.isAdmin),
        staffId: req.session.staffId ? Number(req.session.staffId) : null,
    };
    portalEventClients.add(client);
    res.write(`data: ${JSON.stringify({ type: "connected", emittedAt: new Date().toISOString() })}\n\n`);

    const keepAliveTimer = setInterval(() => {
        try {
            res.write(`data: ${JSON.stringify({ type: "ping", emittedAt: new Date().toISOString() })}\n\n`);
        } catch (error) {
            clearInterval(keepAliveTimer);
            portalEventClients.delete(client);
        }
    }, 25000);

    req.on("close", () => {
        clearInterval(keepAliveTimer);
        portalEventClients.delete(client);
    });
});

const initializeDatabase = async () => {
    if (isPostgres) {
        await validateDatabase();
        await ensureAdminAndRbacData();
        return;
    }

    await runDb(`
        CREATE TABLE IF NOT EXISTS app_status (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            status TEXT NOT NULL DEFAULT 'healthy',
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS subject_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_type TEXT NOT NULL,
            patient_id INTEGER,
            requested_by TEXT,
            status TEXT NOT NULL,
            details TEXT,
            processed_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT,
            last_name TEXT,
            date_of_birth TEXT,
            gender TEXT,
            address TEXT,
            phone TEXT,
            email TEXT,
            emergency_contact TEXT,
            care_level TEXT,
            status TEXT DEFAULT 'Active',
            risk_level TEXT DEFAULT 'Low',
            latitude REAL,
            longitude REAL,
            geofence_radius_meters INTEGER DEFAULT 80,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            age INTEGER,
            condition TEXT,
            carePlan TEXT,
            nextVisit TEXT,
            name TEXT,
            legal_basis TEXT DEFAULT 'care_contract',
            consent_status TEXT DEFAULT 'pending',
            consent_recorded_at TEXT,
            consent_recorded_by TEXT,
            data_retention_until TEXT,
            is_archived INTEGER DEFAULT 0,
            archived_at TEXT
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER,
            staff_id INTEGER,
            title TEXT,
            start TEXT,
            end TEXT,
            notes TEXT,
            status TEXT DEFAULT 'Scheduled',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            client TEXT,
            date TEXT,
            time TEXT,
            type TEXT
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS care_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER,
            author TEXT,
            note TEXT,
            severity TEXT DEFAULT 'Normal',
            retention_expires_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS care_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            review_type TEXT NOT NULL DEFAULT 'care',
            reviewer_staff_id INTEGER,
            due_date TEXT NOT NULL,
            completed_at TEXT,
            status TEXT NOT NULL DEFAULT 'upcoming',
            notes TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS staff (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT,
            last_name TEXT,
            role TEXT,
            email TEXT UNIQUE,
            phone TEXT,
            status TEXT DEFAULT 'Active',
            password_hash TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            name TEXT,
            shift TEXT
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            role TEXT DEFAULT 'super_admin',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            role_key TEXT NOT NULL UNIQUE,
            label TEXT NOT NULL,
            description TEXT,
            is_system INTEGER NOT NULL DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            permission_key TEXT NOT NULL UNIQUE,
            module_key TEXT NOT NULL,
            action TEXT NOT NULL,
            description TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS role_permissions (
            role_id INTEGER NOT NULL,
            permission_id INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (role_id, permission_id),
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
            FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS user_roles (
            admin_user_id INTEGER NOT NULL,
            role_id INTEGER NOT NULL,
            scope_type TEXT NOT NULL DEFAULT 'global',
            scope_value TEXT NOT NULL DEFAULT '',
            is_primary INTEGER NOT NULL DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (admin_user_id, role_id, scope_type, scope_value),
            FOREIGN KEY (admin_user_id) REFERENCES admin_users(id) ON DELETE CASCADE,
            FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS staff_shifts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            staff_id INTEGER,
            patient_id INTEGER,
            shift_date TEXT,
            scheduled_start TEXT,
            scheduled_end TEXT,
            actual_clock_in TEXT,
            actual_clock_out TEXT,
            status TEXT DEFAULT 'scheduled',
            clock_in_latitude REAL,
            clock_in_longitude REAL,
            clock_out_latitude REAL,
            clock_out_longitude REAL,
            clock_in_note TEXT,
            clock_out_note TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_type TEXT NOT NULL,
            actor_identifier TEXT,
            action TEXT NOT NULL,
            target_type TEXT,
            target_identifier TEXT,
            outcome TEXT NOT NULL,
            reason TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS staff_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            staff_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            type TEXT DEFAULT 'info',
            link_url TEXT,
            is_read INTEGER DEFAULT 0,
            deleted_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS staff_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            staff_id INTEGER NOT NULL,
            sender_type TEXT NOT NULL,
            sender_name TEXT NOT NULL,
            subject TEXT,
            body TEXT NOT NULL,
            is_read INTEGER DEFAULT 0,
            archived_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS staff_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            staff_id INTEGER,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            file_name TEXT,
            download_text TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS shift_attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shift_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            file_name TEXT,
            download_text TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS patient_assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            staff_id INTEGER NOT NULL,
            assignment_role TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS patient_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            file_name TEXT NOT NULL,
            mime_type TEXT,
            data_url TEXT NOT NULL,
            is_staff_visible INTEGER DEFAULT 1,
            uploaded_by TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS staff_shift_visit_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shift_id INTEGER NOT NULL,
            staff_id INTEGER NOT NULL,
            note TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS staff_shift_reminders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            shift_id INTEGER NOT NULL,
            staff_id INTEGER NOT NULL,
            reminder_type TEXT NOT NULL,
            reminder_minutes INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS staff_training (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            staff_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            status TEXT DEFAULT 'completed',
            completed_at TEXT,
            expires_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS staff_password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            staff_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS client_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_name TEXT NOT NULL,
            trading_name TEXT,
            organization_type TEXT NOT NULL,
            registration_number TEXT,
            hiqa_registration_number TEXT,
            hse_contract_number TEXT,
            vat_number TEXT,
            website TEXT,
            contact_first_name TEXT NOT NULL,
            contact_last_name TEXT NOT NULL,
            contact_job_title TEXT,
            email TEXT UNIQUE NOT NULL,
            mobile_number TEXT NOT NULL,
            office_telephone TEXT,
            address_line_1 TEXT NOT NULL,
            address_line_2 TEXT,
            town TEXT NOT NULL,
            county TEXT NOT NULL,
            eircode TEXT,
            gps_latitude REAL,
            gps_longitude REAL,
            service_requirements TEXT,
            number_of_beds TEXT,
            number_of_residents TEXT,
            number_of_units TEXT,
            existing_staff_numbers TEXT,
            current_staffing_provider TEXT,
            preferred_shift_types TEXT,
            gdpr_agreement INTEGER DEFAULT 0,
            privacy_agreement INTEGER DEFAULT 0,
            terms_agreement INTEGER DEFAULT 0,
            hiqa_compliance_agreement INTEGER DEFAULT 0,
            authorised_representative INTEGER DEFAULT 0,
            status TEXT DEFAULT 'pending',
            password_hash TEXT,
            portal_login_enabled INTEGER DEFAULT 0,
            portal_login_suspended INTEGER DEFAULT 0,
            portal_login_deactivated INTEGER DEFAULT 0,
            approved_at TEXT,
            approved_by TEXT,
            review_notes TEXT,
            assigned_account_manager TEXT,
            favourite_staff_ids TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS client_password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_account_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS website_announcements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            headline TEXT NOT NULL,
            message TEXT,
            color TEXT DEFAULT 'emerald',
            priority TEXT DEFAULT 'normal',
            enabled INTEGER DEFAULT 1,
            auto_scroll INTEGER DEFAULT 1,
            start_date TEXT,
            end_date TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS website_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            location TEXT,
            county TEXT,
            employment_type TEXT,
            salary TEXT,
            description TEXT,
            requirements TEXT,
            benefits TEXT,
            closing_date TEXT,
            featured INTEGER DEFAULT 0,
            urgent INTEGER DEFAULT 0,
            published INTEGER DEFAULT 1,
            archived INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    const announcementCount = await getDb("SELECT COUNT(*) AS count FROM website_announcements");
    if (!announcementCount || Number(announcementCount.count || 0) === 0) {
        await runDb(`
            INSERT INTO website_announcements (headline, message, color, priority, enabled, auto_scroll, start_date, end_date)
            VALUES
                ('Immediate staffing available nationwide', 'We are urgently supporting healthcare facilities across Ireland with qualified professionals.', 'emerald', 'urgent', 1, 1, NULL, NULL),
                ('Free care assessments available', 'Families and care teams can request a care assessment and get support quickly.', 'blue', 'high', 1, 1, NULL, NULL)
        `);
    }

    const jobCount = await getDb("SELECT COUNT(*) AS count FROM website_jobs");
    if (!jobCount || Number(jobCount.count || 0) === 0) {
        await runDb(`
            INSERT INTO website_jobs (title, location, county, employment_type, salary, description, requirements, benefits, closing_date, featured, urgent, published, archived)
            VALUES
                ('Healthcare Assistant', 'Dublin', 'Dublin', 'Full Time', '€18-€24 per hour', 'Support residents and clients with personal care and daily routines in a fast-paced healthcare setting.', 'QQI Level 5 or equivalent, compassionate approach, valid work authorisation', 'Weekly pay, free mandatory training, referral bonus', '2026-12-31', 1, 0, 1, 0),
                ('Staff Nurse', 'Cork', 'Cork', 'Agency', 'Competitive', 'Provide clinical support and patient-centred care across nursing home and hospital assignments.', 'NMBI registration, minimum 2 years experience, flexible availability', 'Flexible shifts, CPD support, nationwide opportunities', '2026-11-30', 0, 1, 1, 0)
        `);
    }

    await ensureColumns("admin_users", [
        ["name", "TEXT"],
        ["department", "TEXT"],
        ["phone", "TEXT"],
        ["email_normalized", "TEXT"],
        ["phone_normalized", "TEXT"],
        ["email_verified", "INTEGER NOT NULL DEFAULT 0"],
        ["phone_verified", "INTEGER NOT NULL DEFAULT 0"],
        ["mfa_enabled", "INTEGER NOT NULL DEFAULT 0"],
        ["mfa_preferred_method", "TEXT"],
        ["totp_secret_encrypted", "TEXT"],
        ["totp_verified_at", "TEXT"],
        ["mfa_reset_required", "INTEGER NOT NULL DEFAULT 0"],
        ["mfa_version", "INTEGER NOT NULL DEFAULT 1"],
        ["is_active", "INTEGER NOT NULL DEFAULT 1"],
        ["last_login", "TEXT"],
        ["last_login_ip", "TEXT"],
        ["auth_version", "INTEGER NOT NULL DEFAULT 1"],
        ["updated_at", "TEXT"],
    ]);
    await ensureColumns("audit_events", [
        ["actor_role", "TEXT"],
        ["metadata", "TEXT"],
    ]);
    await ensureColumns("staff", [
        ["email_normalized", "TEXT"],
        ["phone_normalized", "TEXT"],
        ["mobile_number", "TEXT"],
        ["is_archived", "INTEGER NOT NULL DEFAULT 0"],
        ["email_verified", "INTEGER NOT NULL DEFAULT 0"],
        ["phone_verified", "INTEGER NOT NULL DEFAULT 0"],
        ["mfa_enabled", "INTEGER NOT NULL DEFAULT 0"],
        ["mfa_preferred_method", "TEXT"],
        ["totp_secret_encrypted", "TEXT"],
        ["totp_verified_at", "TEXT"],
        ["mfa_reset_required", "INTEGER NOT NULL DEFAULT 0"],
        ["mfa_version", "INTEGER NOT NULL DEFAULT 1"],
        ["updated_at", "TEXT"],
    ]);
    await runDb(`
        CREATE TABLE IF NOT EXISTS mfa_challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_type TEXT NOT NULL,
            account_id INTEGER NOT NULL,
            purpose TEXT NOT NULL,
            method TEXT NOT NULL,
            nonce TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            attempts_remaining INTEGER NOT NULL DEFAULT 5,
            expires_at TEXT NOT NULL,
            resend_after TEXT NOT NULL,
            consumed_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);
    await runDb(`
        CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_type TEXT NOT NULL,
            account_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);
    await runDb(`
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_type TEXT NOT NULL,
            account_id INTEGER NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);
    await runDb("CREATE INDEX IF NOT EXISTS idx_mfa_challenges_account ON mfa_challenges(account_type, account_id, purpose, created_at)");
    await runDb("CREATE INDEX IF NOT EXISTS idx_mfa_recovery_account ON mfa_recovery_codes(account_type, account_id, used_at)");
    await runDb("CREATE INDEX IF NOT EXISTS idx_password_history_account ON password_history(account_type, account_id, created_at)");
    const mfaPolicyDefaults = {
        mfa_global_enabled: "0",
        mfa_role_super_admin: "1",
        mfa_role_hr: "1",
        mfa_role_payroll: "1",
        mfa_role_manager: "1",
        mfa_role_staff: "0",
    };
    for (const [key, value] of Object.entries(mfaPolicyDefaults)) {
        await runDb(
            `INSERT INTO system_settings (key, value, updated_at)
             VALUES (?, ?, CURRENT_TIMESTAMP)
             ON CONFLICT(key) DO NOTHING`,
            [key, value]
        );
    }
    const adminIdentityRows = await allDb("SELECT id, username, phone FROM admin_users");
    for (const row of adminIdentityRows) {
        await runDb(
            "UPDATE admin_users SET email_normalized = ?, phone_normalized = ? WHERE id = ?",
            [normalizeEmailAddress(row.username), normalizePhoneForUniqueness(row.phone), row.id]
        );
    }
    const staffIdentityRows = await allDb("SELECT id, email, phone, mobile_number FROM staff");
    for (const row of staffIdentityRows) {
        await runDb(
            "UPDATE staff SET email_normalized = ?, phone_normalized = ? WHERE id = ?",
            [
                normalizeEmailAddress(row.email),
                normalizePhoneForUniqueness(row.mobile_number || row.phone),
                row.id,
            ]
        );
    }
    const adminIdentityDuplicates = await getDb(
        `SELECT COUNT(*) AS count FROM (
            SELECT email_normalized FROM admin_users
            WHERE is_active = 1 AND COALESCE(email_normalized, '') != ''
            GROUP BY email_normalized HAVING COUNT(*) > 1
            UNION ALL
            SELECT phone_normalized FROM admin_users
            WHERE is_active = 1 AND COALESCE(phone_normalized, '') != ''
            GROUP BY phone_normalized HAVING COUNT(*) > 1
        )`
    );
    const staffIdentityDuplicates = await getDb(
        `SELECT COUNT(*) AS count FROM (
            SELECT email_normalized FROM staff
            WHERE COALESCE(is_archived, 0) = 0 AND COALESCE(email_normalized, '') != ''
            GROUP BY email_normalized HAVING COUNT(*) > 1
            UNION ALL
            SELECT phone_normalized FROM staff
            WHERE COALESCE(is_archived, 0) = 0 AND COALESCE(phone_normalized, '') != ''
            GROUP BY phone_normalized HAVING COUNT(*) > 1
        )`
    );
    if (Number(adminIdentityDuplicates?.count || 0) === 0) {
        await runDb("CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_users_email_normalized_active ON admin_users(email_normalized) WHERE is_active = 1 AND email_normalized != ''");
        await runDb("CREATE UNIQUE INDEX IF NOT EXISTS idx_admin_users_phone_normalized_active ON admin_users(phone_normalized) WHERE is_active = 1 AND phone_normalized != ''");
    }
    if (Number(staffIdentityDuplicates?.count || 0) === 0) {
        await runDb("CREATE UNIQUE INDEX IF NOT EXISTS idx_staff_email_normalized_active ON staff(email_normalized) WHERE COALESCE(is_archived, 0) = 0 AND email_normalized != ''");
        await runDb("CREATE UNIQUE INDEX IF NOT EXISTS idx_staff_phone_normalized_active ON staff(phone_normalized) WHERE COALESCE(is_archived, 0) = 0 AND phone_normalized != ''");
    }
    await runDb("CREATE INDEX IF NOT EXISTS idx_admin_users_active ON admin_users(is_active)");
    await runDb("CREATE INDEX IF NOT EXISTS idx_user_roles_admin_user ON user_roles(admin_user_id)");
    await runDb("CREATE INDEX IF NOT EXISTS idx_audit_events_actor_role ON audit_events(actor_role)");

    await ensureColumn("client_accounts", "facility_id", "TEXT");
    await ensureColumn("client_accounts", "onboarded", "INTEGER DEFAULT 0");
    await ensureColumn("client_accounts", "password_hash", "TEXT");

    await runDb(`
        CREATE TABLE IF NOT EXISTS client_service_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_account_id INTEGER NOT NULL,
            staff_required TEXT NOT NULL,
            quantity_required INTEGER DEFAULT 1,
            shift_type TEXT NOT NULL,
            shift_date TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            ward_unit TEXT,
            resident_identifier TEXT,
            room_number TEXT,
            resident_unit TEXT,
            required_skills TEXT,
            notes TEXT,
            priority TEXT DEFAULT 'Routine',
            status TEXT DEFAULT 'open',
            assigned_staff_id INTEGER,
            published_open_shift_id INTEGER,
            scheduled_shift_id INTEGER,
            completed_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS client_notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_account_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            type TEXT DEFAULT 'info',
            link_url TEXT,
            is_read INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            role TEXT,
            availability TEXT,
            status TEXT DEFAULT 'new',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);
    await runDb(`
        CREATE TABLE IF NOT EXISTS application_timeline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id INTEGER NOT NULL,
            stage TEXT NOT NULL,
            title TEXT NOT NULL,
            notes TEXT,
            actor_type TEXT,
            actor_identifier TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await ensureColumn("applications", "name", "TEXT");
    await ensureColumn("applications", "first_name", "TEXT");
    await ensureColumn("applications", "surname", "TEXT");
    await ensureColumn("applications", "email", "TEXT");
    await ensureColumn("applications", "email_normalized", "TEXT");
    await ensureColumn("applications", "phone", "TEXT");
    await ensureColumn("applications", "phone_normalized", "TEXT");
    await ensureColumn("applications", "role", "TEXT");
    await ensureColumn("applications", "availability", "TEXT");
    await ensureColumn("applications", "status", "TEXT DEFAULT 'new'");
    await ensureColumn("applications", "application_ref", "TEXT");
    await ensureColumn("applications", "reviewed_at", "TEXT");
    await ensureColumn("applications", "reviewed_by", "TEXT");
    await ensureColumn("applications", "shortlisted_at", "TEXT");
    await ensureColumn("applications", "interview_scheduled_at", "TEXT");
    await ensureColumn("applications", "interview_completed_at", "TEXT");
    await ensureColumn("applications", "offer_sent_at", "TEXT");
    await ensureColumn("applications", "offer_accepted_at", "TEXT");
    await ensureColumn("applications", "pre_employment_checks_at", "TEXT");
    await ensureColumn("applications", "induction_started_at", "TEXT");
    await ensureColumn("applications", "approved_employee_at", "TEXT");
    await ensureColumn("applications", "active_staff_at", "TEXT");
    await ensureColumn("applications", "rejected_at", "TEXT");
    await ensureColumn("applications", "archived_at", "TEXT");
    await ensureColumn("applications", "last_stage_changed_at", "TEXT");
    await ensureColumn("applications", "last_stage_changed_by", "TEXT");
    const legacyApplicationRows = await allDb("SELECT id, name, first_name, surname, email, phone FROM applications");
    for (const legacyRow of legacyApplicationRows) {
        const nameParts = buildApplicationNameParts(legacyRow);
        await runDb(
            `UPDATE applications
             SET name = ?,
                 first_name = ?,
                 surname = ?,
                 email_normalized = ?,
                 phone_normalized = ?
             WHERE id = ?`,
            [
                nameParts.fullName || String(legacyRow.name || "").trim(),
                nameParts.firstName,
                nameParts.surname,
                normalizeEmailAddress(legacyRow.email),
                normalizePhoneForUniqueness(legacyRow.phone),
                Number(legacyRow.id),
            ]
        );
    }
    const duplicateNormalizedEmail = await getDb(
        `SELECT email_normalized, COUNT(*) AS duplicate_count
         FROM applications
         WHERE COALESCE(email_normalized, '') <> ''
         GROUP BY email_normalized
         HAVING COUNT(*) > 1
         LIMIT 1`
    );
    const duplicateNormalizedPhone = await getDb(
        `SELECT phone_normalized, COUNT(*) AS duplicate_count
         FROM applications
         WHERE COALESCE(phone_normalized, '') <> ''
         GROUP BY phone_normalized
         HAVING COUNT(*) > 1
         LIMIT 1`
    );
    if (!duplicateNormalizedEmail) {
        await runDb(
            `CREATE UNIQUE INDEX IF NOT EXISTS idx_applications_email_normalized_unique
             ON applications(email_normalized)
             WHERE COALESCE(email_normalized, '') <> ''`
        );
    } else {
        console.warn("Applications email uniqueness index skipped due to existing duplicate legacy values.");
        await runDb(
            `CREATE INDEX IF NOT EXISTS idx_applications_email_normalized
             ON applications(email_normalized)`
        );
    }
    if (!duplicateNormalizedPhone) {
        await runDb(
            `CREATE UNIQUE INDEX IF NOT EXISTS idx_applications_phone_normalized_unique
             ON applications(phone_normalized)
             WHERE COALESCE(phone_normalized, '') <> ''`
        );
    } else {
        console.warn("Applications phone uniqueness index skipped due to existing duplicate legacy values.");
        await runDb(
            `CREATE INDEX IF NOT EXISTS idx_applications_phone_normalized
             ON applications(phone_normalized)`
        );
    }
    await ensureColumn("staff_shifts", "is_open", "INTEGER DEFAULT 0");
    await ensureColumn("staff_shifts", "client_account_id", "INTEGER");
    await ensureColumn("staff_shifts", "client_request_id", "INTEGER");
    await ensureColumn("staff_shifts", "request_source", "TEXT");
    await ensureColumn("staff_shifts", "external_client_label", "TEXT");
    await ensureColumn("staff_shifts", "location_address", "TEXT");
    await ensureColumn("staff_shifts", "location_town", "TEXT");
    await ensureColumn("staff_shifts", "location_county", "TEXT");
    await ensureColumn("staff_shifts", "location_eircode", "TEXT");
    await ensureColumn("staff_shifts", "external_latitude", "REAL");
    await ensureColumn("staff_shifts", "external_longitude", "REAL");
    await ensureColumn("staff_shifts", "external_geofence_radius_meters", "INTEGER DEFAULT 100");
    await ensureColumn("staff_shifts", "ward_unit", "TEXT");
    await ensureColumn("staff_shifts", "service_division", "TEXT DEFAULT 'home-care'");
    await ensureColumn("staff_shifts", "shift_code", "TEXT");
    await ensureColumn("staff_shifts", "facility_type", "TEXT");
    await ensureColumn("staff_shifts", "role_required", "TEXT");
    await ensureColumn("staff_shifts", "shift_requirements", "TEXT");
    await ensureColumn("staff_shifts", "break_duration_minutes", "INTEGER DEFAULT 0");
    await ensureColumn("staff_shifts", "quantity_required", "INTEGER DEFAULT 1");
    await ensureColumn("staff_shifts", "contact_person", "TEXT");
    await ensureColumn("staff_shifts", "mileage_km", "REAL DEFAULT 0");
    await ensureColumn("staff_shifts", "payroll_status", "TEXT DEFAULT 'draft'");
    await ensureColumn("staff_shifts", "pay_rate", "REAL");
    await ensureColumn("staff_shifts", "pay_rate_source", "TEXT");
    await runDb(`
        UPDATE staff_shifts
        SET pay_rate = (
                SELECT CAST(s.hourly_rate AS REAL)
                FROM staff s
                WHERE s.id = staff_shifts.staff_id
            ),
            pay_rate_source = 'legacy_staff_rate_backfill'
        WHERE staff_id IS NOT NULL
          AND pay_rate IS NULL
          AND EXISTS (
              SELECT 1
              FROM staff s
              WHERE s.id = staff_shifts.staff_id
                AND s.hourly_rate IS NOT NULL
                AND TRIM(CAST(s.hourly_rate AS TEXT)) != ''
                AND CAST(s.hourly_rate AS REAL) >= 0
          )
    `);

    await runDb(`
        CREATE TABLE IF NOT EXISTS payroll_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            staff_id INTEGER NOT NULL,
            period_start TEXT NOT NULL,
            period_end TEXT NOT NULL,
            total_hours REAL DEFAULT 0,
            gross_pay REAL DEFAULT 0,
            net_pay REAL DEFAULT 0,
            mileage_km REAL DEFAULT 0,
            mileage_payment REAL DEFAULT 0,
            status TEXT DEFAULT 'draft',
            approved_by TEXT,
            approved_at TEXT,
            paid_at TEXT,
            payment_date TEXT,
            notes TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(staff_id, period_start, period_end)
        )
    `);
    await ensureColumns("payroll_records", [
        ["approved_by", "TEXT"],
        ["approved_at", "TEXT"],
        ["paid_at", "TEXT"],
        ["payment_date", "TEXT"],
        ["notes", "TEXT"],
        ["snapshot_json", "TEXT"],
        ["created_at", "TEXT"],
        ["updated_at", "TEXT"],
    ]);
    await runDb(`
        CREATE TABLE IF NOT EXISTS payslips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            staff_id INTEGER NOT NULL,
            payroll_record_id INTEGER,
            period_start TEXT NOT NULL,
            period_end TEXT NOT NULL,
            gross_pay REAL DEFAULT 0,
            net_pay REAL DEFAULT 0,
            file_path TEXT,
            payment_date TEXT,
            email_status TEXT DEFAULT 'not_scheduled',
            email_scheduled_at TEXT,
            email_sent_at TEXT,
            generated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            generated_by TEXT,
            payslip_ref TEXT UNIQUE
        )
    `);
    await ensureColumns("payslips", [
        ["payment_date", "TEXT"],
        ["email_status", "TEXT DEFAULT 'not_scheduled'"],
        ["email_scheduled_at", "TEXT"],
        ["email_sent_at", "TEXT"],
        ["generated_at", "TEXT"],
        ["generated_by", "TEXT"],
    ]);
    await runDb(`
        CREATE TABLE IF NOT EXISTS payslip_email_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payslip_id INTEGER NOT NULL,
            staff_id INTEGER NOT NULL,
            email_address TEXT,
            subject TEXT,
            status TEXT,
            error_message TEXT,
            sent_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);
    await ensureColumn("client_accounts", "force_password_reset", "INTEGER DEFAULT 0");
    await ensureColumn("client_accounts", "facility_id", "TEXT");
    await ensureColumn("client_service_requests", "facility_name", "TEXT");
    await ensureColumn("client_service_requests", "facility_type", "TEXT");
    await ensureColumn("client_service_requests", "facility_address", "TEXT");
    await ensureColumn("client_service_requests", "facility_county", "TEXT");
    await ensureColumn("client_service_requests", "facility_eircode", "TEXT");
    await ensureColumn("client_service_requests", "facility_gps_latitude", "REAL");
    await ensureColumn("client_service_requests", "facility_gps_longitude", "REAL");
    await ensureColumn("client_service_requests", "contact_person", "TEXT");
    await ensureColumn("client_service_requests", "contact_position", "TEXT");
    await ensureColumn("client_service_requests", "contact_phone", "TEXT");
    await ensureColumn("client_service_requests", "contact_email", "TEXT");
    await ensureColumn("client_service_requests", "emergency_contact", "TEXT");
    await ensureColumn("client_service_requests", "break_duration_minutes", "INTEGER DEFAULT 0");
    await ensureColumn("client_service_requests", "total_paid_hours", "REAL");
    await ensureColumn("client_service_requests", "recurring_pattern", "TEXT");
    await ensureColumn("client_service_requests", "multiple_dates", "TEXT");
    await ensureColumn("client_service_requests", "weekly_repeat_day", "TEXT");
    await ensureColumn("client_service_requests", "monthly_repeat_date", "INTEGER");
    await ensureColumn("client_service_requests", "hourly_rate", "REAL");
    await ensureColumn("client_service_requests", "required_training", "TEXT");
    await ensureColumn("client_service_requests", "minimum_experience_years", "REAL");
    await ensureColumn("client_service_requests", "healthcare_setting_required", "TEXT");
    await ensureColumn("client_service_requests", "driving_licence_required", "INTEGER DEFAULT 0");
    await ensureColumn("client_service_requests", "own_vehicle_required", "INTEGER DEFAULT 0");
    await ensureColumn("client_service_requests", "english_language_level", "TEXT");
    await ensureColumn("client_service_requests", "additional_certifications", "TEXT");
    await ensureColumn("client_service_requests", "uniform_required", "INTEGER DEFAULT 0");
    await ensureColumn("client_service_requests", "parking_available", "INTEGER DEFAULT 0");
    await ensureColumn("client_service_requests", "smoking_household", "INTEGER DEFAULT 0");
    await ensureColumn("client_service_requests", "pets_on_premises", "INTEGER DEFAULT 0");
    await ensureColumn("client_service_requests", "special_instructions", "TEXT");
    await ensureColumn("client_service_requests", "language_requirement", "TEXT");
    await ensureColumn("client_service_requests", "travel_radius_km", "REAL");
    await ensureColumn("client_service_requests", "accepted_by_staff_at", "TEXT");
    await ensureColumn("client_service_requests", "approved_at", "TEXT");
    await ensureColumn("staff", "name", "TEXT");
    await ensureColumn("staff", "shift", "TEXT");
    await ensureColumn("staff", "address", "TEXT");
    await ensureColumn("staff", "emergency_contact", "TEXT");
    await ensureColumn("staff", "availability", "TEXT");
    await ensureColumn("staff", "manager_name", "TEXT");
    await ensureColumn("staff", "start_date", "TEXT");
    await ensureColumn("staff", "nationality", "TEXT");
    await ensureColumn("staff", "languages", "TEXT");
    await ensureColumn("staff", "experience_years", "TEXT");
    await ensureColumn("staff", "employee_number", "TEXT");
    await ensureColumn("staff", "preferred_name", "TEXT");
    await ensureColumn("staff", "profile_photo", "TEXT");
    await ensureColumn("staff", "date_of_birth", "TEXT");
    await ensureColumn("staff", "gender", "TEXT");
    await ensureColumn("staff", "nationality", "TEXT");
    await ensureColumn("staff", "pps_number", "TEXT");
    await ensureColumn("staff", "driving_licence_number", "TEXT");
    await ensureColumn("staff", "driving_licence_categories", "TEXT");
    await ensureColumn("staff", "own_vehicle", "INTEGER DEFAULT 0");
    await ensureColumn("staff", "right_to_work", "TEXT");
    await ensureColumn("staff", "visa_type", "TEXT");
    await ensureColumn("staff", "visa_expiry_date", "TEXT");
    await ensureColumn("staff", "passport_number", "TEXT");
    await ensureColumn("staff", "passport_expiry_date", "TEXT");
    await ensureColumn("staff", "mobile_number", "TEXT");
    await ensureColumn("staff", "alternative_phone", "TEXT");
    await ensureColumn("staff", "home_address", "TEXT");
    await ensureColumn("staff", "eircode", "TEXT");
    await ensureColumn("staff", "county", "TEXT");
    await ensureColumn("staff", "emergency_contact_name", "TEXT");
    await ensureColumn("staff", "emergency_contact_relationship", "TEXT");
    await ensureColumn("staff", "emergency_contact_phone", "TEXT");
    await ensureColumn("staff", "emergency_contact_email", "TEXT");
    await ensureColumn("staff", "employment_type", "TEXT");
    await ensureColumn("staff", "service_types", "TEXT");
    await ensureColumn("staff", "employment_status", "TEXT");
    await ensureColumn("staff", "end_date", "TEXT");
    await ensureColumn("staff", "hourly_rate", "TEXT");
    await ensureColumn("staff", "payroll_number", "TEXT");
    await ensureColumn("staff", "branch", "TEXT");
    await ensureColumn("staff", "qqi_qualifications", "TEXT");
    await ensureColumn("staff", "professional_registration", "TEXT");
    await ensureColumn("staff", "other_qualifications", "TEXT");
    await ensureColumn("staff", "skills_specialities", "TEXT");
    await ensureColumn("staff", "mandatory_training", "TEXT");
    await ensureColumn("staff", "additional_certifications", "TEXT");
    await ensureColumn("staff", "languages", "TEXT");
    await ensureColumn("staff", "availability_days", "TEXT");
    await ensureColumn("staff", "shift_preferences", "TEXT");
    await ensureColumn("staff", "weekend_availability", "INTEGER DEFAULT 0");
    await ensureColumn("staff", "bank_holidays", "INTEGER DEFAULT 0");
    await ensureColumn("staff", "max_weekly_hours", "TEXT");
    await ensureColumn("staff", "preferred_working_area", "TEXT");
    await ensureColumn("staff", "internal_notes", "TEXT");
    await ensureColumn("staff", "staff_notes", "TEXT");
    await ensureColumn("staff", "compliance_summary", "TEXT");
    await ensureColumn("staff", "application_id", "INTEGER");
    await ensureColumn("staff", "induction_checklist", "TEXT");
    await ensureColumn("staff", "portal_login_enabled", "INTEGER DEFAULT 1");
    await ensureColumn("staff", "portal_login_suspended", "INTEGER DEFAULT 0");
    await ensureColumn("staff", "portal_login_deactivated", "INTEGER DEFAULT 0");
    await ensureColumn("staff", "welcome_email_sent", "INTEGER DEFAULT 0");
    await ensureColumn("staff", "training_records", "TEXT");
    await ensureColumn("staff", "certification_records", "TEXT");
    await ensureColumn("staff", "nmbi_number", "TEXT");
    await ensureColumn("staff", "nmbi_expiry_date", "TEXT");
    await ensureColumn("staff", "garda_vetting_status", "TEXT");
    await ensureColumn("staff", "garda_vetting_expiry_date", "TEXT");
    await ensureColumn("staff", "force_password_reset", "INTEGER DEFAULT 0");
    await ensureColumn("staff", "is_archived", "INTEGER DEFAULT 0");

    await runDb(`
        UPDATE staff
        SET status = 'Active'
        WHERE lower(trim(COALESCE(status, ''))) IN ('available', 'on duty')
    `);
    await runDb(`
        UPDATE staff
        SET employment_status = 'Active'
        WHERE (employment_status IS NULL OR trim(employment_status) = '')
          AND lower(trim(COALESCE(status, ''))) = 'active'
    `);
    await runDb(`
        UPDATE staff
        SET service_types = '["Both"]'
        WHERE service_types IS NULL OR trim(service_types) = ''
    `);
    await runDb(`
        UPDATE client_accounts
        SET facility_id = 'FAC-' || printf('%05d', id)
        WHERE facility_id IS NULL OR trim(facility_id) = ''
    `);
    await runDb(`
        UPDATE staff_shifts
        SET service_division = CASE
            WHEN COALESCE(client_account_id, 0) > 0 OR lower(COALESCE(request_source, '')) = 'client_portal' THEN 'agency-staffing'
            ELSE 'home-care'
        END
        WHERE service_division IS NULL OR trim(service_division) = ''
    `);
    await runDb(`
        UPDATE staff_shifts
        SET shift_code = CASE
            WHEN service_division = 'agency-staffing' THEN 'AGS-' || printf('%06d', id)
            ELSE 'HCV-' || printf('%06d', id)
        END
        WHERE shift_code IS NULL OR trim(shift_code) = ''
    `);

    await ensureColumn("patients", "first_name", "TEXT");
    await ensureColumn("patients", "last_name", "TEXT");
    await ensureColumn("patients", "date_of_birth", "TEXT");
    await ensureColumn("patients", "gender", "TEXT");
    await ensureColumn("patients", "address", "TEXT");
    await ensureColumn("patients", "phone", "TEXT");
    await ensureColumn("patients", "email", "TEXT");
    await ensureColumn("patients", "emergency_contact", "TEXT");
    await ensureColumn("patients", "care_level", "TEXT");
    await ensureColumn("patients", "status", "TEXT DEFAULT 'Active'");
    await ensureColumn("patients", "risk_level", "TEXT DEFAULT 'Low'");
    await ensureColumn("patients", "name", "TEXT");
    await ensureColumn("patients", "age", "INTEGER");
    await ensureColumn("patients", "condition", "TEXT");
    await ensureColumn("patients", "carePlan", "TEXT");
    await ensureColumn("patients", "nextVisit", "TEXT");
    await ensureColumn("patients", "latitude", "REAL");
    await ensureColumn("patients", "longitude", "REAL");
    await ensureColumn("patients", "geofence_radius_meters", "INTEGER DEFAULT 80");
    await ensureColumn("patients", "home_care_client_id", "TEXT");
    await runDb(`
        UPDATE patients
        SET home_care_client_id = 'HC-' || printf('%05d', id)
        WHERE home_care_client_id IS NULL OR trim(home_care_client_id) = ''
    `);
    await ensureColumn("patients", "created_at", "TEXT");
    await ensureColumn("patients", "legal_basis", "TEXT DEFAULT 'care_contract'");
    await ensureColumn("patients", "consent_status", "TEXT DEFAULT 'pending'");
    await ensureColumn("patients", "consent_recorded_at", "TEXT");
    await ensureColumn("patients", "consent_recorded_by", "TEXT");
    await ensureColumn("patients", "data_retention_until", "TEXT");
    await ensureColumn("patients", "is_archived", "INTEGER DEFAULT 0");
    await ensureColumn("patients", "archived_at", "TEXT");
    await ensureColumn("staff", "first_name", "TEXT");
    await ensureColumn("staff", "last_name", "TEXT");
    await ensureColumn("staff", "email", "TEXT");
    await ensureColumn("staff", "name", "TEXT");
    await ensureColumn("staff", "shift", "TEXT");
    await ensureColumn("staff", "password_hash", "TEXT");
    await ensureColumn("staff", "address", "TEXT");
    await ensureColumn("staff", "emergency_contact", "TEXT");
    await ensureColumn("staff", "availability", "TEXT");
    await ensureColumn("staff", "profile_photo", "TEXT");
    await ensureColumn("staff", "manager_name", "TEXT");
    await ensureColumn("staff", "start_date", "TEXT");
    await ensureColumn("staff", "nationality", "TEXT");
    await ensureColumn("staff", "languages", "TEXT");
    await ensureColumn("staff", "experience_years", "TEXT");
    await ensureColumn("staff", "app_lock_enabled", "INTEGER DEFAULT 0");
    await ensureColumn("staff", "app_lock_method", "TEXT");
    await ensureColumn("staff", "reminder_lead_minutes", "INTEGER DEFAULT 60");
    await ensureColumn("staff", "notify_shift_reminders", "INTEGER DEFAULT 1");
    await ensureColumn("staff", "notify_new_shift", "INTEGER DEFAULT 1");
    await ensureColumn("staff", "notify_open_shift", "INTEGER DEFAULT 1");
    await ensureColumn("staff", "notify_announcements", "INTEGER DEFAULT 1");
    await ensureColumn("staff", "notify_training_reminders", "INTEGER DEFAULT 1");
    await ensureColumn("staff", "notify_compliance_alerts", "INTEGER DEFAULT 1");
    await ensureColumn("staff", "notify_schedule_changes", "INTEGER DEFAULT 1");
    await ensureColumn("care_notes", "retention_expires_at", "TEXT");
    await ensureColumn("appointments", "patient_id", "INTEGER");
    await ensureColumn("appointments", "staff_id", "INTEGER");
    await ensureColumn("appointments", "client", "TEXT");
    await ensureColumn("appointments", "date", "TEXT");
    await ensureColumn("appointments", "time", "TEXT");
    await ensureColumn("appointments", "type", "TEXT");
    await ensureColumn("staff_shifts", "notes", "TEXT");
    await ensureColumn("staff_shifts", "service_type", "TEXT");
    await ensureColumn("staff_shifts", "is_open", "INTEGER DEFAULT 0");
    await ensureColumn("staff_shifts", "clock_in_accuracy", "REAL");
    await ensureColumn("staff_shifts", "clock_out_accuracy", "REAL");
    await ensureColumn("staff_shifts", "clock_in_device", "TEXT");
    await ensureColumn("staff_shifts", "clock_out_device", "TEXT");
    await ensureColumn("staff_shifts", "care_instructions", "TEXT");
    await ensureColumn("patients", "eircode", "TEXT");
    await ensureColumn("patients", "photo_url", "TEXT");
    await ensureColumn("patients", "emergency_contact_name", "TEXT");
    await ensureColumn("patients", "emergency_contact_relationship", "TEXT");
    await ensureColumn("patients", "emergency_contact_phone", "TEXT");
    await ensureColumn("patients", "preferred_name", "TEXT");
    await ensureColumn("patients", "marital_status", "TEXT");
    await ensureColumn("patients", "nationality", "TEXT");
    await ensureColumn("patients", "pps_number", "TEXT");
    await ensureColumn("patients", "primary_language", "TEXT");
    await ensureColumn("patients", "interpreter_required", "INTEGER DEFAULT 0");
    await ensureColumn("patients", "alternative_phone", "TEXT");
    await ensureColumn("patients", "county", "TEXT");
    await ensureColumn("patients", "care_needs_personal_care", "TEXT");
    await ensureColumn("patients", "care_needs_mobility", "TEXT");
    await ensureColumn("patients", "care_needs_clinical_tasks", "TEXT");
    await ensureColumn("patients", "care_needs_medical_conditions", "TEXT");
    await ensureColumn("patients", "care_needs_daily_living", "TEXT");
    await ensureColumn("patients", "care_needs_risks", "TEXT");
    await ensureColumn("patients", "care_needs_communication", "TEXT");
    await ensureColumn("patients", "care_needs_lifestyle", "TEXT");
    await ensureColumn("patients", "care_needs_equipment", "TEXT");
    await ensureColumn("patients", "care_needs_service_types", "TEXT");
    await ensureColumn("patients", "diagnoses", "TEXT");
    await ensureColumn("patients", "allergies", "TEXT");
    await ensureColumn("patients", "current_medication", "TEXT");
    await ensureColumn("patients", "medication_schedule", "TEXT");
    await ensureColumn("patients", "gp_name", "TEXT");
    await ensureColumn("patients", "gp_phone", "TEXT");
    await ensureColumn("patients", "consultant_name", "TEXT");
    await ensureColumn("patients", "hospital_name", "TEXT");
    await ensureColumn("patients", "pharmacy_name", "TEXT");
    await ensureColumn("patients", "vaccination_status", "TEXT");
    await ensureColumn("patients", "dnar_status", "TEXT");
    await ensureColumn("patients", "falls_risk_level", "TEXT");
    await ensureColumn("patients", "infection_risks", "TEXT");
    await ensureColumn("patients", "emergency_contact_alt_phone", "TEXT");
    await ensureColumn("patients", "emergency_contact_email", "TEXT");
    await ensureColumn("patients", "emergency_contact_address", "TEXT");
    await ensureColumn("patients", "key_safe_code", "TEXT");
    await ensureColumn("patients", "door_code", "TEXT");
    await ensureColumn("patients", "alarm_code", "TEXT");
    await ensureColumn("patients", "parking_instructions", "TEXT");
    await ensureColumn("patients", "pets", "TEXT");
    await ensureColumn("patients", "lift_available", "INTEGER DEFAULT 0");
    await ensureColumn("patients", "stairs", "TEXT");
    await ensureColumn("patients", "access_notes", "TEXT");
    await ensureColumn("patients", "care_plan_daily_routine", "TEXT");
    await ensureColumn("patients", "care_plan_preferences", "TEXT");
    await ensureColumn("patients", "care_plan_likes", "TEXT");
    await ensureColumn("patients", "care_plan_dislikes", "TEXT");
    await ensureColumn("patients", "care_plan_communication", "TEXT");
    await ensureColumn("patients", "care_plan_diet", "TEXT");
    await ensureColumn("patients", "care_plan_fluids", "TEXT");
    await ensureColumn("patients", "care_plan_behaviour_support", "TEXT");
    await ensureColumn("patients", "care_plan_risk_information", "TEXT");
    await ensureColumn("patients", "care_plan_goals", "TEXT");
    await ensureColumn("patients", "shift_instructions", "TEXT");
    await ensureColumn("patients", "preferred_days", "TEXT");
    await ensureColumn("patients", "preferred_times", "TEXT");
    await ensureColumn("patients", "visit_duration", "TEXT");
    await ensureColumn("patients", "custom_visit_duration", "TEXT");
    await ensureColumn("patients", "visit_frequency", "TEXT");
    await ensureColumn("patients", "custom_visit_frequency", "TEXT");
    await ensureColumn("patients", "preferred_staff_gender", "TEXT");
    await ensureColumn("patients", "internal_notes", "TEXT");
    await ensureColumn("patients", "updated_at", "TEXT");

    await runDb("INSERT OR IGNORE INTO app_status (id, status) VALUES (1, 'healthy')");
    await savePayrollSettings(await getPayrollSettings());
    await runDb(
        `UPDATE patients
         SET data_retention_until = date('now', '+${defaultPatientRetentionDays} days')
         WHERE data_retention_until IS NULL OR data_retention_until = ''`
    );
    await runDb(
        `UPDATE care_notes
         SET retention_expires_at = datetime(created_at, '+${defaultPatientRetentionDays} days')
         WHERE retention_expires_at IS NULL OR retention_expires_at = ''`
    );

    const patientCount = await getDb("SELECT COUNT(*) AS count FROM patients");
    if (!patientCount || Number(patientCount.count) === 0) {
        await runDb(`
            INSERT INTO patients (first_name, last_name, age, condition, carePlan, nextVisit, latitude, longitude, geofence_radius_meters, status, risk_level, phone, email, emergency_contact, care_level)
            VALUES
                ('Ava', 'Thompson', 78, 'Mobility support', 'Twice-daily mobility checks and medication reminders.', '2026-08-03 09:30', 53.3498, -6.2603, 80, 'Active', 'Moderate', '085 222 4411', 'ava@everkind.com', 'Call daughter Leah', 'High'),
                ('Daniel', 'Brooks', 64, 'Post-surgery recovery', 'Monitoring wound care and hydration throughout the week.', '2026-08-03 12:15', 53.3472, -6.2577, 80, 'Active', 'High', '085 222 4422', 'daniel@everkind.com', 'Call son Owen', 'Moderate'),
                ('Ella', 'Price', 81, 'Dementia support', 'Routine companionship and meal preparation with activity prompts.', '2026-08-03 14:00', 53.3485, -6.2621, 70, 'Active', 'Moderate', '085 222 4433', 'ella@everkind.com', 'Call niece Emma', 'High');
        `);
    }
    await runDb(`
        UPDATE patients
        SET home_care_client_id = 'HC-' || printf('%05d', id)
        WHERE home_care_client_id IS NULL OR trim(home_care_client_id) = ''
    `);

    const staffCount = await getDb("SELECT COUNT(*) AS count FROM staff");
    if (!staffCount || Number(staffCount.count) === 0) {
        const staffPasswordHash = await bcrypt.hash(staffDefaultPassword, 10);
        await runDb(`
            INSERT INTO staff (first_name, last_name, role, email, phone, status, password_hash, shift, name)
            VALUES
                ('Maya', 'Sinclair', 'Senior Care Worker', ?, '07700 900111', 'Active', ?, 'Morning', 'Maya Sinclair'),
                ('Chris', 'O''Malley', 'Support Worker', 'chris@everkind.com', '07700 900112', 'Active', ?, 'Afternoon', 'Chris O''Malley'),
                ('Iris', 'Kaur', 'Care Coordinator', 'iris@everkind.com', '07700 900113', 'Active', ?, 'Evening', 'Iris Kaur');
        `, [staffDefaultEmail, staffPasswordHash, staffPasswordHash, staffPasswordHash]);
    }

    const staffColumns = await allDb("PRAGMA table_info(staff)");
    const staffHash = await bcrypt.hash(staffDefaultPassword, 10);
    const defaultStaff = await getDb(
        "SELECT * FROM staff WHERE email = ? OR name = ? OR first_name = ? OR last_name = ? ORDER BY id LIMIT 1",
        [staffDefaultEmail, "Maya Sinclair", "Maya", "Sinclair"]
    );

    if (defaultStaff) {
        const passwordMatches = Boolean(defaultStaff.password_hash) && (await bcrypt.compare(staffDefaultPassword, defaultStaff.password_hash));
        const needsStaffRepair = !defaultStaff.email || !defaultStaff.first_name || !defaultStaff.last_name || !defaultStaff.password_hash || !passwordMatches;

        if (needsStaffRepair) {
            await runDb(
                "UPDATE staff SET email = ?, first_name = ?, last_name = ?, password_hash = ?, name = ?, status = 'Active', employment_status = COALESCE(NULLIF(employment_status, ''), 'Active') WHERE id = ?",
                [staffDefaultEmail, "Maya", "Sinclair", staffHash, "Maya Sinclair", defaultStaff.id]
            );
        }
    } else {
        const staffTable = await allDb("SELECT * FROM staff ORDER BY id LIMIT 1");
        if (staffTable.length > 0) {
            await runDb(
                "UPDATE staff SET email = ?, first_name = ?, last_name = ?, password_hash = ?, name = ?, status = 'Active', employment_status = COALESCE(NULLIF(employment_status, ''), 'Active') WHERE id = ?",
                [staffDefaultEmail, "Maya", "Sinclair", staffHash, "Maya Sinclair", staffTable[0].id]
            );
        } else {
            await runDb(
                "INSERT INTO staff (name, first_name, last_name, role, email, phone, status, password_hash, shift) VALUES (?, ?, ?, ?, ?, ?, 'Active', ?, 'Morning')",
                ["Maya Sinclair", "Maya", "Sinclair", "Senior Care Worker", staffDefaultEmail, "07700 900111", staffHash]
            );
        }
    }

    await ensureAdminAndRbacData();

    const shiftCount = await getDb("SELECT COUNT(*) AS count FROM staff_shifts");
    if (!shiftCount || Number(shiftCount.count) === 0) {
        const staffList = await allDb("SELECT * FROM staff ORDER BY id LIMIT 3");
        const patientList = await allDb("SELECT * FROM patients ORDER BY id LIMIT 3");
        const today = new Date().toISOString().slice(0, 10);

        for (let index = 0; index < staffList.length && index < patientList.length; index += 1) {
            const staffMember = staffList[index];
            const patient = patientList[index];
            const startHour = String(8 + index * 4).padStart(2, "0");
            const endHour = String(12 + index * 4).padStart(2, "0");
            const assignedHourlyRate = await getValidStaffHourlyRate(staffMember.id);

            const createdShift = await runDb(
                `INSERT INTO staff_shifts (staff_id, patient_id, shift_date, scheduled_start, scheduled_end, status)
                 VALUES (?, ?, ?, ?, ?, 'scheduled')`,
                [staffMember.id, patient.id, today, `${today}T${startHour}:00:00`, `${today}T${endHour}:00:00`]
            );
            await runDb(
                "UPDATE staff_shifts SET service_division = 'home-care', shift_code = ? WHERE id = ?",
                [buildShiftCode("home-care", createdShift.lastID), Number(createdShift.lastID)]
            );
            await snapshotShiftPayRate(createdShift.lastID, staffMember.id, assignedHourlyRate);
        }
    }

    const noteCount = await getDb("SELECT COUNT(*) AS count FROM care_notes");
    if (!noteCount || Number(noteCount.count) === 0) {
        const patient = await getDb("SELECT * FROM patients ORDER BY id LIMIT 1");
        if (patient) {
            await runDb(
                `INSERT INTO care_notes (patient_id, author, note, severity, created_at)
                 VALUES (?, 'Nurse Lewis', 'Patient reported improved mobility following the morning routine.', 'Normal', datetime('now'))`,
                [patient.id]
            );
        }
    }

    const appointmentCount = await getDb("SELECT COUNT(*) AS count FROM appointments");
    if (!appointmentCount || Number(appointmentCount.count) === 0) {
        const patientList = await allDb("SELECT * FROM patients ORDER BY id LIMIT 3");
        const today = new Date().toISOString().slice(0, 10);

        for (let index = 0; index < patientList.length; index += 1) {
            const patient = patientList[index];
            const startHour = 9 + index * 2;
            const time = `${String(startHour).padStart(2, "0")}:30`;
            const endHour = String(startHour + 1).padStart(2, "0");
            await runDb(
                `INSERT INTO appointments (patient_id, staff_id, title, start, end, notes, status, client, date, time, type)
                 VALUES (?, ?, ?, ?, ?, ?, 'Scheduled', ?, ?, ?, ?)`,
                [patient.id, index + 1, "Home visit", `${today}T${time}:00`, `${today}T${endHour}:30:00`, "Prepare meals and check mobility.", `${patient.first_name} ${patient.last_name}`, today, time, "Care visit"]
            );
        }
    }

    const notificationCount = await getDb("SELECT COUNT(*) AS count FROM staff_notifications");
    if (!notificationCount || Number(notificationCount.count) === 0) {
        await runDb(`
            INSERT INTO staff_notifications (staff_id, title, body, type, link_url)
            SELECT id, 'Welcome to Everkind', 'Your staff portal is ready. Review your profile and upcoming shifts.', 'info', '/portal/home'
            FROM staff
        `);
    }

    const messageCount = await getDb("SELECT COUNT(*) AS count FROM staff_messages");
    if (!messageCount || Number(messageCount.count) === 0) {
        await runDb(`
            INSERT INTO staff_messages (staff_id, sender_type, sender_name, subject, body)
            SELECT id, 'admin', 'Care Coordination', 'Welcome', 'Welcome to Everkind. Please review your rota and keep your profile details up to date.'
            FROM staff
        `);
    }

    const documentCount = await getDb("SELECT COUNT(*) AS count FROM staff_documents");
    if (!documentCount || Number(documentCount.count) === 0) {
        await runDb(`
            INSERT INTO staff_documents (staff_id, title, category, file_name, download_text)
            VALUES
                (NULL, 'Employment Contract', 'Contract', 'employment-contract.txt', 'Everkind Employment Contract - placeholder download generated by the staff portal.'),
                (NULL, 'Staff Handbook', 'Handbook', 'staff-handbook.txt', 'Everkind Staff Handbook - placeholder download generated by the staff portal.'),
                (NULL, 'Policies Pack', 'Policies', 'policies-pack.txt', 'Everkind Policies Pack - placeholder download generated by the staff portal.')
        `);
    }

    const trainingCount = await getDb("SELECT COUNT(*) AS count FROM staff_training");
    if (!trainingCount || Number(trainingCount.count) === 0) {
        await runDb(`
            INSERT INTO staff_training (staff_id, title, status, completed_at, expires_at)
            SELECT id, 'Manual Handling', 'completed', datetime('now', '-120 days'), date('now', '+245 days') FROM staff
        `);
        await runDb(`
            INSERT INTO staff_training (staff_id, title, status, completed_at, expires_at)
            SELECT id, 'Safeguarding Adults', 'upcoming', NULL, date('now', '+30 days') FROM staff
        `);
        await runDb(`
            INSERT INTO staff_training (staff_id, title, status, completed_at, expires_at)
            SELECT id, 'Infection Prevention', 'expired', datetime('now', '-450 days'), date('now', '-20 days') FROM staff
        `);
    }
};

app.get("/", async (req, res) => {
    const trustStats = [];

    try {
        const [activeStaffRow, gardaClearedRow, completedTrainingRow, pendingRequestRow, hiqaRow, staffExperienceRows] = await Promise.all([
            getDb("SELECT COUNT(*) AS count FROM staff WHERE COALESCE(is_archived, 0) = 0"),
            getDb(`
                SELECT COUNT(*) AS count
                FROM staff
                WHERE COALESCE(is_archived, 0) = 0
                  AND LOWER(COALESCE(garda_vetting_status, '')) IN ('approved', 'valid', 'complete', 'completed', 'active', 'clear')
            `),
            getDb("SELECT COUNT(*) AS count FROM staff_training WHERE LOWER(COALESCE(status, '')) = 'completed'"),
            getDb("SELECT COUNT(*) AS count FROM client_service_requests WHERE status IN ('pending_review', 'reviewing', 'request_more_information', 'urgent', 'emergency')"),
            getDb("SELECT COUNT(*) AS total, SUM(CASE WHEN COALESCE(hiqa_compliance_agreement, 0) = 1 THEN 1 ELSE 0 END) AS compliant FROM client_accounts"),
            allDb("SELECT experience_years FROM staff WHERE COALESCE(is_archived, 0) = 0"),
        ]);

        const activeStaffCount = Number(activeStaffRow ? activeStaffRow.count : 0);
        const gardaClearedCount = Number(gardaClearedRow ? gardaClearedRow.count : 0);
        const completedTrainingCount = Number(completedTrainingRow ? completedTrainingRow.count : 0);
        const pendingRequestCount = Number(pendingRequestRow ? pendingRequestRow.count : 0);
        const hiqaTotal = Number(hiqaRow ? hiqaRow.total : 0);
        const hiqaCompliant = Number(hiqaRow ? hiqaRow.compliant : 0);
        const hiqaPercent = hiqaTotal > 0 ? Math.round((hiqaCompliant / hiqaTotal) * 100) : 0;

        const combinedExperienceYears = (Array.isArray(staffExperienceRows) ? staffExperienceRows : [])
            .map((row) => Number.parseFloat(String(row.experience_years || "").replace(/[^\d.]/g, "")))
            .filter((value) => Number.isFinite(value) && value > 0)
            .reduce((sum, value) => sum + value, 0);

        if (combinedExperienceYears > 0) {
            trustStats.push({
                value: `${Math.round(combinedExperienceYears)}+`,
                label: "Years Combined Experience",
                icon: "heart",
            });
        }

        if (hiqaTotal > 0) {
            trustStats.push({
                value: `${hiqaPercent}%`,
                label: "HIQA Compliant Accounts",
                icon: "shield",
            });
        }

        if (gardaClearedCount > 0) {
            trustStats.push({
                value: `${gardaClearedCount}`,
                label: "Garda Vetted Staff",
                icon: "team",
            });
        }

        if (completedTrainingCount > 0) {
            trustStats.push({
                value: `${completedTrainingCount}`,
                label: "Completed Mandatory Training Records",
                icon: "cap",
            });
        }

        if (trustStats.length < 4 && activeStaffCount > 0) {
            trustStats.push({
                value: `${activeStaffCount}+`,
                label: "Active Care Professionals",
                icon: "check",
            });
        }

        if (trustStats.length < 4 && pendingRequestCount > 0) {
            trustStats.push({
                value: `${pendingRequestCount}`,
                label: "Open Care & Staffing Requests",
                icon: "clock",
            });
        }
    } catch (error) {
        console.error("Error loading home trust metrics:", error.message);
    }

    return res.render("home", {
        title: "Everkind Home Care | Healthcare Staffing Across Ireland",
        isLoggedIn: Boolean(req.session.isStaff || req.session.isAdmin),
        trustStats: trustStats.slice(0, 4),
    });
});

app.get("/about", (req, res) => {
    res.render("about", {
        title: "About Everkind",
        isLoggedIn: Boolean(req.session.isStaff || req.session.isAdmin),
    });
});

app.get("/services", (req, res) => {
    res.render("services", {
        title: "Healthcare Staffing & Home Support",
        isLoggedIn: Boolean(req.session.isStaff || req.session.isAdmin),
    });
});

app.get("/careers", (req, res) => {
    res.render("careers", {
        title: "Careers at Everkind | Live Healthcare Jobs",
        isLoggedIn: Boolean(req.session.isStaff || req.session.isAdmin),
    });
});

app.get("/testimonials", (req, res) => {
    res.render("testimonials", {
        title: "Testimonials | Everkind Healthcare Staffing",
        isLoggedIn: Boolean(req.session.isStaff || req.session.isAdmin),
    });
});

app.get("/faq", (req, res) => {
    res.render("faq", {
        title: "Frequently Asked Questions",
        isLoggedIn: Boolean(req.session.isStaff || req.session.isAdmin),
    });
});

app.get("/contact", (req, res) => {
    res.render("contact", {
        title: "Contact Everkind",
        isLoggedIn: Boolean(req.session.isStaff || req.session.isAdmin),
    });
});

app.get("/assessment", (req, res) => {
    res.render("assessment", {
        title: "Request a Care Assessment",
        isLoggedIn: Boolean(req.session.isStaff || req.session.isAdmin),
    });
});

app.get("/apply", (req, res) => {
    const submitted = req.query.submitted === "1";
    res.render("apply", {
        title: "Apply to Everkind",
        isLoggedIn: Boolean(req.session.isStaff || req.session.isAdmin),
        submitted,
        formData: {
            first_name: "",
            surname: "",
            email: "",
            phone: "",
            role: "Home Care Assistant",
            availability_options: [],
        },
        applicationAvailabilityGroups,
        allApplicationAvailabilityOptions: applicationAvailabilityOptions,
    });
});

app.post("/apply", async (req, res) => {
    const formData = req.body || {};
    const { firstName, surname, fullName } = buildApplicationNameParts(formData);
    const email = normalizeEmailAddress(formData.email);
    const phone = String(formData.phone || "").trim();
    const role = String(formData.role || "").trim();
    const availabilitySelections = normalizeApplicationAvailabilitySelections(formData.availability_options);

    if (!firstName || !surname) {
        return res.render("apply", {
            title: "Apply to Everkind",
            isLoggedIn: false,
            submitted: false,
            error: "Please provide both first name and surname.",
            formData: {
                first_name: firstName,
                surname,
                email,
                phone,
                role,
                availability_options: availabilitySelections,
            },
            applicationAvailabilityGroups,
            allApplicationAvailabilityOptions: applicationAvailabilityOptions,
        });
    }
    if (!email || !isValidEmailAddress(email)) {
        return res.render("apply", {
            title: "Apply to Everkind",
            isLoggedIn: false,
            submitted: false,
            error: "Please enter a valid email address (for example, name@example.com).",
            formData: {
                first_name: firstName,
                surname,
                email,
                phone,
                role,
                availability_options: availabilitySelections,
            },
            applicationAvailabilityGroups,
            allApplicationAvailabilityOptions: applicationAvailabilityOptions,
        });
    }
    try {
        const { normalizedPhone } = await enforceApplicationUniqueness({ email, phone });
        await runDb(
            `INSERT INTO applications
             (name, first_name, surname, email, email_normalized, phone, phone_normalized, role, availability, status)
             VALUES (?,?,?,?,?,?,?,?,?,'new')`,
            [
                fullName,
                firstName,
                surname,
                email,
                email,
                phone || "",
                normalizedPhone || "",
                role || "",
                serializeJsonField(availabilitySelections),
            ]
        );
        res.redirect("/apply?submitted=1");
    } catch (error) {
        await recordDuplicateIdentityAttempt(req, error, "application");
        const safeMessage = error.code === "APPLICATION_DUPLICATE_EMAIL" || error.code === "APPLICATION_DUPLICATE_PHONE"
            ? error.message
            : "We could not submit your application right now. Please try again.";
        console.error("Error saving application:", error.message);
        res.status(400).render("apply", {
            title: "Apply to Everkind",
            isLoggedIn: false,
            submitted: false,
            error: safeMessage,
            formData: {
                first_name: firstName,
                surname,
                email,
                phone,
                role,
                availability_options: availabilitySelections,
            },
            applicationAvailabilityGroups,
            allApplicationAvailabilityOptions: applicationAvailabilityOptions,
        });
    }
});

app.get("/admin", (req, res) => {
    res.render("admin", {
        title: "Everkind Admin",
        isLoggedIn: Boolean(req.session.isAdmin),
        message: req.query.message || "",
        isAdmin: Boolean(req.session.isAdmin),
    });
});

app.get("/portal", (req, res) => {
    return res.redirect("/portal/login");
});

app.get("/portal/login", (req, res) => {
    if (req.session.isAdmin) {
        return res.redirect("/portal/dashboard");
    }

    if (req.session.isStaff) {
        return res.redirect("/portal/home");
    }

    return res.render("portal-login", { title: "Staff Portal Login", error: req.query.error || "", isLoggedIn: false });
});

app.get("/portal/forgot-password", (req, res) => {
    res.render("portal-forgot-password", {
        title: "Forgot Password",
        error: req.query.error || "",
        message: req.query.message || "",
        previewCode: req.query.previewCode || "",
        isLoggedIn: false,
    });
});

app.post("/portal/forgot-password", async (req, res) => {
    const email = String(req.body.email || "").trim().toLowerCase();
    if (!email) {
        return res.status(400).render("portal-forgot-password", {
            title: "Forgot Password",
            error: "Please enter your registered email address.",
            message: "",
            previewCode: "",
            isLoggedIn: false,
        });
    }

    try {
        const staffMember = await getDb("SELECT * FROM staff WHERE lower(email) = ?", [email]);
        if (!staffMember || isStaffLoginBlocked(staffMember)) {
            return res.status(404).render("portal-forgot-password", {
                title: "Forgot Password",
                error: "No active staff account was found for that email address.",
                message: "",
                previewCode: "",
                isLoggedIn: false,
            });
        }

        const code = createResetCode();
        const codeHash = await bcrypt.hash(code, 10);
        await runDb("DELETE FROM staff_password_resets WHERE staff_id = ? AND used_at IS NULL", [staffMember.id]);
        await runDb(
            `INSERT INTO staff_password_resets (staff_id, code_hash, expires_at)
             VALUES (?, ?, datetime('now', '+15 minutes'))`,
            [staffMember.id, codeHash]
        );

        await queueStaffNotification(
            staffMember.id,
            "Password reset requested",
            "A password reset code was generated for your staff portal account.",
            "security",
            "/portal/reset-password"
        );

        return res.render("portal-forgot-password", {
            title: "Forgot Password",
            error: "",
            message: "A reset code has been generated for your account. Enter it on the reset page.",
            previewCode: isProduction ? "" : code,
            isLoggedIn: false,
        });
    } catch (error) {
        console.error("Error creating password reset:", error.message);
        return res.status(500).render("portal-forgot-password", {
            title: "Forgot Password",
            error: "The reset request could not be completed.",
            message: "",
            previewCode: "",
            isLoggedIn: false,
        });
    }
});

app.get("/portal/reset-password", (req, res) => {
    res.render("portal-reset-password", {
        title: "Reset Password",
        error: req.query.error || "",
        message: req.query.message || "",
        isLoggedIn: false,
    });
});

app.post("/portal/reset-password", async (req, res) => {
    const email = String(req.body.email || "").trim().toLowerCase();
    const code = String(req.body.code || "").trim();
    const password = String(req.body.password || "");

    const securityPolicy = await getSecurityPolicy();
    if (!email || !code || password.length < securityPolicy.passwordMinimumLength) {
        return res.status(400).render("portal-reset-password", {
            title: "Reset Password",
            error: `Email, reset code, and a new password of at least ${securityPolicy.passwordMinimumLength} characters are required.`,
            message: "",
            isLoggedIn: false,
        });
    }

    try {
        const staffMember = await getDb("SELECT * FROM staff WHERE lower(email) = ?", [email]);
        if (!staffMember) {
            return res.status(404).render("portal-reset-password", {
                title: "Reset Password",
                error: "No staff account was found for that email address.",
                message: "",
                isLoggedIn: false,
            });
        }

        const resetRow = await getDb(
            `SELECT * FROM staff_password_resets
             WHERE staff_id = ? AND used_at IS NULL AND datetime(expires_at) > datetime('now')
             ORDER BY created_at DESC LIMIT 1`,
            [staffMember.id]
        );

        if (!resetRow || !(await bcrypt.compare(code, resetRow.code_hash))) {
            return res.status(400).render("portal-reset-password", {
                title: "Reset Password",
                error: "The reset code is invalid or has expired.",
                message: "",
                isLoggedIn: false,
            });
        }

        await assertPasswordNotReused({
            accountType: "staff",
            accountId: staffMember.id,
            password,
            currentPasswordHash: staffMember.password_hash,
        });
        const passwordHash = await hashPassword(password);
        await recordPasswordHistory("staff", staffMember.id, staffMember.password_hash);
        await runDb("UPDATE staff SET password_hash = ? WHERE id = ?", [passwordHash, staffMember.id]);
        await recordPasswordHistory("staff", staffMember.id, passwordHash);
        await runDb("UPDATE staff_password_resets SET used_at = datetime('now') WHERE id = ?", [resetRow.id]);

        return res.render("portal-reset-password", {
            title: "Reset Password",
            error: "",
            message: "Your password has been reset. You can now sign in.",
            isLoggedIn: false,
        });
    } catch (error) {
        if (error.code === "PASSWORD_REUSED") {
            return res.status(400).render("portal-reset-password", {
                title: "Reset Password",
                error: error.message,
                message: "",
                isLoggedIn: false,
            });
        }
        console.error("Error resetting password:", error.message);
        return res.status(500).render("portal-reset-password", {
            title: "Reset Password",
            error: "The password reset could not be completed.",
            message: "",
            isLoggedIn: false,
        });
    }
});

app.get("/client-portal", (req, res) => {
    if (req.session.isClient) {
        return res.redirect("/client-portal/dashboard");
    }
    return res.redirect("/client-portal/login");
});

app.get("/client-portal/login", (req, res) => {
    if (req.session.isClient) {
        return res.redirect("/client-portal/dashboard");
    }
    return res.render("client-portal-login", {
        title: "Facility Portal Login",
        error: req.query.error || "",
        isLoggedIn: false,
    });
});

app.get("/facility-portal", (req, res) => {
    if (req.session.isClient) {
        return res.redirect("/facility-portal/dashboard");
    }
    return res.redirect("/facility-portal/login");
});
app.get("/facility-portal/login", (req, res) => res.redirect(`/client-portal/login${req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : ""}`));
app.get("/facility-portal/register", (req, res) => res.redirect(`/client-portal/register${req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : ""}`));
app.get("/facility-portal/forgot-password", (req, res) => res.redirect(`/client-portal/forgot-password${req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : ""}`));
app.get("/facility-portal/reset-password", (req, res) => res.redirect(`/client-portal/reset-password${req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : ""}`));
app.get("/facility-portal/dashboard", (req, res) => res.redirect(`/client-portal/dashboard${req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : ""}`));
app.get("/facility-portal/requests", (req, res) => res.redirect(`/client-portal/requests${req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : ""}`));
app.get("/facility-portal/requests/new", (req, res) => res.redirect(`/client-portal/requests/new${req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : ""}`));
app.get("/facility-portal/logout", (req, res) => res.redirect(`/client-portal/logout${req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : ""}`));
app.post("/facility-portal/register", (req, res) => res.redirect(307, "/client-portal/register"));
app.post("/facility-portal/forgot-password", (req, res) => res.redirect(307, "/client-portal/forgot-password"));
app.post("/facility-portal/reset-password", (req, res) => res.redirect(307, "/client-portal/reset-password"));
app.post("/facility-portal/requests", (req, res) => res.redirect(307, "/client-portal/requests"));

app.get("/client-portal/register", (req, res) => {
    return res.render("client-portal-register", {
        title: "Facility Portal Registration",
        error: req.query.error || "",
        message: req.query.message || "",
        formData: null,
        isLoggedIn: false,
        clientPortalOrganizationTypes,
        clientPortalServiceRequirementOptions,
        clientPortalShiftTypeOptions,
    });
});

app.post("/client-portal/register", async (req, res) => {
    const { password, confirm_password } = req.body;
    
    // Validate password fields
    if (!password || !confirm_password) {
        return res.status(400).render("client-portal-register", {
            title: "Facility Portal Registration",
            error: "Password and password confirmation are required.",
            message: "",
            formData: req.body,
            isLoggedIn: false,
            clientPortalOrganizationTypes,
            clientPortalServiceRequirementOptions,
        });
    }
    if (password !== confirm_password) {
        return res.status(400).render("client-portal-register", {
            title: "Facility Portal Registration",
            error: "Passwords do not match.",
            message: "",
            formData: req.body,
            isLoggedIn: false,
            clientPortalOrganizationTypes,
            clientPortalServiceRequirementOptions,
        });
    }
    const securityPolicy = await getSecurityPolicy();
    if (password.length < securityPolicy.passwordMinimumLength) {
        return res.status(400).render("client-portal-register", {
            title: "Facility Portal Registration",
            error: `Password must be at least ${securityPolicy.passwordMinimumLength} characters long.`,
            message: "",
            formData: req.body,
            isLoggedIn: false,
            clientPortalOrganizationTypes,
            clientPortalServiceRequirementOptions,
        });
    }

    const profile = buildClientAccountPayload(req.body);
    
    // Stage 1: Only require minimal fields
    if (!profile.organizationName || !profile.organizationType || !profile.contactFirstName || !profile.contactLastName || !profile.contactJobTitle || !profile.email || !profile.mobileNumber) {
        return res.status(400).render("client-portal-register", {
            title: "Facility Portal Registration",
            error: "Please fill in all required fields (marked with *).",
            message: "",
            formData: profile,
            isLoggedIn: false,
            clientPortalOrganizationTypes,
            clientPortalServiceRequirementOptions,
        });
    }
    
    // Check agreements
    if (!profile.termsAgreement || !profile.privacyAgreement) {
        return res.status(400).render("client-portal-register", {
            title: "Facility Portal Registration",
            error: "You must agree to the Terms & Conditions and Privacy Policy.",
            message: "",
            formData: profile,
            isLoggedIn: false,
            clientPortalOrganizationTypes,
            clientPortalServiceRequirementOptions,
        });
    }

    try {
        const existing = await getDb("SELECT id FROM client_accounts WHERE lower(email) = ?", [profile.email]);
        if (existing) {
            return res.status(409).render("client-portal-register", {
                title: "Facility Portal Registration",
                error: "An account already exists for that email address.",
                message: "",
                formData: profile,
                isLoggedIn: false,
                clientPortalOrganizationTypes,
                clientPortalServiceRequirementOptions,
            });
        }

        // Hash password
        const passwordHash = await hashPassword(password);

        // Insert only Stage 1 data (minimal required fields)
        const result = await runDb(
            `INSERT INTO client_accounts
             (organization_name, organization_type, contact_first_name, contact_last_name, contact_job_title, email, mobile_number, address_line_1, town, county, password_hash, terms_agreement, privacy_agreement, status, onboarded, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 0, datetime('now'))`,
            [
                profile.organizationName,
                profile.organizationType,
                profile.contactFirstName,
                profile.contactLastName,
                profile.contactJobTitle,
                profile.email,
                profile.mobileNumber,
                "",
                "",
                "",
                passwordHash,
                profile.termsAgreement,
                profile.privacyAgreement,
            ]
        );
        await recordPasswordHistory("client", result.lastID, passwordHash);
        
        // Generate facility ID
        const facilityId = `FAC-${String(result.lastID || "").padStart(5, "0")}`;
        await runDb("UPDATE client_accounts SET facility_id = ? WHERE id = ?", [facilityId, Number(result.lastID)]);

        await writeAuditEvent(req, {
            action: "client_portal_registration_stage1",
            targetType: "client_account",
            targetIdentifier: String(result.lastID),
            outcome: "success",
            actorType: "anonymous",
            actorIdentifier: profile.email,
        });
        
        emitPortalEvent("client_registration", { 
            clientAccountId: Number(result.lastID), 
            email: profile.email, 
            status: "pending",
            organization: profile.organizationName
        }, { adminOnly: true });

        return res.render("client-portal-register", {
            title: "Facility Portal Registration",
            error: "",
            message: "✓ Account created successfully! An admin will review your organisation within 24-48 hours. You'll receive an email confirmation.",
            formData: null,
            isLoggedIn: false,
            clientPortalOrganizationTypes,
            clientPortalServiceRequirementOptions,
        });
    } catch (error) {
        console.error("Error creating facility portal registration:", error.message);
        return res.status(500).render("client-portal-register", {
            title: "Facility Portal Registration",
            error: "The registration could not be completed. Please try again.",
            message: "",
            formData: profile,
            isLoggedIn: false,
            clientPortalOrganizationTypes,
            clientPortalServiceRequirementOptions,
        });
    }
});

app.get("/client-portal/forgot-password", (req, res) => {
    return res.render("client-portal-forgot-password", {
        title: "Facility Portal Password Reset",
        error: req.query.error || "",
        message: req.query.message || "",
        previewCode: req.query.previewCode || "",
        isLoggedIn: false,
    });
});

app.post("/client-portal/forgot-password", async (req, res) => {
    const email = String(req.body.email || "").trim().toLowerCase();
    if (!email) {
        return res.status(400).render("client-portal-forgot-password", {
            title: "Facility Portal Password Reset",
            error: "Please enter the approved facility portal email address.",
            message: "",
            previewCode: "",
            isLoggedIn: false,
        });
    }
    try {
        const account = await getDb("SELECT * FROM client_accounts WHERE lower(email) = ?", [email]);
        const authState = getClientAuthState(account);
        if (!authState.allowed) {
            return res.status(404).render("client-portal-forgot-password", {
                title: "Facility Portal Password Reset",
                error: authState.message,
                message: "",
                previewCode: "",
                isLoggedIn: false,
            });
        }
        const code = createResetCode();
        const codeHash = await bcrypt.hash(code, 10);
        await runDb("DELETE FROM client_password_resets WHERE client_account_id = ? AND used_at IS NULL", [account.id]);
        await runDb(
            `INSERT INTO client_password_resets (client_account_id, code_hash, expires_at)
             VALUES (?, ?, datetime('now', '+15 minutes'))`,
            [account.id, codeHash]
        );
        await queueClientNotification(account.id, "Password reset requested", "A password reset code was generated for your facility portal account.", "security", "/facility-portal/reset-password");
        return res.render("client-portal-forgot-password", {
            title: "Facility Portal Password Reset",
            error: "",
            message: "A reset code has been generated. Enter it on the reset page to set your password.",
            previewCode: isProduction ? "" : code,
            isLoggedIn: false,
        });
    } catch (error) {
        console.error("Error creating facility portal reset code:", error.message);
        return res.status(500).render("client-portal-forgot-password", {
            title: "Facility Portal Password Reset",
            error: "The reset request could not be completed.",
            message: "",
            previewCode: "",
            isLoggedIn: false,
        });
    }
});

app.get("/client-portal/reset-password", (req, res) => {
    return res.render("client-portal-reset-password", {
        title: "Set Facility Portal Password",
        error: req.query.error || "",
        message: req.query.message || "",
        isLoggedIn: false,
    });
});

app.post("/client-portal/reset-password", async (req, res) => {
    const email = String(req.body.email || "").trim().toLowerCase();
    const code = String(req.body.code || "").trim();
    const password = String(req.body.password || "");
    const securityPolicy = await getSecurityPolicy();
    if (!email || !code || password.length < securityPolicy.passwordMinimumLength) {
        return res.status(400).render("client-portal-reset-password", {
            title: "Set Facility Portal Password",
            error: `Email, reset code, and a password of at least ${securityPolicy.passwordMinimumLength} characters are required.`,
            message: "",
            isLoggedIn: false,
        });
    }
    try {
        const account = await getDb("SELECT * FROM client_accounts WHERE lower(email) = ?", [email]);
        const authState = getClientAuthState(account);
        if (!account) {
            return res.status(404).render("client-portal-reset-password", {
                title: "Set Facility Portal Password",
                error: "No facility portal account was found for that email address.",
                message: "",
                isLoggedIn: false,
            });
        }
        if (!authState.allowed) {
            return res.status(400).render("client-portal-reset-password", {
                title: "Set Facility Portal Password",
                error: authState.message,
                message: "",
                isLoggedIn: false,
            });
        }
        const resetRow = await getDb(
            `SELECT * FROM client_password_resets
             WHERE client_account_id = ? AND used_at IS NULL AND datetime(expires_at) > datetime('now')
             ORDER BY created_at DESC LIMIT 1`,
            [account.id]
        );
        if (!resetRow || !(await bcrypt.compare(code, resetRow.code_hash))) {
            return res.status(400).render("client-portal-reset-password", {
                title: "Set Facility Portal Password",
                error: "The reset code is invalid or has expired.",
                message: "",
                isLoggedIn: false,
            });
        }
        await assertPasswordNotReused({
            accountType: "client",
            accountId: account.id,
            password,
            currentPasswordHash: account.password_hash,
        });
        const passwordHash = await hashPassword(password);
        await recordPasswordHistory("client", account.id, account.password_hash);
        await runDb("UPDATE client_accounts SET password_hash = ?, force_password_reset = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?", [passwordHash, account.id]);
        await recordPasswordHistory("client", account.id, passwordHash);
        await runDb("UPDATE client_password_resets SET used_at = datetime('now') WHERE id = ?", [resetRow.id]);
        return res.render("client-portal-reset-password", {
            title: "Set Facility Portal Password",
            error: "",
            message: "Your facility portal password has been set. You can now sign in.",
            isLoggedIn: false,
        });
    } catch (error) {
        if (error.code === "PASSWORD_REUSED") {
            return res.status(400).render("client-portal-reset-password", {
                title: "Set Facility Portal Password",
                error: error.message,
                message: "",
                isLoggedIn: false,
            });
        }
        console.error("Error resetting facility portal password:", error.message);
        return res.status(500).render("client-portal-reset-password", {
            title: "Set Facility Portal Password",
            error: "The password could not be set.",
            message: "",
            isLoggedIn: false,
        });
    }
});

app.get("/client-portal/logout", async (req, res) => {
    try {
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "logout",
            targetType: "session",
            targetIdentifier: "client_portal",
            outcome: "success",
        });
        await destroySession(req);
        return res.redirect("/facility-portal/login?error=You have been signed out.");
    } catch (error) {
        console.error("Error during facility portal logout:", error.message);
        return res.status(500).render("error", {
            title: "Sign-out unavailable",
            message: "The system could not complete sign-out. Please try again.",
        });
    }
});

// Onboarding flow - GET handler
app.get("/client-portal/onboarding", requireClientPortal, async (req, res) => {
    try {
        const account = mapClientAccountRow(await getDb("SELECT * FROM client_accounts WHERE id = ?", [Number(req.session.clientAccountId)]));
        if (!account) {
            return res.redirect("/client-portal/login?error=Account not found");
        }

        // If already onboarded, redirect to dashboard
        if (account.onboarded) {
            return res.redirect("/client-portal/dashboard");
        }

        return res.render("client-portal-onboarding", {
            title: "Welcome to Everkind",
            error: req.query.error || "",
            message: req.query.message || "",
            approved: account.status === "approved",
            facility: account,
            isLoggedIn: true,
            clientPortalOrganizationTypes,
            clientPortalServiceRequirementOptions,
        });
    } catch (error) {
        console.error("Error loading onboarding:", error.message);
        return res.status(500).render("error", {
            title: "Error",
            message: "Could not load onboarding page",
            isLoggedIn: true,
        });
    }
});

// Onboarding profile completion - POST handler
app.post("/client-portal/onboarding/profile", requireClientPortal, async (req, res) => {
    try {
        const account = await getDb("SELECT * FROM client_accounts WHERE id = ?", [Number(req.session.clientAccountId)]);
        if (!account) {
            return res.status(404).json({ error: "Account not found" });
        }

        if (account.status !== "approved") {
            return res.status(400).render("client-portal-onboarding", {
                title: "Welcome to Everkind",
                error: "Your account must be approved by admin before completing your profile.",
                message: "",
                approved: false,
                facility: account,
                isLoggedIn: true,
                clientPortalOrganizationTypes,
                clientPortalServiceRequirementOptions,
            });
        }

        const profile = buildClientAccountPayload(req.body);

        // Validate required Stage 2 fields
        if (!profile.addressLine1 || !profile.town || !profile.county || !profile.eircode) {
            return res.status(400).render("client-portal-onboarding", {
                title: "Welcome to Everkind",
                error: "Address and Eircode are required to complete your profile.",
                message: "",
                approved: true,
                facility: { ...account, ...profile },
                isLoggedIn: true,
                clientPortalOrganizationTypes,
                clientPortalServiceRequirementOptions,
            });
        }

        const fullAddress = [
            profile.addressLine1,
            profile.addressLine2,
            profile.town,
            profile.county,
            profile.eircode,
        ].filter(Boolean).join(", ");

        let gpsLatitude = null;
        let gpsLongitude = null;
        try {
            const geocodeResult = await geocodeAddress(fullAddress);
            if (geocodeResult && geocodeResult[0]) {
                gpsLatitude = Number(geocodeResult[0].lat);
                gpsLongitude = Number(geocodeResult[0].lon);
            }
        } catch (error) {
            console.warn("Geocoding unavailable for onboarding profile:", error.message);
        }

        // Update account with Stage 2 data
        await runDb(
            `UPDATE client_accounts SET
             trading_name = ?, registration_number = ?, hiqa_registration_number = ?,
             vat_number = ?, website = ?,
             address_line_1 = ?, address_line_2 = ?, town = ?, county = ?, eircode = ?,
             gps_latitude = ?, gps_longitude = ?,
             number_of_beds = ?, number_of_residents = ?,
             current_staffing_provider = ?, service_requirements = ?,
             onboarded = 1, updated_at = datetime('now')
             WHERE id = ?`,
            [
                profile.tradingName || null,
                profile.registrationNumber || null,
                profile.hiqaRegistrationNumber || null,
                profile.vatNumber || null,
                profile.website || null,
                profile.addressLine1,
                profile.addressLine2 || null,
                profile.town,
                profile.county,
                profile.eircode,
                gpsLatitude,
                gpsLongitude,
                profile.numberOfBeds || null,
                profile.numberOfResidents || null,
                profile.currentStaffingProvider || null,
                serializeJsonField(profile.serviceRequirements),
                Number(req.session.clientAccountId),
            ]
        );

        await writeAuditEvent(req, {
            action: "client_onboarding_profile_complete",
            targetType: "client_account",
            targetIdentifier: String(req.session.clientAccountId),
            outcome: "success",
            actorType: "client",
        });

        emitPortalEvent("client_onboarding_complete", {
            clientAccountId: Number(req.session.clientAccountId),
            email: account.email,
            organization: account.organization_name,
        }, { adminOnly: true });

        return res.redirect("/client-portal/dashboard?message=Profile updated successfully! You can now request healthcare staff.");
    } catch (error) {
        console.error("Error updating onboarding profile:", error.message);
        return res.status(500).render("client-portal-onboarding", {
            title: "Welcome to Everkind",
            error: "Could not update your profile. Please try again.",
            message: "",
            approved: true,
            facility: req.body,
            isLoggedIn: true,
            clientPortalOrganizationTypes,
            clientPortalServiceRequirementOptions,
        });
    }
});

app.get("/client-portal/dashboard", requireClientPortal, async (req, res) => {
    try {
        const account = mapClientAccountRow(await getDb("SELECT * FROM client_accounts WHERE id = ?", [Number(req.session.clientAccountId)]));
        if (!account) {
            return res.redirect("/facility-portal/login?error=Your facility portal account could not be found.");
        }
        if (account.status === "approved" && !Number(account.onboarded || 0)) {
            return res.redirect("/client-portal/onboarding");
        }
        const requests = (await allDb(
            `SELECT csr.*, ca.organization_name, ca.contact_first_name, ca.contact_last_name,
                    s.name AS assigned_staff_name, s.role AS assigned_staff_role, s.profile_photo AS assigned_staff_photo,
                    s.experience_years AS assigned_staff_experience_years, s.qqi_qualifications AS assigned_staff_qqi_qualifications,
                    s.nmbi_number AS assigned_staff_nmbi_number, s.mandatory_training AS assigned_staff_mandatory_training,
                    s.additional_certifications AS assigned_staff_additional_certifications, s.languages AS assigned_staff_languages
             FROM client_service_requests csr
             INNER JOIN client_accounts ca ON ca.id = csr.client_account_id
             LEFT JOIN staff s ON s.id = csr.assigned_staff_id
             WHERE csr.client_account_id = ?
             ORDER BY csr.created_at DESC`,
            [account.id]
        )).map(mapClientRequestRow);
        const notifications = await allDb(
            `SELECT * FROM client_notifications
             WHERE client_account_id = ?
             ORDER BY created_at DESC
             LIMIT 5`,
            [account.id]
        );
        const bookings = (await allDb(
            `SELECT ss.*, COALESCE(p.first_name || ' ' || p.last_name, ss.external_client_label, 'Client') AS patient_name,
                    s.first_name || ' ' || s.last_name AS staff_name,
                    COALESCE(p.address, ss.location_address) AS address
             FROM staff_shifts ss
             LEFT JOIN patients p ON p.id = ss.patient_id
             LEFT JOIN staff s ON s.id = ss.staff_id
             WHERE ss.client_account_id = ?
             ORDER BY ss.scheduled_start ASC
             LIMIT 8`,
            [account.id]
        )).map(mapShiftRow);

        return res.render("client-portal-dashboard", {
            title: "Facility Portal Dashboard",
            isLoggedIn: true,
            account,
            currentClientName: account.displayName,
            currentClientEmail: account.email,
            requests,
            notifications,
            bookings,
            message: req.query.message || "",
        });
    } catch (error) {
        console.error("Error loading facility portal dashboard:", error.message);
        return res.status(500).render("error", {
            title: "Facility portal unavailable",
            message: "The facility portal dashboard could not be loaded.",
        });
    }
});

app.get("/client-portal/requests", requireClientPortal, async (req, res) => {
    try {
        const account = mapClientAccountRow(await getDb("SELECT * FROM client_accounts WHERE id = ?", [Number(req.session.clientAccountId)]));
        const requests = (await allDb(
            `SELECT csr.*, ca.organization_name, ca.contact_first_name, ca.contact_last_name
             FROM client_service_requests csr
             INNER JOIN client_accounts ca ON ca.id = csr.client_account_id
             WHERE csr.client_account_id = ?
             ORDER BY csr.created_at DESC`,
            [Number(req.session.clientAccountId)]
        )).map(mapClientRequestRow);
        return res.render("client-portal-requests", {
            title: "Facility Requests",
            isLoggedIn: true,
            account,
            currentClientName: account.displayName,
            currentClientEmail: account.email,
            requests,
        });
    } catch (error) {
        console.error("Error loading facility requests:", error.message);
        return res.status(500).render("error", { title: "Facility requests unavailable", message: "The request history could not be loaded." });
    }
});

app.get("/client-portal/requests/new", requireClientPortal, async (req, res) => {
    try {
        const account = mapClientAccountRow(await getDb("SELECT * FROM client_accounts WHERE id = ?", [Number(req.session.clientAccountId)]));
        return res.render("client-portal-request-form", {
            title: "Request Staff",
            isLoggedIn: true,
            account,
            currentClientName: account.displayName,
            currentClientEmail: account.email,
            error: req.query.error || "",
            message: req.query.message || "",
            formData: null,
            clientPortalFacilityTypeOptions,
            clientPortalRequestRoleOptions,
            clientPortalShiftTypeOptions,
            clientPortalRecurringPatternOptions,
            clientPortalSkillOptions,
            clientPortalTrainingOptions,
            clientPortalEnglishLevelOptions,
            clientPortalPriorityOptions,
        });
    } catch (error) {
        console.error("Error loading facility request form:", error.message);
        return res.status(500).render("error", { title: "Request form unavailable", message: "The request form could not be loaded." });
    }
});

app.post("/client-portal/requests", requireClientPortal, async (req, res) => {
    try {
        const account = mapClientAccountRow(await getDb("SELECT * FROM client_accounts WHERE id = ?", [Number(req.session.clientAccountId)]));
        const payload = buildClientRequestPayload(req.body, account);
        if (!payload.facilityName || !payload.facilityAddress || !payload.contactPerson || !payload.contactPhone || !payload.contactEmail || !payload.shiftDate || !payload.startTime || !payload.endTime) {
            return res.status(400).render("client-portal-request-form", {
                title: "Request Staff",
                isLoggedIn: true,
                account,
                currentClientName: account.displayName,
                currentClientEmail: account.email,
                error: "Facility, contact, and shift timing details are required.",
                message: "",
                formData: payload,
                clientPortalFacilityTypeOptions,
                clientPortalRequestRoleOptions,
                clientPortalShiftTypeOptions,
                clientPortalRecurringPatternOptions,
                clientPortalSkillOptions,
                clientPortalTrainingOptions,
                clientPortalEnglishLevelOptions,
                clientPortalPriorityOptions,
            });
        }
        const result = await runDb(
            `INSERT INTO client_service_requests
             (client_account_id, facility_name, facility_type, facility_address, facility_county, facility_eircode, facility_gps_latitude, facility_gps_longitude, contact_person, contact_position, contact_phone, contact_email, emergency_contact, staff_required, quantity_required, shift_type, recurring_pattern, multiple_dates, weekly_repeat_day, monthly_repeat_date, shift_date, start_time, end_time, break_duration_minutes, total_paid_hours, hourly_rate, ward_unit, resident_identifier, room_number, resident_unit, required_skills, required_training, minimum_experience_years, healthcare_setting_required, driving_licence_required, own_vehicle_required, english_language_level, additional_certifications, notes, uniform_required, parking_available, smoking_household, pets_on_premises, special_instructions, priority, language_requirement, travel_radius_km, status)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_review')`,
            [
                account.id,
                payload.facilityName,
                payload.facilityType,
                payload.facilityAddress,
                payload.facilityCounty,
                payload.facilityEircode,
                payload.facilityGpsLatitude,
                payload.facilityGpsLongitude,
                payload.contactPerson,
                payload.contactPosition,
                payload.contactPhone,
                payload.contactEmail,
                payload.emergencyContact,
                payload.staffRequired,
                payload.quantityRequired,
                payload.shiftType,
                payload.recurringPattern,
                serializeJsonField(payload.multipleDates),
                payload.weeklyRepeatDay,
                payload.monthlyRepeatDate,
                payload.shiftDate,
                payload.startTime,
                payload.endTime,
                payload.breakDurationMinutes,
                payload.totalPaidHours,
                payload.hourlyRate,
                payload.wardUnit,
                payload.residentIdentifier,
                payload.roomNumber,
                payload.residentUnit,
                serializeJsonField(payload.requiredSkills),
                serializeJsonField(payload.requiredTraining),
                payload.minimumExperienceYears,
                payload.healthcareSettingRequired,
                payload.drivingLicenceRequired ? 1 : 0,
                payload.ownVehicleRequired ? 1 : 0,
                payload.englishLanguageLevel,
                payload.additionalCertifications,
                payload.notes,
                payload.uniformRequired ? 1 : 0,
                payload.parkingAvailable ? 1 : 0,
                payload.smokingHousehold ? 1 : 0,
                payload.petsOnPremises ? 1 : 0,
                payload.specialInstructions,
                payload.priority,
                payload.languageRequirement,
                payload.travelRadiusKm,
            ]
        );
        await queueClientNotification(account.id, "Staff request submitted", "Your staffing request has been submitted and is pending admin review.", "request", "/facility-portal/requests");
        emitPortalEvent("client_request", { requestId: Number(result.lastID), clientAccountId: account.id, status: "pending_review" }, { adminOnly: true });
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "client_request_created",
            targetType: "client_request",
            targetIdentifier: String(result.lastID),
            outcome: "success",
        });
        return res.redirect("/facility-portal/dashboard?message=Request submitted successfully.");
    } catch (error) {
        console.error("Error creating facility request:", error.message);
        const account = mapClientAccountRow(await getDb("SELECT * FROM client_accounts WHERE id = ?", [Number(req.session.clientAccountId)]));
        return res.status(500).render("client-portal-request-form", {
            title: "Request Staff",
            isLoggedIn: true,
            account,
            currentClientName: account.displayName,
            currentClientEmail: account.email,
            error: "The staffing request could not be submitted.",
            message: "",
            formData: buildClientRequestPayload(req.body, account),
            clientPortalFacilityTypeOptions,
            clientPortalRequestRoleOptions,
            clientPortalShiftTypeOptions,
            clientPortalRecurringPatternOptions,
            clientPortalSkillOptions,
            clientPortalTrainingOptions,
            clientPortalEnglishLevelOptions,
            clientPortalPriorityOptions,
        });
    }
});

app.get("/portal/logout", async (req, res) => {
    try {
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "logout",
            targetType: "session",
            targetIdentifier: "portal",
            outcome: "success",
        });
        await destroySession(req);
        res.redirect("/portal/login?error=You have been signed out.");
    } catch (error) {
        console.error("Error during portal logout:", error.message);
        res.status(500).render("error", {
            title: "Sign-out unavailable",
            message: "The system could not complete sign-out. Please try again.",
        });
    }
});

app.get("/portal/dashboard", requirePortal, requireAdmin, async (req, res) => {
    try {
        if (res.locals.adminAccess.effectiveRole === "hr") {
            return res.redirect("/admin/hr-dashboard");
        }
        if (res.locals.adminAccess.effectiveRole === "payroll") {
            return res.redirect("/admin/payroll");
        }
        const patientCount = await getDb("SELECT COUNT(*) AS count FROM patients WHERE COALESCE(is_archived, 0) = 0");
        const staffCount = await getDb("SELECT COUNT(*) AS count FROM staff");
        const operationalShiftCounts = await getOperationalShiftCounts();
        const activeCarePlans = await getDb("SELECT COUNT(*) AS count FROM patients WHERE COALESCE(is_archived, 0) = 0 AND carePlan IS NOT NULL AND carePlan != ''");
        const currentBusinessDate = getBusinessDateKey();
        const medicationDue = await getDb("SELECT COUNT(*) AS count FROM staff_shifts WHERE status IN ('scheduled', 'clocked_in') AND date(scheduled_start) = ?", [currentBusinessDate]);
        const incidentCount = await getDb("SELECT COUNT(*) AS count FROM care_notes WHERE severity = 'Critical'");
        const totalShifts = await getDb("SELECT COUNT(*) AS count FROM staff_shifts");

        const { recentActivity, upcomingVisits } = await getDashboardShiftCollections();

        const staffPreview = (await allDb("SELECT * FROM staff ORDER BY first_name LIMIT 4")).map(mapStaffRow);

        res.render("portal-dashboard", {
            title: "Portal Dashboard",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            metrics: {
                patients: Number(patientCount.count),
                staff: Number(staffCount.count),
                visitsToday: Number(operationalShiftCounts.todayShifts || 0),
                carePlans: Number(activeCarePlans.count),
                medicationDue: Number(medicationDue.count),
                incidents: Number(incidentCount.count),
                totalShifts: Number(totalShifts.count),
            },
            recentActivity,
            upcomingVisits,
            staffPreview,
        });
    } catch (error) {
        console.error("Error loading dashboard data:", error.message);
        res.status(500).render("error", {
            title: "Dashboard unavailable",
            message: "The staff dashboard could not be loaded.",
        });
    }
});

app.get("/portal/compliance", requirePortal, requireAdmin, async (req, res) => {
    try {
        const patients = (await allDb(
            `SELECT id, first_name, last_name, name, legal_basis, consent_status, consent_recorded_at, consent_recorded_by, data_retention_until
             FROM patients
             WHERE COALESCE(is_archived, 0) = 0
             ORDER BY id`
        )).map(mapPatientRow);

        const subjectRequests = await allDb(
            `SELECT id, request_type, patient_id, requested_by, status, details, processed_at, created_at
             FROM subject_requests
             ORDER BY created_at DESC
             LIMIT 50`
        );

        return res.render("portal-compliance", {
            title: "Compliance Controls",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            patients,
            subjectRequests,
        });
    } catch (error) {
        console.error("Error loading compliance controls:", error.message);
        return res.status(500).render("error", {
            title: "Compliance controls unavailable",
            message: "The compliance control centre could not be loaded.",
        });
    }
});

app.get("/portal/shifts", requirePortal, async (req, res) => {
    try {
        const staffId = Number(req.session.staffId) || null;
        const isAdmin = Boolean(req.session.isAdmin);

        if (!isAdmin) {
            return res.redirect("/portal/my-schedule");
        }

        const shiftRows = await allDb(`
            SELECT ss.*,
                   p.home_care_client_id,
                   COALESCE(p.first_name || ' ' || p.last_name, ss.external_client_label, 'Home Care Client') AS home_care_client_name,
                   COALESCE(p.latitude, ss.external_latitude) AS latitude,
                   COALESCE(p.longitude, ss.external_longitude) AS longitude,
                   COALESCE(p.geofence_radius_meters, ss.external_geofence_radius_meters) AS geofence_radius_meters,
                   s.first_name || ' ' || s.last_name AS staff_name,
                   s.status AS staff_status,
                   s.role AS staff_role,
                   ca.facility_id,
                   COALESCE(ss.external_client_label, ca.organization_name, 'Healthcare Facility') AS facility_name,
                   COALESCE(ss.facility_type, csr.facility_type, ca.organization_type, 'Healthcare Facility') AS facility_type,
                   COALESCE(ss.location_address, csr.facility_address, ca.address_line_1, p.address, '') AS location_address,
                   COALESCE(ss.location_county, csr.facility_county, ca.county, p.county, '') AS location_county,
                   COALESCE(ss.location_eircode, csr.facility_eircode, ca.eircode, p.eircode, '') AS location_eircode,
                   COALESCE(ss.role_required, csr.staff_required, s.role, ss.service_type, 'Healthcare Assistant') AS role_required,
                   COALESCE(ss.shift_requirements, csr.notes, ss.care_instructions, ss.notes, '') AS shift_requirements,
                   COALESCE(ss.break_duration_minutes, csr.break_duration_minutes, 0) AS break_duration_minutes,
                   COALESCE(ss.quantity_required, csr.quantity_required, 1) AS quantity_required,
                   COALESCE(ss.contact_person, csr.contact_person, ca.contact_first_name || ' ' || ca.contact_last_name, '') AS contact_person
            FROM staff_shifts ss
            LEFT JOIN patients p ON p.id = ss.patient_id
            LEFT JOIN staff s ON s.id = ss.staff_id
            LEFT JOIN client_accounts ca ON ca.id = ss.client_account_id
            LEFT JOIN client_service_requests csr ON csr.id = ss.client_request_id
            ORDER BY ss.scheduled_start ASC
        `);
        const now = new Date();
        const shifts = shiftRows.map((shift) => mapShiftRow(shift, now));

        const query = req.query || {};
        const searchTerm = String(query.q || "").trim().toLowerCase();
        const divisionFilter = String(query.division || "all").trim().toLowerCase();
        const statusFilter = String(query.status || "all").trim().toLowerCase();
        const fromDate = String(query.date_from || "").trim();
        const toDate = String(query.date_to || "").trim();
        const staffFilter = String(query.staff_id || "").trim();
        const patientFilter = String(query.patient_id || "").trim();
        const facilityFilter = String(query.facility_id || "").trim();
        const facilityTypeFilter = String(query.facility_type || "").trim().toLowerCase();
        const countyFilter = String(query.county || "").trim().toLowerCase();
        const roleFilter = String(query.role || "").trim().toLowerCase();

        const filteredShifts = shifts.filter((shift) => {
            const shiftDateKey = String(shift.scheduledStart || shift.shift_date || "").slice(0, 10);
            if (fromDate && shiftDateKey && shiftDateKey < fromDate) {
                return false;
            }
            if (toDate && shiftDateKey && shiftDateKey > toDate) {
                return false;
            }
            if (divisionFilter !== "all" && shift.serviceDivision !== divisionFilter) {
                return false;
            }
            if (!shiftMatchesScheduleStatus(shift, statusFilter)) {
                return false;
            }
            if (staffFilter && String(shift.staffId || "") !== staffFilter) {
                return false;
            }
            if (patientFilter && String(shift.patientId || "") !== patientFilter) {
                return false;
            }
            if (facilityFilter && String(shift.clientAccountId || "") !== facilityFilter) {
                return false;
            }
            if (facilityTypeFilter && String(shift.facility_type || shift.facilityType || "").toLowerCase() !== facilityTypeFilter) {
                return false;
            }
            if (countyFilter && String(shift.county || shift.location_county || "").toLowerCase() !== countyFilter) {
                return false;
            }
            if (roleFilter && !String(shift.roleRequired || "").toLowerCase().includes(roleFilter)) {
                return false;
            }
            if (!searchTerm) {
                return true;
            }
            const searchText = [
                shift.shiftCode,
                shift.staffName,
                shift.patientName,
                shift.homeCareClientName,
                shift.facilityName,
                shift.facility_type || shift.facilityType || "",
                shift.address,
                shift.county,
                shift.roleRequired,
                shift.serviceType,
                shift.requirementLabel,
                shift.status,
                shift.operationalStatus,
                shift.client_request_id,
                shift.clientAccountId,
                shift.patientId,
            ].join(" ").toLowerCase();
            return searchText.includes(searchTerm);
        });

        const summary = buildScheduleSummary(shifts);

        const liveShift = filteredShifts.find((shift) => shift.status === "clocked_in" && (!staffId || shift.staffId === staffId)) || null;
        const myShifts = filteredShifts.filter((shift) => !staffId || shift.staffId === staffId);

        let patients = [];
        let staff = [];
        let facilities = [];
        let facilityTypes = [];
        let counties = [];
        if (isAdmin) {
            patients = (await allDb(
                "SELECT id, first_name, last_name, name FROM patients WHERE COALESCE(is_archived, 0) = 0 ORDER BY first_name"
            )).map(mapPatientRow);
            staff = (await allDb(
                "SELECT id, first_name, last_name, name, role FROM staff ORDER BY first_name"
            )).map(mapStaffRow);
            facilities = (await allDb(
                "SELECT id, facility_id, organization_name, organization_type FROM client_accounts ORDER BY organization_name"
            )).map(mapClientAccountRow);
            facilityTypes = Array.from(new Set(shifts.map((shift) => String(shift.facility_type || shift.facilityType || "").trim()).filter(Boolean))).sort((a, b) => a.localeCompare(b));
            counties = Array.from(new Set(shifts.map((shift) => String(shift.county || shift.location_county || "").trim()).filter(Boolean))).sort((a, b) => a.localeCompare(b));
        }

        res.render("portal-shifts", {
            title: "Shift Schedule",
            isLoggedIn: true,
            isAdmin,
            currentStaffName: req.session.staffName || "Operations team",
            liveShift: liveShift ? mapShiftRow(liveShift, now) : null,
            shifts: isAdmin ? filteredShifts : (myShifts.length ? myShifts : filteredShifts),
            userHasStaffProfile: Boolean(staffId),
            shiftStatus: req.query.status || "",
            patients,
            staff,
            facilities,
            facilityTypes,
            counties,
            scheduleSummary: summary,
            scheduleFilters: {
                q: String(query.q || "").trim(),
                division: divisionFilter || "all",
                status: statusFilter || "all",
                dateFrom: fromDate,
                dateTo: toDate,
                staffId: staffFilter,
                patientId: patientFilter,
                facilityId: facilityFilter,
                facilityType: String(query.facility_type || "").trim(),
                county: String(query.county || "").trim(),
                role: String(query.role || "").trim(),
            },
        });
    } catch (error) {
        console.error("Error loading shifts:", error.message);
        res.status(500).render("error", {
            title: "Shifts unavailable",
            message: "The staff shift list could not be loaded.",
        });
    }
});

// ============ APPLICATIONS ============

const recruitmentStageSet = new Set(recruitmentStageDefinitions.map((stage) => stage.key));
const recruitmentStageLabelMap = recruitmentStageDefinitions.reduce((map, stage) => {
    map[stage.key] = stage.label;
    return map;
}, {});

const normalizeRecruitmentStatus = (value) => {
    const raw = String(value || "").trim().toLowerCase();
    if (!raw) {
        return "new";
    }
    const alias = legacyRecruitmentStatusAliases[raw];
    const normalized = alias || raw;
    return recruitmentStageSet.has(normalized) ? normalized : "new";
};

const getRecruitmentStageLabel = (status) => recruitmentStageLabelMap[status] || status.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
const buildApplicationRef = () => {
    const now = new Date();
    const y = String(now.getFullYear());
    const m = String(now.getMonth() + 1).padStart(2, "0");
    const d = String(now.getDate()).padStart(2, "0");
    const rand = Math.floor(Math.random() * 9000 + 1000);
    return `EVK-APP-${y}${m}${d}-${rand}`;
};

const appendApplicationTimelineEntry = async (applicationId, stage, title, notes, actor = {}) => {
    await runDb(
        `INSERT INTO application_timeline (application_id, stage, title, notes, actor_type, actor_identifier)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [
            Number(applicationId),
            String(stage || "new"),
            String(title || "Status updated"),
            notes ? String(notes) : null,
            actor.actorType || null,
            actor.actorIdentifier || null,
        ]
    );
};

const sendRecruitmentEmail = async (toEmail, subject, htmlBody) => {
    const recipient = String(toEmail || "").trim();
    if (!recipient) {
        return { success: false, skipped: true, reason: "missing-email" };
    }
    const transporter = getMailTransporter();
    if (!transporter) {
        return { success: false, skipped: true, reason: "smtp-not-configured" };
    }
    await transporter.sendMail({
        from: `"${companyName} Recruitment" <${smtpFrom}>`,
        to: recipient,
        subject,
        html: htmlBody,
    });
    return { success: true };
};

const ensureStaffFromApplication = async (applicationRow) => {
    const applicationId = Number(applicationRow.id);
    const applicationEmail = String(applicationRow.email || "").trim().toLowerCase();
    const applicationNameParts = buildApplicationNameParts(applicationRow);
    const defaultShift = String(applicationRow.shift || "Morning").trim() || "Morning";
    let existingStaffMember = await getDb("SELECT id, status FROM staff WHERE application_id = ?", [applicationId]);
    if (!existingStaffMember && applicationEmail) {
        existingStaffMember = await getDb("SELECT id, status FROM staff WHERE lower(COALESCE(email, '')) = ?", [applicationEmail]);
    }
    if (!existingStaffMember) {
        const identity = await enforceApplicationUniqueness({
            email: applicationRow.email,
            phone: applicationRow.phone,
            excludeApplicationId: applicationId,
        });
        const defaultHash = await hashPassword(staffDefaultPassword);
        const insertResult = await runDb(
            `INSERT INTO staff
             (application_id, first_name, last_name, name, email, phone, role, availability, status, shift, employment_status, password_hash, induction_checklist, portal_login_enabled, welcome_email_sent)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
            [
                applicationId,
                applicationNameParts.firstName,
                applicationNameParts.surname,
                applicationNameParts.fullName || applicationRow.name || "",
                applicationRow.email || "",
                applicationRow.phone || "",
                applicationRow.role || "Care Worker",
                applicationRow.availability || "",
                "Induction",
                defaultShift,
                "Induction",
                defaultHash,
                serializeJsonField(normalizeInductionChecklist(null)),
                1,
                0,
            ]
        );
        await runDb(
            "UPDATE staff SET email_normalized = ?, phone_normalized = ? WHERE id = ?",
            [identity.normalizedEmail || null, identity.normalizedPhone || null, insertResult.lastID]
        );
        await recordPasswordHistory("staff", insertResult.lastID, defaultHash);
        return { staffId: Number(insertResult.lastID), created: true };
    }

    const identity = await enforceApplicationUniqueness({
        email: applicationRow.email,
        phone: applicationRow.phone,
        excludeApplicationId: applicationId,
        excludeStaffId: existingStaffMember.id,
    });
    await runDb(
        `UPDATE staff
         SET application_id = ?,
             first_name = COALESCE(NULLIF(first_name, ''), ?),
             last_name = COALESCE(NULLIF(last_name, ''), ?),
             name = COALESCE(NULLIF(name, ''), ?),
             email = COALESCE(NULLIF(email, ''), ?),
             phone = COALESCE(NULLIF(phone, ''), ?),
             email_normalized = COALESCE(NULLIF(email_normalized, ''), ?),
             phone_normalized = COALESCE(NULLIF(phone_normalized, ''), ?),
             role = COALESCE(NULLIF(role, ''), ?),
             availability = COALESCE(NULLIF(availability, ''), ?),
             status = 'Induction',
             shift = COALESCE(NULLIF(shift, ''), ?),
             employment_status = 'Induction',
             portal_login_enabled = 1,
             portal_login_suspended = 0,
             portal_login_deactivated = 0,
             induction_checklist = CASE
                 WHEN COALESCE(induction_checklist, '') = '' THEN ?
                 ELSE induction_checklist
             END
         WHERE id = ?`,
        [
            applicationId,
            applicationNameParts.firstName,
            applicationNameParts.surname,
            applicationNameParts.fullName || applicationRow.name || "",
            applicationRow.email || "",
            applicationRow.phone || "",
            identity.normalizedEmail || null,
            identity.normalizedPhone || null,
            applicationRow.role || "Care Worker",
            applicationRow.availability || "",
            defaultShift,
            serializeJsonField(normalizeInductionChecklist(null)),
            Number(existingStaffMember.id),
        ]
    );
    return { staffId: Number(existingStaffMember.id), created: false };
};

app.get("/portal/applications", requirePortal, requireAdmin, async (req, res) => {
    try {
        const applicationRows = await allDb(`
            SELECT a.*, s.id AS staff_member_id, s.status AS staff_member_status
            FROM applications a
            LEFT JOIN staff s ON s.application_id = a.id
            ORDER BY a.created_at DESC
        `);
        const applications = applicationRows.map((row) => ({
            ...row,
            ...(() => {
                const nameParts = buildApplicationNameParts(row);
                const parsedAvailability = parseApplicationAvailability(row.availability);
                return {
                    name: nameParts.fullName || row.name || "Unnamed Applicant",
                    first_name: nameParts.firstName,
                    surname: nameParts.surname,
                    status: normalizeRecruitmentStatus(row.status),
                    availabilitySelections: parsedAvailability.selections,
                    availabilityGrouped: parsedAvailability.grouped,
                    availabilityDisplay: parsedAvailability.displayText,
                    availabilityLegacyText: parsedAvailability.legacyText,
                };
            })(),
        }));
        const timelineRows = await allDb(
            `SELECT *
             FROM application_timeline
             WHERE application_id IN (
                SELECT id FROM applications
             )
             ORDER BY created_at DESC, id DESC`
        );
        const timelinesById = {};
        for (const entry of timelineRows) {
            const appId = Number(entry.application_id);
            if (!timelinesById[appId]) {
                timelinesById[appId] = [];
            }
            if (timelinesById[appId].length < 30) {
                timelinesById[appId].push({
                    stage: normalizeRecruitmentStatus(entry.stage),
                    stageLabel: getRecruitmentStageLabel(normalizeRecruitmentStatus(entry.stage)),
                    title: entry.title,
                    notes: entry.notes,
                    actorType: entry.actor_type,
                    actorIdentifier: entry.actor_identifier,
                    createdAt: entry.created_at,
                });
            }
        }
        const requestedFilter = String(req.query.filter || "all").trim().toLowerCase();
        const filter = requestedFilter === "all" ? "all" : normalizeRecruitmentStatus(requestedFilter);
        res.render("portal-applications", {
            title: "Applications",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            applications,
            recruitmentStages: recruitmentStageDefinitions,
            applicationTimelinesById: timelinesById,
            filter,
            applicationAvailabilityGroups,
            allApplicationAvailabilityOptions: applicationAvailabilityOptions,
        });
    } catch (error) {
        console.error("Error loading applications:", error.message);
        res.status(500).render("error", { title: "Applications unavailable", message: "Could not load applications." });
    }
});

const handleApplicationStatusUpdate = async (req, res) => {
    const requestedStatus = normalizeRecruitmentStatus(req.body.status);
    if (!recruitmentStageSet.has(requestedStatus)) {
        return res.status(400).json({ success: false, message: "Invalid status." });
    }
    try {
        const applicationId = Number(req.params.id);
        const applicationRow = await getDb("SELECT * FROM applications WHERE id = ?", [applicationId]);
        if (!applicationRow) {
            return res.status(404).json({ success: false, message: "Application not found." });
        }

        const actor = getActorContext(req);
        const actorLabel = req.session.staffName || req.session.staffEmail || actor.actorIdentifier || "System";
        const stageNotes = String(req.body.notes || "").trim();
        const previousStatus = normalizeRecruitmentStatus(applicationRow.status);
        let effectiveStatus = requestedStatus;

        const updates = [
            "status = ?",
            "last_stage_changed_at = CURRENT_TIMESTAMP",
            "last_stage_changed_by = ?",
        ];
        const params = [effectiveStatus, String(actorLabel)];

        const timestampColumnsByStage = {
            reviewing: "reviewed_at",
            shortlisted: "shortlisted_at",
            interview_scheduled: "interview_scheduled_at",
            interview_completed: "interview_completed_at",
            offer_sent: "offer_sent_at",
            offer_accepted: "offer_accepted_at",
            pre_employment_checks: "pre_employment_checks_at",
            induction: "induction_started_at",
            approved_employee: "approved_employee_at",
            active_staff: "active_staff_at",
            rejected: "rejected_at",
            archived: "archived_at",
        };
        const timestampColumn = timestampColumnsByStage[effectiveStatus];
        if (timestampColumn) {
            updates.push(`${timestampColumn} = COALESCE(${timestampColumn}, CURRENT_TIMESTAMP)`);
        }
        if (effectiveStatus === "reviewing") {
            updates.push("reviewed_by = COALESCE(reviewed_by, ?)");
            params.push(String(actorLabel));
        }

        let staffInfo = null;
        if (["offer_accepted", "pre_employment_checks", "induction", "approved_employee", "active_staff"].includes(effectiveStatus)) {
            staffInfo = await ensureStaffFromApplication({ ...applicationRow, status: effectiveStatus });
        }
        if (effectiveStatus === "offer_accepted") {
            effectiveStatus = "induction";
            params[0] = effectiveStatus;
            updates.push("induction_started_at = COALESCE(induction_started_at, CURRENT_TIMESTAMP)");
        }

        await runDb(`UPDATE applications SET ${updates.join(", ")} WHERE id = ?`, [...params, applicationId]);

        if (staffInfo && Number(staffInfo.staffId) > 0) {
            if (effectiveStatus === "approved_employee") {
                await runDb(
                    `UPDATE staff
                     SET status = 'Active',
                         employment_status = 'Active',
                         portal_login_enabled = 1,
                         portal_login_suspended = 0,
                         portal_login_deactivated = 0
                     WHERE id = ?`,
                    [Number(staffInfo.staffId)]
                );
            } else if (effectiveStatus === "active_staff") {
                await runDb(
                    `UPDATE staff
                     SET status = 'Active',
                         employment_status = 'Active',
                         portal_login_enabled = 1,
                         portal_login_suspended = 0,
                         portal_login_deactivated = 0
                     WHERE id = ?`,
                    [Number(staffInfo.staffId)]
                );
            }
        }

        if (previousStatus !== requestedStatus) {
            await appendApplicationTimelineEntry(
                applicationId,
                requestedStatus,
                `Stage changed to ${getRecruitmentStageLabel(requestedStatus)}`,
                stageNotes || null,
                actor
            );
        }
        if (requestedStatus === "offer_accepted") {
            await appendApplicationTimelineEntry(
                applicationId,
                "induction",
                "Moved to Induction",
                "Employee profile created automatically from application data.",
                actor
            );
        }

        await writeAuditEvent(req, {
            ...actor,
            action: "application_stage_changed",
            targetType: "application",
            targetIdentifier: String(applicationId),
            outcome: "success",
            reason: `${previousStatus} -> ${requestedStatus}`,
        });

        const emailAddress = String(applicationRow.email || "").trim();
        if (emailAddress && ["interview_scheduled", "offer_sent", "offer_accepted", "rejected", "archived"].includes(requestedStatus)) {
            const stageLabel = getRecruitmentStageLabel(requestedStatus);
            const emailSubject = `Everkind recruitment update: ${stageLabel}`;
            const emailHtml = `
                <div style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;">
                    <h2 style="color:#17324b;">Everkind Home Care Recruitment Update</h2>
                    <p>Hi ${String(applicationRow.name || "Applicant")},</p>
                    <p>Your application for <strong>${String(applicationRow.role || "the role")}</strong> is now at stage: <strong>${stageLabel}</strong>.</p>
                    ${stageNotes ? `<p>Notes from our team:<br>${stageNotes}</p>` : ""}
                    <p>Thank you,<br>${companyName} Recruitment Team</p>
                </div>
            `;
            try {
                await sendRecruitmentEmail(emailAddress, emailSubject, emailHtml);
            } catch (mailError) {
                console.error("Recruitment stage email failed:", mailError.message);
                await appendApplicationTimelineEntry(
                    applicationId,
                    requestedStatus,
                    "Email delivery failed",
                    mailError.message,
                    actor
                );
            }
        }

        emitPortalEvent("recruitment_update", {
            applicationId,
            status: effectiveStatus,
            statusLabel: getRecruitmentStageLabel(effectiveStatus),
        }, { adminOnly: true });

        return res.json({ success: true, status: effectiveStatus });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
};

app.patch("/portal/applications/:id/details", requirePortal, requireAdmin, async (req, res) => {
    try {
        const applicationId = Number(req.params.id);
        if (!Number.isInteger(applicationId) || applicationId <= 0) {
            return res.status(400).json({ success: false, message: "Invalid application id." });
        }

        const applicationRow = await getDb("SELECT * FROM applications WHERE id = ?", [applicationId]);
        if (!applicationRow) {
            return res.status(404).json({ success: false, message: "Application not found." });
        }

        const nameParts = buildApplicationNameParts(req.body || {});
        if (!nameParts.firstName || !nameParts.surname) {
            return res.status(400).json({ success: false, message: "First name and surname are required." });
        }
        const email = normalizeEmailAddress(req.body.email);
        if (!email || !isValidEmailAddress(email)) {
            return res.status(400).json({ success: false, message: "A valid email address is required." });
        }
        const phone = String(req.body.phone || "").trim();
        const role = String(req.body.role || "").trim();
        const availabilitySelections = normalizeApplicationAvailabilitySelections(req.body.availability_options || req.body.availabilitySelections);
        const availabilityLegacy = String(req.body.availabilityLegacy || "").trim();
        const availabilityValue = availabilitySelections.length ? serializeJsonField(availabilitySelections) : availabilityLegacy;
        const linkedStaffMember = await getDb("SELECT id FROM staff WHERE application_id = ?", [applicationId]);
        const { normalizedPhone } = await enforceApplicationUniqueness({
            email,
            phone,
            excludeApplicationId: applicationId,
            excludeStaffId: linkedStaffMember ? Number(linkedStaffMember.id) : null,
        });

        await runDb(
            `UPDATE applications
             SET name = ?,
                 first_name = ?,
                 surname = ?,
                 email = ?,
                 email_normalized = ?,
                 phone = ?,
                 phone_normalized = ?,
                 role = ?,
                 availability = ?
             WHERE id = ?`,
            [
                nameParts.fullName,
                nameParts.firstName,
                nameParts.surname,
                email,
                email,
                phone,
                normalizedPhone || "",
                role,
                availabilityValue,
                applicationId,
            ]
        );
        if (linkedStaffMember) {
            await runDb(
                `UPDATE staff
                 SET first_name = ?,
                     last_name = ?,
                     name = ?,
                     email = ?,
                     phone = ?,
                     role = COALESCE(NULLIF(?, ''), role),
                     availability = ?
                 WHERE id = ?`,
                [
                    nameParts.firstName,
                    nameParts.surname,
                    nameParts.fullName,
                    email,
                    phone,
                    role,
                    availabilityValue,
                    Number(linkedStaffMember.id),
                ]
            );
        }

        const actor = getActorContext(req);
        await appendApplicationTimelineEntry(
            applicationId,
            normalizeRecruitmentStatus(applicationRow.status),
            "Applicant details updated",
            "Profile details were updated by an administrator.",
            actor
        );
        await writeAuditEvent(req, {
            ...actor,
            action: "application_details_updated",
            targetType: "application",
            targetIdentifier: String(applicationId),
            outcome: "success",
        });

        return res.json({ success: true });
    } catch (error) {
        if (error.code === "APPLICATION_DUPLICATE_EMAIL" || error.code === "APPLICATION_DUPLICATE_PHONE") {
            await recordDuplicateIdentityAttempt(req, error, "application");
            return res.status(409).json({ success: false, message: error.message });
        }
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.post("/portal/applications/:id/status", requirePortal, requireAdmin, handleApplicationStatusUpdate);
app.patch("/portal/applications/:id/status", requirePortal, requireAdmin, handleApplicationStatusUpdate);
app.get("/admin/applications", requirePortal, requireAdmin, (req, res) => {
    res.redirect("/portal/applications");
});

// Hire applicant: create staff profile from application
app.post("/portal/applications/:id/hire", requirePortal, requireAdmin, async (req, res) => {
    try {
        const applicationId = Number(req.params.id);
        const app_ = await getDb("SELECT * FROM applications WHERE id = ?", [applicationId]);
        if (!app_) return res.status(404).send("Application not found");
        const actor = getActorContext(req);
        const staffInfo = await ensureStaffFromApplication(app_);
        await runDb(
            `UPDATE applications
             SET status = 'induction',
                 offer_accepted_at = COALESCE(offer_accepted_at, CURRENT_TIMESTAMP),
                 induction_started_at = COALESCE(induction_started_at, CURRENT_TIMESTAMP),
                 last_stage_changed_at = CURRENT_TIMESTAMP,
                 last_stage_changed_by = ?
             WHERE id = ?`,
            [String(req.session.staffName || req.session.staffEmail || actor.actorIdentifier || "Administrator"), applicationId]
        );
        await appendApplicationTimelineEntry(
            applicationId,
            "induction",
            "Moved to Induction",
            "Employee profile created/linked from application.",
            actor
        );
        await writeAuditEvent(req, {
            ...actor,
            action: "application_hired",
            targetType: "application",
            targetIdentifier: String(applicationId),
            outcome: "success",
            reason: `staff_id:${Number(staffInfo.staffId || 0)}`,
        });

        const staffRedirectId = Number(staffInfo.staffId || 0);
        if (staffRedirectId) {
            return res.redirect(`/staff?section=induction&highlight=${staffRedirectId}#induction-section`);
        }
        return res.redirect("/staff?section=induction#induction-section");
    } catch (error) {
        console.error("Error hiring applicant:", error.message);
        return res.redirect("/portal/applications?error=hire-failed");
    }
});

app.post("/portal/applications/:id/delete", requirePortal, requireAdmin, async (req, res) => {
    try {
        await runDb("DELETE FROM applications WHERE id = ?", [Number(req.params.id)]);
        res.redirect("/portal/applications");
    } catch (error) {
        res.redirect("/portal/applications");
    }
});

app.get("/portal/client-portal", requirePortal, requireAdmin, async (req, res) => {
    return res.redirect("/admin/facility-portal");
});

app.get("/portal/facility-portal", requirePortal, requireAdmin, (req, res) => {
    return res.redirect("/admin/facility-portal");
});

app.post("/portal/client-accounts/:id/status", requirePortal, requireAdmin, async (req, res) => {
    try {
        const accountId = Number(req.params.id);
        const status = clientPortalRegistrationStatuses.includes(String(req.body.status || "").trim())
            ? String(req.body.status).trim()
            : "pending";
        const notes = String(req.body.review_notes || "").trim();
        const account = await getDb("SELECT * FROM client_accounts WHERE id = ?", [accountId]);
        if (!account) {
            return res.redirect("/admin/facility-portal?error=client-account-not-found");
        }
        const portalEnabled = status === "approved" ? 1 : 0;
        const shouldIssueTemporaryPassword = status === "approved" && account.status !== "approved";
        let temporaryPassword = "";
        let temporaryPasswordHash = account.password_hash;
        if (shouldIssueTemporaryPassword) {
            temporaryPassword = createTemporaryPassword();
            temporaryPasswordHash = await hashPassword(temporaryPassword);
        }
        await runDb(
            `UPDATE client_accounts
             SET status = ?, review_notes = ?, password_hash = ?, force_password_reset = ?, portal_login_enabled = ?, portal_login_suspended = ?, portal_login_deactivated = ?, approved_at = CASE WHEN ? = 'approved' THEN datetime('now') ELSE approved_at END, approved_by = CASE WHEN ? = 'approved' THEN ? ELSE approved_by END, updated_at = CURRENT_TIMESTAMP
             WHERE id = ?`,
            [
                status,
                notes,
                temporaryPasswordHash,
                shouldIssueTemporaryPassword ? 1 : 0,
                portalEnabled,
                status === "suspended" ? 1 : 0,
                status === "rejected" ? 1 : 0,
                status,
                status,
                req.session.staffEmail || adminEmail,
                accountId,
            ]
        );
        await queueClientNotification(
            accountId,
            status === "approved" ? "Facility portal approved" : "Facility portal status updated",
            status === "approved"
                ? "Your facility portal registration has been approved. Use your temporary password to log in, then set a new password immediately."
                : `Your facility portal registration is now marked as ${status.replace(/_/g, " ")}.`,
            "account",
            status === "approved" ? "/facility-portal/login" : "/facility-portal/login"
        );
        emitPortalEvent("client_registration", { clientAccountId: accountId, status }, { adminOnly: true });
        if (temporaryPassword) {
            const encodedEmail = encodeURIComponent(account.email || "");
            const encodedTemp = encodeURIComponent(temporaryPassword);
            return res.redirect(`/admin/facility-portal?approved=1&facility_email=${encodedEmail}&temp_password=${encodedTemp}`);
        }
        return res.redirect("/admin/facility-portal");
    } catch (error) {
        console.error("Error updating client account status:", error.message);
        return res.redirect("/admin/facility-portal?error=client-account-status-update-failed");
    }
});

app.post("/portal/client-requests/:id/status", requirePortal, requireAdmin, async (req, res) => {
    try {
        const requestId = Number(req.params.id);
        const status = clientPortalRequestStatuses.includes(String(req.body.status || "").trim())
            ? String(req.body.status).trim()
            : "pending_review";
        const requestRow = await getDb("SELECT * FROM client_service_requests WHERE id = ?", [requestId]);
        if (!requestRow) {
            return res.redirect("/admin/shift-requests?error=client-request-not-found");
        }
        const account = await getDb("SELECT * FROM client_accounts WHERE id = ?", [requestRow.client_account_id]);
        let nextStatus = status;
        let publishedOpenShiftId = requestRow.published_open_shift_id || null;
        if (status === "approved" && !requestRow.published_open_shift_id && !requestRow.scheduled_shift_id) {
            const createdShiftId = await createShiftFromClientRequest({ clientAccount: account, clientRequest: requestRow, isOpen: true });
            publishedOpenShiftId = createdShiftId;
            nextStatus = "awaiting_staff";
        }
        await runDb(
            "UPDATE client_service_requests SET status = ?, published_open_shift_id = COALESCE(?, published_open_shift_id), approved_at = CASE WHEN ? = 'approved' THEN datetime('now') ELSE approved_at END, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            [nextStatus, publishedOpenShiftId, status, requestId]
        );
        await queueClientNotification(
            requestRow.client_account_id,
            "Staff request updated",
            nextStatus === "awaiting_staff"
                ? "Your request has been approved and is now awaiting the next available qualified staff member."
                : `Your staffing request is now marked as ${nextStatus.replace(/_/g, " ")}.`,
            "request",
            "/facility-portal/requests"
        );
        emitPortalEvent("client_request", { requestId, status: nextStatus }, { adminOnly: true });
        return res.redirect("/admin/shift-requests");
    } catch (error) {
        console.error("Error updating client request status:", error.message);
        return res.redirect("/admin/shift-requests?error=client-request-status-update-failed");
    }
});

app.post("/portal/client-requests/:id/publish-open-shift", requirePortal, requireAdmin, async (req, res) => {
    try {
        const requestId = Number(req.params.id);
        const requestRow = await getDb("SELECT * FROM client_service_requests WHERE id = ?", [requestId]);
        if (!requestRow) {
            return res.redirect("/admin/shift-requests?error=client-request-not-found");
        }
        const account = await getDb("SELECT * FROM client_accounts WHERE id = ?", [requestRow.client_account_id]);
        const shiftId = await createShiftFromClientRequest({ clientAccount: account, clientRequest: requestRow, isOpen: true });
        await runDb(
            "UPDATE client_service_requests SET status = 'awaiting_staff', published_open_shift_id = ?, approved_at = COALESCE(approved_at, datetime('now')), updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            [shiftId, requestId]
        );
        await queueClientNotification(requestRow.client_account_id, "Request published to open shifts", "Your staffing request is now live in the Everkind open-shift pool.", "request", "/facility-portal/requests");
        return res.redirect("/admin/shift-requests");
    } catch (error) {
        console.error("Error publishing client request to open shifts:", error.message);
        return res.redirect("/admin/shift-requests?error=publish-open-shift-failed");
    }
});

app.post("/portal/client-requests/:id/assign", requirePortal, requireAdmin, async (req, res) => {
    try {
        const requestId = Number(req.params.id);
        const staffId = Number(req.body.staff_id);
        if (!Number.isInteger(staffId) || staffId <= 0) {
            return res.redirect("/admin/shift-requests?error=staff-selection-required");
        }
        const requestRow = await getDb("SELECT * FROM client_service_requests WHERE id = ?", [requestId]);
        if (!requestRow) {
            return res.redirect("/admin/shift-requests?error=client-request-not-found");
        }
        const account = await getDb("SELECT * FROM client_accounts WHERE id = ?", [requestRow.client_account_id]);
        const staffMember = mapStaffRow(await getDb("SELECT * FROM staff WHERE id = ?", [staffId]));
        const eligibility = await staffMeetsRequestRequirements({
            staffMember,
            shift: {
                id: 0,
                scheduled_start: `${requestRow.shift_date} ${requestRow.start_time}`,
                scheduled_end: `${requestRow.shift_date} ${requestRow.end_time}`,
            },
            request: mapClientRequestRow(requestRow),
        });
        if (!eligibility.eligible) {
            return res.redirect(`/admin/shift-requests?error=${encodeURIComponent(eligibility.reasons[0] || "staff-not-eligible")}`);
        }
        const shiftId = await createShiftFromClientRequest({ clientAccount: account, clientRequest: requestRow, staffId, isOpen: false });
        await runDb(
            "UPDATE client_service_requests SET status = 'confirmed', assigned_staff_id = ?, scheduled_shift_id = ?, approved_at = COALESCE(approved_at, datetime('now')), accepted_by_staff_at = datetime('now'), updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            [staffId, shiftId, requestId]
        );
        await queueClientNotification(requestRow.client_account_id, "Staff request assigned", "An Everkind team member has been scheduled for your request.", "request", "/facility-portal/requests");
        return res.redirect("/admin/shift-requests");
    } catch (error) {
        console.error("Error assigning staff to client request:", error.message);
        return res.redirect("/admin/shift-requests?error=client-request-assignment-failed");
    }
});

app.post("/portal/client-requests/:id/duplicate", requirePortal, requireAdmin, async (req, res) => {
    try {
        const requestId = Number(req.params.id);
        const requestRow = await getDb("SELECT * FROM client_service_requests WHERE id = ?", [requestId]);
        if (!requestRow) {
            return res.redirect("/admin/shift-requests?error=client-request-not-found");
        }
        await runDb(
            `INSERT INTO client_service_requests
             (client_account_id, facility_name, facility_type, facility_address, facility_county, facility_eircode, facility_gps_latitude, facility_gps_longitude, contact_person, contact_position, contact_phone, contact_email, emergency_contact, staff_required, quantity_required, shift_type, recurring_pattern, multiple_dates, weekly_repeat_day, monthly_repeat_date, shift_date, start_time, end_time, break_duration_minutes, total_paid_hours, hourly_rate, ward_unit, resident_identifier, room_number, resident_unit, required_skills, required_training, minimum_experience_years, healthcare_setting_required, driving_licence_required, own_vehicle_required, english_language_level, additional_certifications, notes, uniform_required, parking_available, smoking_household, pets_on_premises, special_instructions, priority, language_requirement, travel_radius_km, status)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_review')`,
            [
                requestRow.client_account_id,
                requestRow.facility_name,
                requestRow.facility_type,
                requestRow.facility_address,
                requestRow.facility_county,
                requestRow.facility_eircode,
                requestRow.facility_gps_latitude,
                requestRow.facility_gps_longitude,
                requestRow.contact_person,
                requestRow.contact_position,
                requestRow.contact_phone,
                requestRow.contact_email,
                requestRow.emergency_contact,
                requestRow.staff_required,
                requestRow.quantity_required,
                requestRow.shift_type,
                requestRow.recurring_pattern,
                requestRow.multiple_dates,
                requestRow.weekly_repeat_day,
                requestRow.monthly_repeat_date,
                requestRow.shift_date,
                requestRow.start_time,
                requestRow.end_time,
                requestRow.break_duration_minutes,
                requestRow.total_paid_hours,
                requestRow.hourly_rate,
                requestRow.ward_unit,
                requestRow.resident_identifier,
                requestRow.room_number,
                requestRow.resident_unit,
                requestRow.required_skills,
                requestRow.required_training,
                requestRow.minimum_experience_years,
                requestRow.healthcare_setting_required,
                requestRow.driving_licence_required,
                requestRow.own_vehicle_required,
                requestRow.english_language_level,
                requestRow.additional_certifications,
                requestRow.notes,
                requestRow.uniform_required,
                requestRow.parking_available,
                requestRow.smoking_household,
                requestRow.pets_on_premises,
                requestRow.special_instructions,
                requestRow.priority,
                requestRow.language_requirement,
                requestRow.travel_radius_km,
            ]
        );
        return res.redirect("/admin/shift-requests");
    } catch (error) {
        console.error("Error duplicating client request:", error.message);
        return res.redirect("/admin/shift-requests?error=client-request-duplicate-failed");
    }
});

// Submit application from website (updates apply form)
app.post("/api/applications", async (req, res) => {
    const payload = req.body || {};
    const { firstName, surname, fullName } = buildApplicationNameParts(payload);
    const email = normalizeEmailAddress(payload.email);
    const phone = String(payload.phone || "").trim();
    const role = String(payload.role || "").trim();
    const availabilitySelections = normalizeApplicationAvailabilitySelections(payload.availability_options || payload.availabilitySelections);
    if (!firstName || !surname) {
        return res.status(400).json({ success: false, message: "First name and surname are required." });
    }
    if (!email || !isValidEmailAddress(email)) {
        return res.status(400).json({ success: false, message: "A valid email address is required." });
    }
    try {
        const { normalizedPhone } = await enforceApplicationUniqueness({ email, phone });
        const applicationRef = buildApplicationRef();
        const insertResult = await runDb(
            `INSERT INTO applications
             (name, first_name, surname, email, email_normalized, phone, phone_normalized, role, availability, status, application_ref, last_stage_changed_at, last_stage_changed_by)
             VALUES (?,?,?,?,?,?,?,?,?,'new',?,CURRENT_TIMESTAMP,?)`,
            [
                fullName,
                firstName,
                surname,
                email,
                email,
                phone || "",
                normalizedPhone || "",
                role || "",
                serializeJsonField(availabilitySelections),
                applicationRef,
                "Website",
            ]
        );
        const applicationId = Number(insertResult.lastID);
        await appendApplicationTimelineEntry(
            applicationId,
            "new",
            "Application submitted",
            `Reference: ${applicationRef}`,
            { actorType: "applicant", actorIdentifier: String(email || fullName || "").trim() || null }
        );
        emitPortalEvent("recruitment_update", {
            applicationId,
            status: "new",
            statusLabel: getRecruitmentStageLabel("new"),
        }, { adminOnly: true });

        const applicantEmail = String(email || "").trim();
        if (applicantEmail) {
            const subject = `Everkind application received (${applicationRef})`;
            const body = `
                <div style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;">
                    <h2 style="color:#17324b;">Thank you for applying to ${companyName}</h2>
                    <p>Hi ${String(fullName || "Applicant")},</p>
                    <p>We have received your application for <strong>${String(role || "our care team")}</strong>.</p>
                    <p>Your application reference is <strong>${applicationRef}</strong>.</p>
                    <p>Our recruitment team will review your application and contact you with updates.</p>
                    <p>Kind regards,<br>${companyName} Recruitment Team</p>
                </div>
            `;
            try {
                await sendRecruitmentEmail(applicantEmail, subject, body);
            } catch (mailError) {
                console.error("Application confirmation email failed:", mailError.message);
                await appendApplicationTimelineEntry(
                    applicationId,
                    "new",
                    "Confirmation email failed",
                    mailError.message,
                    { actorType: "system", actorIdentifier: "mailer" }
                );
            }
        }
        res.json({ success: true });
    } catch (error) {
        if (error.code === "APPLICATION_DUPLICATE_EMAIL" || error.code === "APPLICATION_DUPLICATE_PHONE") {
            await recordDuplicateIdentityAttempt(req, error, "application");
            return res.status(409).json({ success: false, message: error.message });
        }
        res.status(500).json({ success: false, message: error.message });
    }
});

// ============ OPEN SHIFTS ============

app.get("/portal/open-shifts", requirePortal, requireAdmin, async (req, res) => {
    try {
        const openShifts = await allDb(`
            SELECT ss.*,
                   p.home_care_client_id,
                   COALESCE(p.first_name || ' ' || p.last_name, ss.external_client_label, 'Home Care Client') AS home_care_client_name,
                   COALESCE(ss.external_client_label, ca.organization_name, p.first_name || ' ' || p.last_name, 'Client') AS patient_name,
                   ca.organization_name AS facility_name,
                   COALESCE(ss.facility_type, csr.facility_type, ca.organization_type) AS facility_type,
                   COALESCE(ss.location_address, ca.address_line_1, p.address, '') AS location_address,
                   COALESCE(ss.location_county, ca.county, p.county, '') AS location_county,
                   COALESCE(ss.location_eircode, ca.eircode, p.eircode, '') AS location_eircode,
                   csr.contact_person,
                   csr.staff_required,
                   csr.required_skills,
                   csr.required_training
            FROM staff_shifts ss
            LEFT JOIN patients p ON p.id = ss.patient_id
            LEFT JOIN client_accounts ca ON ca.id = ss.client_account_id
            LEFT JOIN client_service_requests csr ON csr.id = ss.client_request_id
            WHERE COALESCE(ss.is_open, 0) = 1
            ORDER BY ss.scheduled_start ASC
        `);
        const patients = (await allDb(
            `SELECT id, first_name, last_name, name, status, shift_instructions, care_needs_service_types
             FROM patients
             WHERE COALESCE(is_archived, 0) = 0
             ORDER BY first_name`
        )).map(mapPatientRow);
        res.render("portal-open-shifts", {
            title: "Open Shifts",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            openShifts: openShifts.map(mapShiftRow).filter((shift) => shift.operationalStatus === "open"),
            patients,
        });
    } catch (error) {
        console.error("Error loading open shifts:", error.message);
        res.status(500).render("error", { title: "Open Shifts unavailable", message: "Could not load open shifts." });
    }
});

app.post("/api/open-shifts", requirePortal, requireAdmin, async (req, res) => {
    const { patientId, shiftDate, startTime, endTime, serviceType, notes, care_instructions: careInstructionsBody, role_required: roleRequiredBody } = req.body;
    const careInstructions = String(careInstructionsBody || notes || "").trim();
    if (!patientId || !shiftDate || !startTime || !endTime) {
        return res.status(400).json({ success: false, message: "Client, date, and times are required." });
    }
    try {
        const patient = mapPatientRow(await getDb("SELECT * FROM patients WHERE id = ? AND COALESCE(is_archived, 0) = 0", [Number(patientId)]));
        if (!patient) {
            return res.status(404).json({ success: false, message: "Client not found." });
        }
        if (["In Hospital", "On Holiday", "Temporarily Suspended", "Discharged", "Deceased", "Archived"].includes(patient.status)) {
            return res.status(409).json({ success: false, message: `Open shifts cannot be created while this client is marked as ${patient.status}.` });
        }
        const scheduledStart = `${shiftDate} ${startTime}`;
        const scheduledEnd   = `${shiftDate} ${endTime}`;
        const result = await runDb(
            `INSERT INTO staff_shifts (patient_id, shift_date, scheduled_start, scheduled_end, service_type, notes, care_instructions, status, is_open, service_division, role_required)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'scheduled', 1, 'home-care', ?)`,
            [Number(patientId), shiftDate, scheduledStart, scheduledEnd, serviceType || patient.serviceTypes[0] || "Personal Care", careInstructions || patient.shift_instructions || "", careInstructions || patient.shift_instructions || "", String(roleRequiredBody || "Healthcare Assistant").trim()]
        );
        await runDb("UPDATE staff_shifts SET shift_code = ? WHERE id = ?", [buildShiftCode("home-care", result.lastID), Number(result.lastID)]);
        const staffRows = (await allDb("SELECT * FROM staff WHERE lower(status) NOT IN ('suspended', 'inactive')")).map(mapStaffRow);
        for (const member of staffRows) {
            if (member.notifyOpenShift) {
                await queueStaffNotification(
                    member.id,
                    "New open shift available",
                    `A ${serviceType || "care"} shift on ${shiftDate} is now available for pickup.`,
                    "shift",
                    "/portal/staff-open-shifts"
                );
            }
        }
        emitPortalEvent("open_shift_update", { action: "created", shiftId: Number(result.lastID) });
        res.json({ success: true, id: result.lastID });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});

app.post("/api/shifts/:id/delete", requirePortal, requireAdmin, async (req, res) => {
    try {
        await runDb("DELETE FROM staff_shifts WHERE id = ?", [Number(req.params.id)]);
        res.redirect("back");
    } catch (error) {
        res.redirect("back");
    }
});

// ============ LIVE TRACKING ============

app.get("/portal/live-tracking", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getLiveTrackingModuleData();

        res.render("portal-live-tracking", {
            title: "Live Tracking",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            liveTracking: data,
        });
    } catch (error) {
        console.error("Error loading live tracking:", error.message);
        res.status(500).render("error", { title: "Live Tracking unavailable", message: "Could not load live tracking." });
    }
});

// ============ ATTENDANCE ============

app.get("/portal/attendance", requirePortal, requireAdmin, async (req, res) => {
    try {
        const selectedDate = req.query.date || new Date().toISOString().slice(0, 10);
        const records = await allDb(`
            SELECT ss.*,
                   COALESCE(ss.external_client_label, ca.organization_name, p.first_name || ' ' || p.last_name, 'Client') AS patient_name,
                   p.home_care_client_id,
                   ca.facility_id,
                   ca.organization_name AS facility_name,
                   s.first_name || ' ' || s.last_name AS staff_name,
                   s.status AS staff_status
            FROM staff_shifts ss
            LEFT JOIN patients p ON p.id = ss.patient_id
            LEFT JOIN client_accounts ca ON ca.id = ss.client_account_id
            LEFT JOIN staff s ON s.id = ss.staff_id
            WHERE date(ss.scheduled_start) = ? OR date(ss.shift_date) = ?
            ORDER BY ss.scheduled_start ASC
        `, [selectedDate, selectedDate]);

        const clockedIn  = records.filter(r => r.actual_clock_in).length;
        const clockedOut = records.filter(r => r.actual_clock_out).length;
        const missed     = records.filter(r => r.status === "no_show").length;
        let totalMins = 0;
        for (const r of records) {
            if (r.actual_clock_in && r.actual_clock_out) {
                totalMins += Math.round((new Date(r.actual_clock_out) - new Date(r.actual_clock_in)) / 60000);
            }
        }
        const now = new Date();
        const late = records.filter(r => {
            if (r.actual_clock_in && r.scheduled_start) {
                return new Date(r.actual_clock_in) > new Date(r.scheduled_start.replace(" ", "T"));
            }
            if (!r.actual_clock_in && r.scheduled_start) {
                const start = new Date(r.scheduled_start.replace(" ", "T"));
                return now > start && r.status !== "completed" && r.status !== "cancelled";
            }
            return false;
        }).length;

        res.render("portal-attendance", {
            title: "Attendance",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            records,
            selectedDate,
            stats: {
                clockedIn, clockedOut, late, missed,
                totalHours: (totalMins / 60).toFixed(1),
            },
        });
    } catch (error) {
        console.error("Error loading attendance:", error.message);
        res.status(500).render("error", { title: "Attendance unavailable", message: "Could not load attendance records." });
    }
});

// ============ REPORTS ============

app.get("/portal/reports", requirePortal, requireAdmin, async (req, res) => {
    const [allShiftsRow, homeCareRow, agencyRow, openRow, inProgressRow, completedRow] = await Promise.all([
        getDb("SELECT COUNT(*) AS count FROM staff_shifts"),
        getDb("SELECT COUNT(*) AS count FROM staff_shifts WHERE COALESCE(service_division, 'home-care') = 'home-care'"),
        getDb("SELECT COUNT(*) AS count FROM staff_shifts WHERE COALESCE(service_division, 'home-care') = 'agency-staffing'"),
        getAvailableOpenShiftCount().then((count) => ({ count })),
        getDb("SELECT COUNT(*) AS count FROM staff_shifts WHERE status IN ('clocked_in', 'on_break')"),
        getDb("SELECT COUNT(*) AS count FROM staff_shifts WHERE status IN ('completed', 'clocked_out')"),
    ]);
    res.render("portal-reports", {
        title: "Reports",
        isLoggedIn: true,
        isAdmin: true,
        currentStaffName: req.session.staffName || "Administrator",
        currentStaffEmail: req.session.staffEmail || adminEmail,
        shiftSummary: {
            all: Number(allShiftsRow ? allShiftsRow.count : 0),
            homeCare: Number(homeCareRow ? homeCareRow.count : 0),
            agency: Number(agencyRow ? agencyRow.count : 0),
            open: Number(openRow ? openRow.count : 0),
            inProgress: Number(inProgressRow ? inProgressRow.count : 0),
            completed: Number(completedRow ? completedRow.count : 0),
        },
    });
});

// Export attendance as CSV
const exportAttendanceCsv = async (req, res) => {
    try {
        const data = await getAttendanceModuleData(req.query || {});
        const selectedDate = data.selectedDate;
        const records = data.records;

        res.setHeader("Content-Type", "text/csv");
        res.setHeader("Content-Disposition", `attachment; filename="attendance-${selectedDate}.csv"`);
        let csv = "Type,Shift Code,Staff,Home Care Client/Facility,Scheduled Start,Scheduled End,Clock In,Clock Out,Hours,Status\n";
        for (const r of records) {
            const clockIn  = r.actual_clock_in  ? r.actual_clock_in.slice(11, 16)  : "";
            const clockOut = r.actual_clock_out ? r.actual_clock_out.slice(11, 16) : "";
            let hrs = "";
            if (r.actual_clock_in && r.actual_clock_out) {
                const m = Math.round((new Date(r.actual_clock_out) - new Date(r.actual_clock_in)) / 60000);
                hrs = (m / 60).toFixed(2);
            }
            const division = getShiftDivision(r) === "agency-staffing" ? "AGENCY" : "HOME CARE";
            const shiftCode = r.shift_code || buildShiftCode(getShiftDivision(r), r.id);
            csv += `"${division}","${shiftCode}","${r.staff_name || ""}","${r.patient_name || ""}","${r.scheduled_start || ""}","${r.scheduled_end || ""}","${clockIn}","${clockOut}","${hrs}","${r.status || ""}"\n`;
        }
        res.send(csv);
    } catch (error) {
        res.status(500).send("Error generating export");
    }
};

// Export attendance as CSV
app.get("/portal/attendance/export", requirePortal, requireAdmin, exportAttendanceCsv);
app.get("/admin/attendance/export", requirePortal, requireAdmin, exportAttendanceCsv);

const isoDateKey = (value) => String(value || "").slice(0, 10);

const isDateWithinRange = (dateValue, fromDate, toDate) => {
    const key = isoDateKey(dateValue);
    if (!key) {
        return false;
    }
    if (fromDate && key < fromDate) {
        return false;
    }
    if (toDate && key > toDate) {
        return false;
    }
    return true;
};

const getDashboardModuleData = async () => {
    const currentBusinessDate = getBusinessDateKey();
    const [patientCount, staffCount, operationalShiftCounts, activeCarePlans, medicationDue, incidentCount, totalShifts, recruitmentRows, inductionCount, activeRecruitmentStaffCount] = await Promise.all([
        getDb("SELECT COUNT(*) AS count FROM patients WHERE COALESCE(is_archived, 0) = 0"),
        getDb("SELECT COUNT(*) AS count FROM staff"),
        getOperationalShiftCounts(),
        getDb("SELECT COUNT(*) AS count FROM patients WHERE COALESCE(is_archived, 0) = 0 AND carePlan IS NOT NULL AND carePlan != ''"),
        getDb("SELECT COUNT(*) AS count FROM staff_shifts WHERE status IN ('scheduled', 'clocked_in') AND date(scheduled_start) = ?", [currentBusinessDate]),
        getDb("SELECT COUNT(*) AS count FROM care_notes WHERE severity = 'Critical'"),
        getDb("SELECT COUNT(*) AS count FROM staff_shifts"),
        allDb(`
            SELECT status, COUNT(*) AS count
            FROM applications
            GROUP BY status
        `),
        getDb("SELECT COUNT(*) AS count FROM staff WHERE lower(COALESCE(status, '')) = 'induction'"),
        getDb("SELECT COUNT(*) AS count FROM staff WHERE lower(COALESCE(status, '')) = 'active'"),
    ]);

    const recruitmentCounts = {
        applicationsTotal: Number(Array.isArray(recruitmentRows) ? recruitmentRows.reduce((sum, row) => sum + Number(row.count || 0), 0) : 0),
        new: 0,
        reviewing: 0,
        shortlisted: 0,
        interview_scheduled: 0,
        interview_completed: 0,
        offer_sent: 0,
        offer_accepted: 0,
        pre_employment_checks: 0,
        induction: Number(inductionCount ? inductionCount.count : 0),
        awaiting_approval: Number(inductionCount ? inductionCount.count : 0),
        approved_employee: 0,
        active_staff: Number(activeRecruitmentStaffCount ? activeRecruitmentStaffCount.count : 0),
        rejected: 0,
        archived: 0,
    };
    for (const row of recruitmentRows) {
        const status = normalizeRecruitmentStatus(row.status);
        if (Object.prototype.hasOwnProperty.call(recruitmentCounts, status)) {
            recruitmentCounts[status] = Number(row.count || 0);
        }
    }

    const { recentActivity, upcomingVisits } = await getDashboardShiftCollections();
    const staffPreview = (await allDb("SELECT * FROM staff ORDER BY first_name LIMIT 4")).map(mapStaffRow);

    return {
        metrics: {
            patients: Number(patientCount ? patientCount.count : 0),
            staff: Number(staffCount ? staffCount.count : 0),
            visitsToday: Number(operationalShiftCounts.todayShifts || 0),
            carePlans: Number(activeCarePlans ? activeCarePlans.count : 0),
            medicationDue: Number(medicationDue ? medicationDue.count : 0),
            incidents: Number(incidentCount ? incidentCount.count : 0),
            totalShifts: Number(totalShifts ? totalShifts.count : 0),
        },
        recruitmentMetrics: recruitmentCounts,
        recentActivity,
        upcomingVisits,
        staffPreview,
    };
};

const getHrDashboardModuleData = async () => {
    const [staffRows, applicationRows, trainingRows, documentRows, recentActivity] = await Promise.all([
        allDb("SELECT * FROM staff WHERE COALESCE(is_archived, 0) = 0 ORDER BY COALESCE(updated_at, start_date) DESC, id DESC"),
        allDb("SELECT id, name, email, role, status, created_at, last_stage_changed_at FROM applications ORDER BY COALESCE(last_stage_changed_at, created_at) DESC, id DESC"),
        allDb(
            `SELECT staff_training.*, COALESCE(NULLIF(staff.name, ''), staff.first_name || ' ' || staff.last_name, staff.email) AS staff_name
             FROM staff_training
             LEFT JOIN staff ON staff.id = staff_training.staff_id
             ORDER BY COALESCE(staff_training.expires_at, staff_training.created_at) ASC`
        ),
        allDb("SELECT staff_id, COUNT(*) AS count FROM staff_documents WHERE staff_id IS NOT NULL GROUP BY staff_id"),
        allDb(
            `SELECT actor_identifier, actor_role, action, target_type, target_identifier, outcome, created_at
             FROM audit_events
             WHERE (
                 target_type IN ('staff', 'application')
                 OR action LIKE 'staff_%'
                 OR action LIKE 'application_%'
                 OR action LIKE 'recruitment_%'
                 OR action LIKE 'induction_%'
             )
             ORDER BY created_at DESC
             LIMIT 8`
        ),
    ]);
    const staff = staffRows.map(mapStaffRow);
    const documentCounts = new Map(documentRows.map((row) => [Number(row.staff_id), Number(row.count || 0)]));
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const dayMs = 24 * 60 * 60 * 1000;
    const daysUntil = (value) => {
        const parsed = new Date(`${String(value || "").slice(0, 10)}T23:59:59`);
        return Number.isNaN(parsed.getTime()) ? null : Math.ceil((parsed.getTime() - today.getTime()) / dayMs);
    };
    const expiryState = (value, reminderDays = 30) => {
        const days = daysUntil(value);
        if (days === null) return null;
        if (days < 0) return "expired";
        if (days <= reminderDays) return "expiring";
        return "current";
    };
    const expiryItems = [];
    const complianceRows = staff.map((member) => {
        const issues = [];
        const memberExpiries = [
            { label: "Garda vetting", value: member.gardaVettingExpiryDate, reminderDays: 30 },
            { label: "Professional registration", value: member.nmbiExpiryDate, reminderDays: 60 },
            { label: "Right to work", value: member.visaExpiryDate, reminderDays: 60 },
            { label: "Passport", value: member.passportExpiryDate, reminderDays: 60 },
            ...member.certificationRecords.map((record) => ({
                label: record.item,
                value: record.expiryDate,
                reminderDays: Number(record.reminderDays) || 30,
            })),
        ];
        for (const expiry of memberExpiries) {
            const state = expiryState(expiry.value, expiry.reminderDays);
            if (!state || state === "current") continue;
            expiryItems.push({
                staffId: member.id,
                staffName: member.name,
                item: expiry.label,
                expiryDate: expiry.value,
                state,
            });
            issues.push(`${expiry.label} ${state}`);
        }
        const outstandingTraining = member.trainingRecords.filter((record) => !record.completed).length;
        if (outstandingTraining) issues.push(`${outstandingTraining} training item${outstandingTraining === 1 ? "" : "s"} pending`);
        if (!member.gardaVettingStatus || !["complete", "completed", "approved", "current", "clear"].includes(String(member.gardaVettingStatus).toLowerCase())) {
            issues.push("Garda vetting requires review");
        }
        if (!documentCounts.get(Number(member.id))) issues.push("No staff documents uploaded");
        if (!member.rightToWork) issues.push("Right-to-work status missing");
        const inductionOutstanding = member.inductionChecklistSummary && Number(member.inductionChecklistSummary.outstanding || 0);
        if (String(member.status).toLowerCase() === "induction" && inductionOutstanding) {
            issues.push(`${inductionOutstanding} induction step${inductionOutstanding === 1 ? "" : "s"} outstanding`);
        }
        const score = Number(member.complianceSummary.overallCompliance);
        const derivedScore = issues.length ? Math.max(25, 100 - issues.length * 15) : 100;
        return {
            id: member.id,
            name: member.name,
            role: member.role,
            employmentStatus: member.employmentStatus,
            score: Number.isFinite(score) ? Math.min(score, derivedScore) : derivedScore,
            issues,
            tone: issues.some((issue) => /expired|overdue|missing|no staff documents/i.test(issue)) ? "red" : issues.length ? "amber" : "green",
        };
    }).sort((left, right) => right.issues.length - left.issues.length || left.name.localeCompare(right.name));

    const normalizedApplications = applicationRows.map((application) => ({
        ...application,
        status: normalizeRecruitmentStatus(application.status),
    }));
    const applicationCounts = normalizedApplications.reduce((counts, application) => {
        counts[application.status] = Number(counts[application.status] || 0) + 1;
        return counts;
    }, {});
    const onboardingStaff = staff.filter((member) => ["induction", "onboarding"].includes(String(member.status || member.employmentStatus).toLowerCase()));
    const activeStaff = staff.filter((member) => ["active", "available", "on duty"].includes(String(member.status || member.employmentStatus).toLowerCase()));
    const probationStaff = staff.map((member) => {
        const startDate = member.startDate ? new Date(`${member.startDate}T00:00:00`) : null;
        const explicitProbation = String(member.employmentStatus || "").toLowerCase().includes("probation");
        const reviewDate = startDate && !Number.isNaN(startDate.getTime())
            ? new Date(startDate.getFullYear(), startDate.getMonth() + 6, startDate.getDate())
            : null;
        const onProbation = explicitProbation || Boolean(reviewDate && reviewDate >= today);
        return { ...member, reviewDate, onProbation };
    }).filter((member) => member.onProbation);
    const upcomingProbationReviews = probationStaff.filter((member) => {
        if (!member.reviewDate) return false;
        const days = Math.ceil((member.reviewDate.getTime() - today.getTime()) / dayMs);
        return days >= 0 && days <= 30;
    });
    const databaseTraining = trainingRows.map((record) => {
        const state = expiryState(record.expires_at, 30);
        const normalizedStatus = String(record.status || "").toLowerCase();
        return {
            ...record,
            state: normalizedStatus === "expired" || state === "expired"
                ? "overdue"
                : normalizedStatus === "upcoming" || state === "expiring"
                    ? "upcoming"
                    : normalizedStatus === "pending"
                        ? "pending"
                        : "current",
        };
    });
    const embeddedTraining = staff.flatMap((member) => member.trainingRecords.map((record) => {
        const state = expiryState(record.expiryDate, Number(record.reminderDays) || 30);
        return {
            staff_id: member.id,
            staff_name: member.name,
            title: record.item,
            expires_at: record.expiryDate,
            state: !record.completed ? "pending" : state === "expired" ? "overdue" : state === "expiring" ? "upcoming" : "current",
        };
    }));
    const training = [...databaseTraining, ...embeddedTraining];
    const pendingTraining = training.filter((record) => record.state === "pending");
    const overdueTraining = training.filter((record) => record.state === "overdue");
    const upcomingTraining = training.filter((record) => record.state === "upcoming");
    const expiringDocuments = expiryItems.filter((item) => item.state === "expiring");
    const expiredDocuments = expiryItems.filter((item) => item.state === "expired");

    return {
        metrics: {
            activeStaff: activeStaff.length,
            newApplications: Number(applicationCounts.new || 0),
            awaitingReview: Number(applicationCounts.new || 0) + Number(applicationCounts.reviewing || 0),
            onboarding: onboardingStaff.length,
            requiringAction: complianceRows.filter((member) => member.issues.length).length,
            expiringDocuments: expiringDocuments.length,
            expiredDocuments: expiredDocuments.length,
            pendingTraining: pendingTraining.length,
            overdueTraining: overdueTraining.length,
            upcomingTraining: upcomingTraining.length,
            complianceIssues: complianceRows.reduce((total, member) => total + member.issues.length, 0),
            incompleteCompliance: complianceRows.filter((member) => member.issues.length).length,
            missingDocuments: complianceRows.filter((member) => member.issues.some((issue) => /document|right-to-work/i.test(issue))).length,
            probation: probationStaff.length,
            upcomingProbationReviews: upcomingProbationReviews.length,
        },
        applicationCounts,
        recentApplications: normalizedApplications.slice(0, 6),
        complianceRows: complianceRows.slice(0, 8),
        upcomingTraining: upcomingTraining.slice(0, 6),
        trainingAlerts: [
            ...overdueTraining.map((record) => ({ ...record, state: "overdue" })),
            ...pendingTraining.map((record) => ({ ...record, state: "pending" })),
            ...upcomingTraining.map((record) => ({ ...record, state: "upcoming" })),
        ],
        documentAlerts: [...expiredDocuments, ...expiringDocuments].slice(0, 6),
        probationReviews: upcomingProbationReviews.slice(0, 6).map((member) => ({
            id: member.id,
            name: member.name,
            role: member.role,
            reviewDate: member.reviewDate.toISOString().slice(0, 10),
        })),
        recentActivity: recentActivity.map((event) => ({
            ...event,
            label: String(event.action || "").replace(/_/g, " ").replace(/\b\w/g, (character) => character.toUpperCase()),
        })),
    };
};

const getComplianceModuleData = async () => {
    const patients = (await allDb(
        `SELECT id, first_name, last_name, name, legal_basis, consent_status, consent_recorded_at, consent_recorded_by, data_retention_until
         FROM patients
         WHERE COALESCE(is_archived, 0) = 0
         ORDER BY id`
    )).map(mapPatientRow);

    const subjectRequests = await allDb(
        `SELECT id, request_type, patient_id, requested_by, status, details, processed_at, created_at
         FROM subject_requests
         ORDER BY created_at DESC
         LIMIT 50`
    );
    return { patients, subjectRequests };
};

const getScheduleModuleData = async (query, staffId = null) => {
    const now = new Date();
    const shiftRows = await allDb(`
        SELECT ss.*,
               p.home_care_client_id,
               COALESCE(p.first_name || ' ' || p.last_name, ss.external_client_label, 'Home Care Client') AS home_care_client_name,
               COALESCE(p.latitude, ss.external_latitude) AS latitude,
               COALESCE(p.longitude, ss.external_longitude) AS longitude,
               COALESCE(p.geofence_radius_meters, ss.external_geofence_radius_meters) AS geofence_radius_meters,
               s.first_name || ' ' || s.last_name AS staff_name,
               s.role AS staff_role,
               ca.facility_id,
               COALESCE(ss.external_client_label, ca.organization_name, 'Healthcare Facility') AS facility_name,
               COALESCE(ss.facility_type, csr.facility_type, ca.organization_type, 'Healthcare Facility') AS facility_type,
               COALESCE(ss.location_address, csr.facility_address, ca.address_line_1, p.address, '') AS location_address,
               COALESCE(ss.location_county, csr.facility_county, ca.county, p.county, '') AS location_county,
               COALESCE(ss.location_eircode, csr.facility_eircode, ca.eircode, p.eircode, '') AS location_eircode,
               COALESCE(ss.role_required, csr.staff_required, s.role, ss.service_type, 'Healthcare Assistant') AS role_required,
               COALESCE(ss.shift_requirements, csr.notes, ss.care_instructions, ss.notes, '') AS shift_requirements,
               COALESCE(ss.break_duration_minutes, csr.break_duration_minutes, 0) AS break_duration_minutes,
               COALESCE(ss.quantity_required, csr.quantity_required, 1) AS quantity_required,
               COALESCE(ss.contact_person, csr.contact_person, ca.contact_first_name || ' ' || ca.contact_last_name, '') AS contact_person
        FROM staff_shifts ss
        LEFT JOIN patients p ON p.id = ss.patient_id
        LEFT JOIN staff s ON s.id = ss.staff_id
        LEFT JOIN client_accounts ca ON ca.id = ss.client_account_id
        LEFT JOIN client_service_requests csr ON csr.id = ss.client_request_id
        ORDER BY ss.scheduled_start ASC
    `);
    const shifts = shiftRows.map((shift) => mapShiftRow(shift, now));

    const searchTerm = String(query.q || "").trim().toLowerCase();
    const divisionFilter = String(query.division || "all").trim().toLowerCase();
    const statusFilter = String(query.status || "all").trim().toLowerCase();
    const fromDate = String(query.date_from || "").trim();
    const toDate = String(query.date_to || "").trim();
    const staffFilter = String(query.staff_id || "").trim();
    const patientFilter = String(query.patient_id || "").trim();
    const facilityFilter = String(query.facility_id || "").trim();
    const facilityTypeFilter = String(query.facility_type || "").trim().toLowerCase();
    const countyFilter = String(query.county || "").trim().toLowerCase();
    const roleFilter = String(query.role || "").trim().toLowerCase();

    const filteredShifts = shifts.filter((shift) => {
        const shiftDateKey = String(shift.scheduledStart || shift.shift_date || "").slice(0, 10);
        if (fromDate && shiftDateKey && shiftDateKey < fromDate) {
            return false;
        }
        if (toDate && shiftDateKey && shiftDateKey > toDate) {
            return false;
        }
        if (divisionFilter !== "all" && shift.serviceDivision !== divisionFilter) {
            return false;
        }
        if (!shiftMatchesScheduleStatus(shift, statusFilter)) {
            return false;
        }
        if (staffFilter && String(shift.staffId || "") !== staffFilter) {
            return false;
        }
        if (patientFilter && String(shift.patientId || "") !== patientFilter) {
            return false;
        }
        if (facilityFilter && String(shift.clientAccountId || "") !== facilityFilter) {
            return false;
        }
        if (facilityTypeFilter && String(shift.facility_type || shift.facilityType || "").toLowerCase() !== facilityTypeFilter) {
            return false;
        }
        if (countyFilter && String(shift.county || shift.location_county || "").toLowerCase() !== countyFilter) {
            return false;
        }
        if (roleFilter && !String(shift.roleRequired || "").toLowerCase().includes(roleFilter)) {
            return false;
        }
        if (!searchTerm) {
            return true;
        }
        const searchText = [
            shift.shiftCode,
            shift.staffName,
            shift.patientName,
            shift.homeCareClientName,
            shift.facilityName,
            shift.facility_type || shift.facilityType || "",
            shift.address,
            shift.county,
            shift.roleRequired,
            shift.serviceType,
            shift.requirementLabel,
            shift.status,
            shift.operationalStatus,
            shift.client_request_id,
            shift.clientAccountId,
            shift.patientId,
        ].join(" ").toLowerCase();
        return searchText.includes(searchTerm);
    });

    const summary = buildScheduleSummary(shifts);
    const liveShift = filteredShifts.find((shift) => shift.status === "clocked_in" && (!staffId || shift.staffId === staffId)) || null;

    const [patients, staff, facilities] = await Promise.all([
        allDb("SELECT id, first_name, last_name, name FROM patients WHERE COALESCE(is_archived, 0) = 0 ORDER BY first_name"),
        allDb("SELECT id, first_name, last_name, name, role FROM staff ORDER BY first_name"),
        allDb("SELECT id, facility_id, organization_name, organization_type FROM client_accounts ORDER BY organization_name"),
    ]);
    const facilityTypes = Array.from(new Set(shifts.map((shift) => String(shift.facility_type || shift.facilityType || "").trim()).filter(Boolean))).sort((a, b) => a.localeCompare(b));
    const counties = Array.from(new Set(shifts.map((shift) => String(shift.county || shift.location_county || "").trim()).filter(Boolean))).sort((a, b) => a.localeCompare(b));

    return {
        liveShift: liveShift ? mapShiftRow(liveShift, now) : null,
        shifts: filteredShifts,
        patients: patients.map(mapPatientRow),
        staff: staff.map(mapStaffRow),
        facilities: facilities.map(mapClientAccountRow),
        facilityTypes,
        counties,
        scheduleSummary: summary,
        scheduleFilters: {
            q: String(query.q || "").trim(),
            division: divisionFilter || "all",
            status: statusFilter || "all",
            dateFrom: fromDate,
            dateTo: toDate,
            staffId: staffFilter,
            patientId: patientFilter,
            facilityId: facilityFilter,
            facilityType: String(query.facility_type || "").trim(),
            county: String(query.county || "").trim(),
            role: String(query.role || "").trim(),
        },
    };
};

const getOpenShiftsModuleData = async () => {
    const openShifts = await allDb(`
        SELECT ss.*,
               p.home_care_client_id,
               COALESCE(p.first_name || ' ' || p.last_name, ss.external_client_label, 'Home Care Client') AS home_care_client_name,
               COALESCE(ss.external_client_label, ca.organization_name, p.first_name || ' ' || p.last_name, 'Client') AS patient_name,
               ca.organization_name AS facility_name,
               COALESCE(ss.facility_type, csr.facility_type, ca.organization_type) AS facility_type,
               COALESCE(ss.location_address, ca.address_line_1, p.address, '') AS location_address,
               COALESCE(ss.location_county, ca.county, p.county, '') AS location_county,
               COALESCE(ss.location_eircode, ca.eircode, p.eircode, '') AS location_eircode,
               csr.contact_person,
               csr.staff_required,
               csr.required_skills,
               csr.required_training
        FROM staff_shifts ss
        LEFT JOIN patients p ON p.id = ss.patient_id
        LEFT JOIN client_accounts ca ON ca.id = ss.client_account_id
        LEFT JOIN client_service_requests csr ON csr.id = ss.client_request_id
        WHERE COALESCE(ss.is_open, 0) = 1
        ORDER BY ss.scheduled_start ASC
    `);
    const patients = (await allDb(
        `SELECT id, first_name, last_name, name, status, shift_instructions, care_needs_service_types
         FROM patients
         WHERE COALESCE(is_archived, 0) = 0
         ORDER BY first_name`
    )).map(mapPatientRow);
    return {
        openShifts: openShifts.map(mapShiftRow).filter((shift) => shift.operationalStatus === "open"),
        patients,
    };
};

const getLiveTrackingCategory = (shift, now = new Date(), gracePeriodMinutes = 15) => {
    const state = getEffectiveShiftState(shift, now, gracePeriodMinutes);

    if (isEmergencyTrackingShift(shift)) {
        return "emergency_alert";
    }
    if (state === "break") {
        return "break";
    }
    if (state === "completed") {
        return "finished";
    }
    if (state === "running_late") {
        return "running_late";
    }
    if (state === "clocked_in") {
        return "clocked_in";
    }
    if (state === "missed" || state === "attendance_exception") {
        return state;
    }
    if (state === "cancelled") {
        return "cancelled";
    }
    return state;
};

const getLiveTrackingModuleData = async () => {
    const now = new Date();
    const today = getBusinessDateKey(now);
    const gracePeriodMinutes = 15;
    const escalationMinutes = 30;

    const shiftRows = await allDb(`
        SELECT ss.*,
               p.home_care_client_id,
               COALESCE(p.first_name || ' ' || p.last_name, ss.external_client_label, 'Home Care Client') AS home_care_client_name,
               COALESCE(ss.external_client_label, ca.organization_name, p.first_name || ' ' || p.last_name, 'Client') AS patient_name,
               ca.organization_name AS facility_name,
               ca.organization_type AS facility_type,
               ca.facility_id,
               COALESCE(ss.location_address, ca.address_line_1, p.address, '') AS location_address,
               COALESCE(ss.location_county, ca.county, p.county, '') AS location_county,
               COALESCE(ss.location_eircode, ca.eircode, p.eircode, '') AS location_eircode,
               COALESCE(ss.external_latitude, p.latitude, ca.gps_latitude) AS latitude,
               COALESCE(ss.external_longitude, p.longitude, ca.gps_longitude) AS longitude,
               COALESCE(ss.external_geofence_radius_meters, p.geofence_radius_meters, 120) AS geofence_radius_meters,
               s.id AS staff_profile_id,
               s.id AS staff_identifier,
               COALESCE(s.first_name || ' ' || s.last_name, s.name, 'Unassigned') AS staff_name,
               s.status AS staff_status,
               COALESCE(s.role, ss.role_required, 'Care Worker') AS staff_role,
               COALESCE(s.phone, '') AS staff_phone,
               COALESCE(s.profile_photo, '') AS staff_photo
        FROM staff_shifts ss
        LEFT JOIN patients p ON p.id = ss.patient_id
        LEFT JOIN client_accounts ca ON ca.id = ss.client_account_id
        LEFT JOIN staff s ON s.id = ss.staff_id
        WHERE COALESCE(ss.is_open, 0) = 0
        ORDER BY ss.scheduled_start ASC
    `);

    const records = shiftRows
        .map((shift) => {
            const mapped = mapShiftRow(shift, now, gracePeriodMinutes);
            const category = getLiveTrackingCategory(shift, now, gracePeriodMinutes);
            const scheduledStartValue = mapped.scheduledStart || mapped.shift_date || "";
            const scheduledEndValue = mapped.scheduledEnd || "";
            const scheduledStart = scheduledStartValue ? new Date(normalizeDateTimeString(scheduledStartValue)) : null;
            const scheduledEnd = scheduledEndValue ? new Date(normalizeDateTimeString(scheduledEndValue)) : null;
            const hasValidStart = scheduledStart && !Number.isNaN(scheduledStart.getTime());
            const hasGps = Number.isFinite(Number(mapped.latitude)) && Number.isFinite(Number(mapped.longitude));
            const minutesLate = category === "running_late" && hasValidStart
                ? Math.max(0, Math.floor((now.getTime() - (scheduledStart.getTime() + gracePeriodMinutes * 60 * 1000)) / 60000))
                : 0;
            const countdownMinutes = !mapped.actual_clock_in && hasValidStart
                ? Math.max(0, Math.floor((scheduledStart.getTime() - now.getTime()) / 60000))
                : null;

            return {
                ...mapped,
                category,
                displayStatus: category === "on_duty" ? "On Duty"
                    : category === "clocked_in" ? "Clocked In"
                        : category === "running_late" ? "Running Late"
                            : category === "not_clocked_in" ? "Not Clocked In"
                                : category === "finished" ? "Finished"
                                    : category === "break" ? "Break"
                                        : category === "emergency_alert" ? "Emergency Alert"
                                            : category === "cancelled" ? "Cancelled" : "Scheduled",
                isEscalated: category === "running_late" && minutesLate >= escalationMinutes,
                minutesLate,
                countdownMinutes,
                scheduledStartIso: hasValidStart ? scheduledStart.toISOString() : "",
                scheduledEndIso: scheduledEnd && !Number.isNaN(scheduledEnd.getTime()) ? scheduledEnd.toISOString() : "",
                hasGps,
                gpsStatus: hasGps ? "Live GPS" : "GPS issue",
                gpsIssue: !hasGps,
                shiftTypeLabel: mapped.serviceDivision === "agency-staffing" ? "Agency" : "Home Care",
                entityName: mapped.serviceDivision === "agency-staffing" ? mapped.facilityName : mapped.homeCareClientName,
                facilityCategory: String(mapped.facility_type || mapped.facilityType || mapped.serviceType || "community").toLowerCase(),
                staffProfileId: mapped.staffId || shift.staff_profile_id || null,
                staffIdentifier: String(shift.staff_identifier || mapped.staffId || "").trim(),
                staffPhone: String(shift.staff_phone || "").trim(),
                staffPhoto: String(shift.staff_photo || "").trim(),
                phoneAvailable: Boolean(String(shift.staff_phone || "").trim()),
                locationAddress: mapped.address || "",
                locationCounty: mapped.county || "",
                clientConfirmation: String(shift.client_confirmation || "Pending"),
                managerApprovalStatus: String(shift.manager_approval_status || "Pending"),
                leftEarly: Boolean(mapped.actual_clock_out && mapped.scheduledEnd && new Date(normalizeDateTimeString(mapped.actual_clock_out)).getTime() < new Date(normalizeDateTimeString(mapped.scheduledEnd)).getTime()),
            };
        })
        .filter((row) => getShiftBusinessDateKey(row) === today && isActiveLiveTrackingShift(row));

    const counts = {
        on_duty: records.filter((row) => row.category === "on_duty" || row.category === "clocked_in" || row.category === "break").length,
        clocked_in: records.filter((row) => row.category === "clocked_in").length,
        running_late: records.filter((row) => row.category === "running_late").length,
        not_clocked_in: records.filter((row) => row.category === "not_clocked_in").length,
        finished: records.filter((row) => row.category === "finished").length,
        break: records.filter((row) => row.category === "break").length,
        emergency_alert: records.filter((row) => row.category === "emergency_alert").length,
        gps_issues: records.filter((row) => row.gpsIssue).length,
    };

    return {
        generatedAt: now.toISOString(),
        todayLabel: now.toLocaleDateString("en-IE", { weekday: "long", day: "numeric", month: "long" }),
        todayDate: today,
        gracePeriodMinutes,
        escalationMinutes,
        records,
        counts,
    };
};

const getAttendanceModuleData = async (query) => {
    const now = new Date();
    const selectedDate = String(query.date || getBusinessDateKey(now)).trim();
    const statusFilter = String(query.status || "all").trim().toLowerCase();
    const divisionFilter = String(query.division || "all").trim().toLowerCase();
    const searchTerm = String(query.q || "").trim().toLowerCase();

    const records = await allDb(`
        SELECT ss.*,
               COALESCE(ss.external_client_label, ca.organization_name, p.first_name || ' ' || p.last_name, 'Client') AS patient_name,
               p.home_care_client_id,
               ca.facility_id,
               ca.organization_name AS facility_name,
               s.first_name || ' ' || s.last_name AS staff_name
        FROM staff_shifts ss
        LEFT JOIN patients p ON p.id = ss.patient_id
        LEFT JOIN client_accounts ca ON ca.id = ss.client_account_id
        LEFT JOIN staff s ON s.id = ss.staff_id
        WHERE date(ss.scheduled_start) = ? OR date(ss.shift_date) = ?
        ORDER BY ss.scheduled_start ASC
    `, [selectedDate, selectedDate]);

    const normalizedRecords = records.map((row) => {
        const effectiveStatus = getEffectiveShiftState(row, now, 15);
        const attendanceStatus = effectiveStatus === "completed" ? "completed"
            : effectiveStatus === "clocked_in" || effectiveStatus === "break" ? "on_duty"
               : effectiveStatus === "missed" ? "no_show"
                   : effectiveStatus;
        const mapped = mapShiftRow(row, now, 15);
        return {
            ...row,
            staff_name: formatStaffDisplayName(row.staff_name, row.staff_status),
            status: effectiveStatus,
            status_label: mapped.statusLabel,
            status_class: mapped.statusClass,
            attendance_status: attendanceStatus,
            attendance_division: getShiftDivision(row),
        };
    });

    const filteredRecords = normalizedRecords.filter((row) => {
        if (statusFilter !== "all" && row.attendance_status !== statusFilter) {
            return false;
        }
        if (divisionFilter !== "all" && row.attendance_division !== divisionFilter) {
            return false;
        }
        if (!searchTerm) {
            return true;
        }
        const searchText = [
            row.staff_name,
            row.patient_name,
            row.home_care_client_id,
            row.facility_id,
            row.facility_name,
            row.shift_code,
            row.status,
        ].join(" ").toLowerCase();
        return searchText.includes(searchTerm);
    });

    const clockedIn = filteredRecords.filter((row) => row.actual_clock_in).length;
    const clockedOut = filteredRecords.filter((row) => row.actual_clock_out).length;
    const missed = filteredRecords.filter((row) => row.status === "missed").length;
    let totalMins = 0;
    for (const record of filteredRecords) {
        if (record.actual_clock_in && record.actual_clock_out) {
            totalMins += Math.round((new Date(record.actual_clock_out) - new Date(record.actual_clock_in)) / 60000);
        }
    }
    const late = filteredRecords.filter((record) => {
        if (record.actual_clock_in && record.scheduled_start) {
            return new Date(record.actual_clock_in) > new Date(record.scheduled_start.replace(" ", "T"));
        }
        return record.status === "running_late";
    }).length;

    return {
        records: filteredRecords,
        selectedDate,
        filters: {
            status: statusFilter,
            division: divisionFilter,
            q: String(query.q || "").trim(),
        },
        stats: {
            clockedIn,
            clockedOut,
            late,
            missed,
            totalHours: (totalMins / 60).toFixed(1),
        },
    };
};

const getReportsModuleData = async () => {
    const [allShiftsRow, homeCareRow, agencyRow, openRow, inProgressRow, completedRow] = await Promise.all([
        getDb("SELECT COUNT(*) AS count FROM staff_shifts"),
        getDb("SELECT COUNT(*) AS count FROM staff_shifts WHERE COALESCE(service_division, 'home-care') = 'home-care'"),
        getDb("SELECT COUNT(*) AS count FROM staff_shifts WHERE COALESCE(service_division, 'home-care') = 'agency-staffing'"),
        getAvailableOpenShiftCount().then((count) => ({ count })),
        getDb("SELECT COUNT(*) AS count FROM staff_shifts WHERE status IN ('clocked_in', 'on_break')"),
        getDb("SELECT COUNT(*) AS count FROM staff_shifts WHERE status IN ('completed', 'clocked_out')"),
    ]);
    return {
        shiftSummary: {
            all: Number(allShiftsRow ? allShiftsRow.count : 0),
            homeCare: Number(homeCareRow ? homeCareRow.count : 0),
            agency: Number(agencyRow ? agencyRow.count : 0),
            open: Number(openRow ? openRow.count : 0),
            inProgress: Number(inProgressRow ? inProgressRow.count : 0),
            completed: Number(completedRow ? completedRow.count : 0),
        },
    };
};

const getHomeCareClientsModuleData = async () => {
    const patients = (await allDb("SELECT * FROM patients WHERE COALESCE(is_archived, 0) = 0 ORDER BY last_name, first_name, id")).map(mapPatientRow);
    const assignmentRows = await allDb(
        `SELECT pa.patient_id, pa.assignment_role, s.first_name, s.last_name, s.name
         FROM patient_assignments pa
         LEFT JOIN staff s ON s.id = pa.staff_id`
    );
    const assignmentsByPatientId = assignmentRows.reduce((accumulator, row) => {
        const key = Number(row.patient_id);
        if (!accumulator[key]) {
            accumulator[key] = [];
        }
        accumulator[key].push({
            assignmentRole: row.assignment_role,
            staffName: row.name || formatName(row.first_name, row.last_name),
        });
        return accumulator;
    }, {});
    const enrichedPatients = patients.map((patient) => ({
        ...patient,
        assignments: assignmentsByPatientId[patient.id] || [],
    }));
    return {
        patients: enrichedPatients,
        summary: {
            total: enrichedPatients.length,
        },
    };
};

const getHomeVisitModuleData = async (query) => {
    const filter = String(query.filter || "today").trim().toLowerCase();
    const fromDate = String(query.date_from || "").trim();
    const toDate = String(query.date_to || "").trim();
    const today = new Date();
    const todayKey = getBusinessDateKey(today);
    const tomorrow = new Date(today.getTime() + 24 * 60 * 60 * 1000);
    const tomorrowKey = getBusinessDateKey(tomorrow);
    const weekStart = new Date(today);
    weekStart.setDate(today.getDate() - today.getDay());
    const weekEnd = new Date(weekStart);
    weekEnd.setDate(weekStart.getDate() + 6);
    const weekStartKey = getBusinessDateKey(weekStart);
    const weekEndKey = getBusinessDateKey(weekEnd);

    const shiftRows = await allDb(`
        SELECT ss.*,
               p.home_care_client_id,
               COALESCE(p.first_name || ' ' || p.last_name, ss.external_client_label, 'Home Care Client') AS home_care_client_name,
               s.first_name || ' ' || s.last_name AS staff_name,
               s.status AS staff_status
        FROM staff_shifts ss
        LEFT JOIN patients p ON p.id = ss.patient_id
        LEFT JOIN staff s ON s.id = ss.staff_id
        WHERE COALESCE(ss.service_division, 'home-care') = 'home-care'
          AND COALESCE(ss.is_open, 0) = 0
        ORDER BY ss.scheduled_start ASC
    `);
    const shifts = shiftRows.map(mapShiftRow);

    const filteredVisits = shifts.filter((shift) => {
        const shiftDate = getShiftBusinessDateKey(shift);
        const status = String(shift.operationalStatus || "").toLowerCase();
        if (fromDate || toDate) {
            if (!isDateWithinRange(shiftDate, fromDate, toDate)) {
                return false;
            }
        }
        if (filter === "tomorrow") {
            return shiftDate === tomorrowKey;
        }
        if (filter === "this_week") {
            return shiftDate >= weekStartKey && shiftDate <= weekEndKey;
        }
        if (filter === "missed") {
            return status === "missed";
        }
        if (filter === "completed") {
            return status === "completed";
        }
        if (filter === "cancelled") {
            return status === "cancelled";
        }
        return shiftDate === todayKey && isCountableTodayShift(shift);
    });

    const todayVisits = shifts.filter((shift) => getShiftBusinessDateKey(shift) === todayKey);
    const countableTodayVisits = todayVisits.filter(isCountableTodayShift);
    const summary = {
        today: countableTodayVisits.length,
        completed: todayVisits.filter((shift) => shift.operationalStatus === "completed").length,
        outstanding: todayVisits.filter((shift) => ["scheduled", "open", "not_clocked_in", "running_late", "on_duty", "break"].includes(shift.operationalStatus)).length,
        missed: todayVisits.filter((shift) => shift.operationalStatus === "missed").length,
        cancelled: todayVisits.filter((shift) => shift.operationalStatus === "cancelled").length,
    };

    return {
        filter,
        fromDate,
        toDate,
        visits: filteredVisits,
        summary,
    };
};

const getFacilityModuleData = async () => {
    const facilities = (await allDb(`
        SELECT *
        FROM client_accounts
        ORDER BY organization_name ASC, created_at DESC
    `)).map(mapClientAccountRow);
    return {
        facilities,
        summary: {
            total: facilities.length,
            pending: facilities.filter((facility) => facility.status === "pending").length,
            approved: facilities.filter((facility) => facility.status === "approved").length,
            suspended: facilities.filter((facility) => facility.status === "suspended").length,
        },
    };
};

const getFacilityPortalModuleData = async () => {
    const registrations = (await allDb(`
        SELECT *
        FROM client_accounts
        ORDER BY created_at DESC
    `)).map(mapClientAccountRow);
    return {
        registrations,
        summary: {
            pendingApprovals: registrations.filter((registration) => ["pending", "more_info_requested"].includes(String(registration.status || ""))).length,
            approvedAccounts: registrations.filter((registration) => String(registration.status || "") === "approved").length,
            suspendedAccounts: registrations.filter((registration) => String(registration.status || "") === "suspended").length,
        },
    };
};

const getShiftRequestsModuleData = async () => {
    const requests = (await allDb(`
        SELECT csr.*, ca.organization_name, ca.contact_first_name, ca.contact_last_name, ca.email,
               s.name AS assigned_staff_name, s.role AS assigned_staff_role, s.profile_photo AS assigned_staff_photo,
               s.experience_years AS assigned_staff_experience_years, s.qqi_qualifications AS assigned_staff_qqi_qualifications,
               s.nmbi_number AS assigned_staff_nmbi_number, s.mandatory_training AS assigned_staff_mandatory_training,
               s.additional_certifications AS assigned_staff_additional_certifications, s.languages AS assigned_staff_languages
        FROM client_service_requests csr
        INNER JOIN client_accounts ca ON ca.id = csr.client_account_id
        LEFT JOIN staff s ON s.id = csr.assigned_staff_id
        ORDER BY csr.created_at DESC
    `)).map(mapClientRequestRow);
    const staff = (await allDb("SELECT id, first_name, last_name, name, role, status FROM staff ORDER BY first_name, last_name")).map(mapStaffRow);
    return {
        requests,
        staff,
        summary: {
            total: requests.length,
            pending: requests.filter((request) => ["pending_review", "reviewing", "request_more_information"].includes(String(request.status || ""))).length,
            awaitingStaff: requests.filter((request) => String(request.status || "") === "awaiting_staff").length,
            confirmed: requests.filter((request) => ["accepted", "confirmed", "checked_in", "on_break"].includes(String(request.status || ""))).length,
        },
    };
};

const getCareReviewsModuleData = async () => {
    const rows = await allDb(`
        SELECT cr.*,
               p.home_care_client_id,
               COALESCE(p.first_name || ' ' || p.last_name, p.name, 'Home Care Client') AS patient_name,
               s.first_name || ' ' || s.last_name AS reviewer_name
        FROM care_reviews cr
        INNER JOIN patients p ON p.id = cr.patient_id
        LEFT JOIN staff s ON s.id = cr.reviewer_staff_id
        WHERE COALESCE(p.is_archived, 0) = 0
        ORDER BY cr.due_date ASC, cr.created_at DESC
    `);
    const staff = (await allDb("SELECT id, first_name, last_name, name, role, status FROM staff WHERE lower(status) = 'active' ORDER BY first_name, last_name")).map(mapStaffRow);
    const clients = (await allDb("SELECT id, first_name, last_name, home_care_client_id FROM patients WHERE COALESCE(is_archived, 0) = 0 ORDER BY first_name, last_name")).map(mapPatientRow);
    const todayKey = new Date().toISOString().slice(0, 10);
    const summary = {
        upcoming: rows.filter((row) => String(row.status || "") === "upcoming" && String(row.due_date || "") >= todayKey).length,
        completed: rows.filter((row) => String(row.status || "") === "completed").length,
        overdue: rows.filter((row) => String(row.status || "") !== "completed" && String(row.due_date || "") < todayKey).length,
        risk: rows.filter((row) => String(row.review_type || "") === "risk").length,
        medication: rows.filter((row) => String(row.review_type || "") === "medication").length,
    };
    return { reviews: rows, staff, clients, summary };
};

// === PAYROLL ENGINE ===

const IRISH_BANK_HOLIDAYS = new Set([
    // 2025
    "2025-01-01","2025-02-03","2025-03-17","2025-04-21","2025-05-05",
    "2025-06-02","2025-08-04","2025-10-27","2025-12-25","2025-12-26",
    // 2026
    "2026-01-01","2026-02-02","2026-03-17","2026-04-06","2026-05-04",
    "2026-06-01","2026-08-03","2026-10-26","2026-12-25","2026-12-28",
    // 2027
    "2027-01-01","2027-02-01","2027-03-17","2027-04-05","2027-05-03",
    "2027-06-07","2027-08-02","2027-10-25","2027-12-27","2027-12-28",
]);

const PAYROLL_RATES = {
    nightPremium: 0.25,    // +25% for 22:00-08:00
    weekendPremium: 0.25,  // +25% for Sat/Sun
    bankHolidayPremium: 0.50, // +50% for bank holidays
    overtimePremium: 0.50, // +50% above threshold
    overtimeWeeklyHours: 39,
    mileageRatePerKm: 0.25, // €0.25/km
};
const PAYROLL_SETTING_KEYS = {
    nightPremium: "payroll.nightPremium",
    weekendPremium: "payroll.weekendPremium",
    bankHolidayPremium: "payroll.bankHolidayPremium",
    overtimePremium: "payroll.overtimePremium",
    overtimeWeeklyHours: "payroll.overtimeWeeklyHours",
    mileageRatePerKm: "payroll.mileageRatePerKm",
};
const roundPayrollNumber = (value, decimals = 2) => {
    const parsed = Number(value || 0);
    if (!Number.isFinite(parsed)) {
        return 0;
    }
    const factor = 10 ** decimals;
    return Math.round(parsed * factor) / factor;
};

const parseNonNegativeNumber = (value, fallback = 0) => {
    if (value === null || value === undefined || String(value).trim() === "") {
        return fallback;
    }
    const parsed = Number(value);
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
};

const getDefaultPayrollSettings = () => ({ ...PAYROLL_RATES });

const getPayrollSettings = async () => {
    const keys = Object.values(PAYROLL_SETTING_KEYS);
    const placeholders = keys.map(() => "?").join(", ");
    const rows = await allDb(`SELECT key, value FROM system_settings WHERE key IN (${placeholders})`, keys);
    const rowMap = new Map(rows.map((row) => [String(row.key || ""), row.value]));
    const defaults = getDefaultPayrollSettings();
    return {
        nightPremium: parseNonNegativeNumber(rowMap.get(PAYROLL_SETTING_KEYS.nightPremium), defaults.nightPremium),
        weekendPremium: parseNonNegativeNumber(rowMap.get(PAYROLL_SETTING_KEYS.weekendPremium), defaults.weekendPremium),
        bankHolidayPremium: parseNonNegativeNumber(rowMap.get(PAYROLL_SETTING_KEYS.bankHolidayPremium), defaults.bankHolidayPremium),
        overtimePremium: parseNonNegativeNumber(rowMap.get(PAYROLL_SETTING_KEYS.overtimePremium), defaults.overtimePremium),
        overtimeWeeklyHours: parseNonNegativeNumber(rowMap.get(PAYROLL_SETTING_KEYS.overtimeWeeklyHours), defaults.overtimeWeeklyHours),
        mileageRatePerKm: parseNonNegativeNumber(rowMap.get(PAYROLL_SETTING_KEYS.mileageRatePerKm), defaults.mileageRatePerKm),
    };
};

const savePayrollSettings = async (settings) => {
    const normalized = {
        nightPremium: roundPayrollNumber(parseNonNegativeNumber(settings.nightPremium, PAYROLL_RATES.nightPremium), 4),
        weekendPremium: roundPayrollNumber(parseNonNegativeNumber(settings.weekendPremium, PAYROLL_RATES.weekendPremium), 4),
        bankHolidayPremium: roundPayrollNumber(parseNonNegativeNumber(settings.bankHolidayPremium, PAYROLL_RATES.bankHolidayPremium), 4),
        overtimePremium: roundPayrollNumber(parseNonNegativeNumber(settings.overtimePremium, PAYROLL_RATES.overtimePremium), 4),
        overtimeWeeklyHours: roundPayrollNumber(parseNonNegativeNumber(settings.overtimeWeeklyHours, PAYROLL_RATES.overtimeWeeklyHours), 2),
        mileageRatePerKm: roundPayrollNumber(parseNonNegativeNumber(settings.mileageRatePerKm, PAYROLL_RATES.mileageRatePerKm), 4),
    };

    for (const [settingName, settingKey] of Object.entries(PAYROLL_SETTING_KEYS)) {
        await runDb(
            `INSERT INTO system_settings (key, value, updated_at)
             VALUES (?, ?, CURRENT_TIMESTAMP)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP`,
            [settingKey, String(normalized[settingName])]
        );
    }

    return normalized;
};

const recalculatePayrollSnapshot = (snapshot = {}) => {
    const shiftItems = Array.isArray(snapshot.shiftItems)
        ? snapshot.shiftItems.map((item) => ({
            shiftId: Number(item.shiftId || 0),
            shiftCode: String(item.shiftCode || "").trim(),
            date: String(item.date || item.scheduledStart || "").slice(0, 10),
            assignmentName: String(item.assignmentName || "").trim(),
            division: String(item.division || "").trim(),
            shiftType: String(item.shiftType || "day").trim(),
            hours: roundPayrollNumber(parseNonNegativeNumber(item.hours, 0), 4),
            breakMinutes: roundPayrollNumber(parseNonNegativeNumber(item.breakMinutes, 0), 2),
            payRate: roundPayrollNumber(parseNonNegativeNumber(item.payRate, 0), 4),
            payRateSource: String(item.payRateSource || "").trim(),
            base: roundPayrollNumber(parseNonNegativeNumber(item.base, 0), 2),
            premium: roundPayrollNumber(parseNonNegativeNumber(item.premium, 0), 2),
            overtimeHours: roundPayrollNumber(parseNonNegativeNumber(item.overtimeHours, 0), 4),
            overtimePremium: roundPayrollNumber(parseNonNegativeNumber(item.overtimePremium, 0), 2),
            gross: roundPayrollNumber(parseNonNegativeNumber(item.gross, 0), 2),
        }))
        : [];
    const normalized = {
        staffId: Number(snapshot.staffId || 0),
        staffName: String(snapshot.staffName || snapshot.name || "Staff Member").trim() || "Staff Member",
        staffRole: String(snapshot.staffRole || snapshot.role || "").trim(),
        staffEmployeeNumber: String(snapshot.staffEmployeeNumber || "").trim(),
        paymentDate: String(snapshot.paymentDate || "").trim().slice(0, 10),
        notes: String(snapshot.notes || "").trim(),
        basicHours: roundPayrollNumber(parseNonNegativeNumber(snapshot.basicHours, snapshot.dayHours || 0), 2),
        nightHours: roundPayrollNumber(parseNonNegativeNumber(snapshot.nightHours, 0), 2),
        weekendHours: roundPayrollNumber(parseNonNegativeNumber(snapshot.weekendHours, 0), 2),
        bankHolidayHours: roundPayrollNumber(parseNonNegativeNumber(snapshot.bankHolidayHours, 0), 2),
        overtimeHours: roundPayrollNumber(parseNonNegativeNumber(snapshot.overtimeHours, 0), 2),
        mileageKm: roundPayrollNumber(parseNonNegativeNumber(snapshot.mileageKm, 0), 2),
        mileageRate: roundPayrollNumber(parseNonNegativeNumber(snapshot.mileageRate, PAYROLL_RATES.mileageRatePerKm), 4),
        basicRate: roundPayrollNumber(parseNonNegativeNumber(snapshot.basicRate, snapshot.hourlyRate || 0), 4),
        nightRate: roundPayrollNumber(parseNonNegativeNumber(snapshot.nightRate, snapshot.hourlyRate || 0), 4),
        weekendRate: roundPayrollNumber(parseNonNegativeNumber(snapshot.weekendRate, snapshot.hourlyRate || 0), 4),
        bankHolidayRate: roundPayrollNumber(parseNonNegativeNumber(snapshot.bankHolidayRate, snapshot.hourlyRate || 0), 4),
        overtimeRate: roundPayrollNumber(parseNonNegativeNumber(snapshot.overtimeRate, 0), 4),
        payeTax: roundPayrollNumber(parseNonNegativeNumber(snapshot.payeTax, snapshot.estimatedTax || 0), 2),
        prsiAmount: roundPayrollNumber(parseNonNegativeNumber(snapshot.prsiAmount, 0), 2),
        uscAmount: roundPayrollNumber(parseNonNegativeNumber(snapshot.uscAmount, 0), 2),
        homeCareHours: roundPayrollNumber(parseNonNegativeNumber(snapshot.homeCareHours, 0), 2),
        agencyHours: roundPayrollNumber(parseNonNegativeNumber(snapshot.agencyHours, 0), 2),
        shiftCount: shiftItems.length || Number(snapshot.shiftCount || 0),
        shiftItems,
    };

    const hasShiftItems = shiftItems.length > 0;
    const basicPay = roundPayrollNumber(hasShiftItems
        ? shiftItems.filter((item) => item.shiftType === "day").reduce((sum, item) => sum + item.base + item.premium, 0)
        : normalized.basicHours * normalized.basicRate, 2);
    const nightPay = roundPayrollNumber(hasShiftItems
        ? shiftItems.filter((item) => item.shiftType === "night").reduce((sum, item) => sum + item.base + item.premium, 0)
        : normalized.nightHours * normalized.nightRate, 2);
    const weekendPay = roundPayrollNumber(hasShiftItems
        ? shiftItems.filter((item) => item.shiftType === "weekend").reduce((sum, item) => sum + item.base + item.premium, 0)
        : normalized.weekendHours * normalized.weekendRate, 2);
    const bankHolidayPay = roundPayrollNumber(hasShiftItems
        ? shiftItems.filter((item) => item.shiftType === "bank_holiday").reduce((sum, item) => sum + item.base + item.premium, 0)
        : normalized.bankHolidayHours * normalized.bankHolidayRate, 2);
    const overtimePay = roundPayrollNumber(hasShiftItems
        ? shiftItems.reduce((sum, item) => sum + item.overtimePremium, 0)
        : normalized.overtimeHours * normalized.overtimeRate, 2);
    const mileagePayment = roundPayrollNumber(normalized.mileageKm * normalized.mileageRate, 2);
    const grossPay = roundPayrollNumber(basicPay + nightPay + weekendPay + bankHolidayPay + overtimePay + mileagePayment, 2);
    const totalDeductions = roundPayrollNumber(normalized.payeTax + normalized.prsiAmount + normalized.uscAmount, 2);
    const netPay = roundPayrollNumber(grossPay - totalDeductions, 2);
    const totalHours = roundPayrollNumber(hasShiftItems
        ? shiftItems.reduce((sum, item) => sum + item.hours, 0)
        : normalized.basicHours + normalized.nightHours + normalized.weekendHours + normalized.bankHolidayHours, 2);
    const regularHours = roundPayrollNumber(Math.max(0, totalHours - normalized.overtimeHours), 2);

    return {
        ...normalized,
        basicPay,
        nightPay,
        weekendPay,
        bankHolidayPay,
        overtimePay,
        mileagePayment,
        grossPay,
        totalDeductions,
        netPay,
        totalHours,
        regularHours,
        dayHours: normalized.basicHours,
        hourlyRate: normalized.basicRate,
        estimatedTax: normalized.payeTax,
        overtimePremium: overtimePay,
    };
};

const buildPayrollSnapshotFromStaffRow = (staffRow = {}, payrollSettings = PAYROLL_RATES, overrides = {}) => {
    const hourlyRate = parseNonNegativeNumber(overrides.basicRate, staffRow.hourlyRate || 0);
    const grossPay = parseNonNegativeNumber(staffRow.grossPay, 0);
    const snapshot = {
        staffId: staffRow.staffId || overrides.staffId || 0,
        staffName: overrides.staffName !== undefined ? overrides.staffName : (staffRow.staffName || staffRow.name || "Staff Member"),
        staffRole: overrides.staffRole !== undefined ? overrides.staffRole : (staffRow.staffRole || staffRow.role || ""),
        staffEmployeeNumber: overrides.staffEmployeeNumber !== undefined ? overrides.staffEmployeeNumber : (staffRow.staffEmployeeNumber || ""),
        paymentDate: overrides.paymentDate || staffRow.paymentDate || "",
        notes: overrides.notes !== undefined ? overrides.notes : (staffRow.notes || ""),
        basicHours: overrides.basicHours !== undefined ? overrides.basicHours : (staffRow.dayHours || 0),
        nightHours: overrides.nightHours !== undefined ? overrides.nightHours : (staffRow.nightHours || 0),
        weekendHours: overrides.weekendHours !== undefined ? overrides.weekendHours : (staffRow.weekendHours || 0),
        bankHolidayHours: overrides.bankHolidayHours !== undefined ? overrides.bankHolidayHours : (staffRow.bankHolidayHours || 0),
        overtimeHours: overrides.overtimeHours !== undefined ? overrides.overtimeHours : (staffRow.overtimeHours || 0),
        mileageKm: overrides.mileageKm !== undefined ? overrides.mileageKm : (staffRow.mileageKm || 0),
        mileageRate: overrides.mileageRate !== undefined ? overrides.mileageRate : payrollSettings.mileageRatePerKm,
        basicRate: hourlyRate,
        nightRate: overrides.nightRate !== undefined ? overrides.nightRate : hourlyRate * (1 + payrollSettings.nightPremium),
        weekendRate: overrides.weekendRate !== undefined ? overrides.weekendRate : hourlyRate * (1 + payrollSettings.weekendPremium),
        bankHolidayRate: overrides.bankHolidayRate !== undefined ? overrides.bankHolidayRate : hourlyRate * (1 + payrollSettings.bankHolidayPremium),
        overtimeRate: overrides.overtimeRate !== undefined ? overrides.overtimeRate : hourlyRate * payrollSettings.overtimePremium,
        payeTax: overrides.payeTax !== undefined ? overrides.payeTax : (staffRow.estimatedTax || 0),
        prsiAmount: overrides.prsiAmount !== undefined ? overrides.prsiAmount : (staffRow.prsiAmount || 0),
        uscAmount: overrides.uscAmount !== undefined ? overrides.uscAmount : (staffRow.uscAmount || 0),
        homeCareHours: overrides.homeCareHours !== undefined ? overrides.homeCareHours : (staffRow.homeCareHours || 0),
        agencyHours: overrides.agencyHours !== undefined ? overrides.agencyHours : (staffRow.agencyHours || 0),
        shiftCount: overrides.shiftCount !== undefined ? overrides.shiftCount : (Array.isArray(staffRow.shifts) ? staffRow.shifts.length : 0),
        shiftItems: Array.isArray(staffRow.shifts) ? staffRow.shifts : [],
    };
    return recalculatePayrollSnapshot(snapshot);
};

const getPayrollSnapshotForRecord = (payrollRecord, staffRow, payrollSettings = PAYROLL_RATES) => {
    const baseSnapshot = buildPayrollSnapshotFromStaffRow(staffRow, payrollSettings, {
        paymentDate: payrollRecord ? payrollRecord.payment_date || "" : "",
        notes: payrollRecord ? payrollRecord.notes || "" : "",
    });
    if (!payrollRecord || !payrollRecord.snapshot_json) {
        return baseSnapshot;
    }
    const storedSnapshot = parseJsonObjectField(payrollRecord.snapshot_json);
    return recalculatePayrollSnapshot({
        ...baseSnapshot,
        ...storedSnapshot,
        paymentDate: storedSnapshot.paymentDate || payrollRecord.payment_date || baseSnapshot.paymentDate,
        notes: storedSnapshot.notes !== undefined ? storedSnapshot.notes : (payrollRecord.notes || baseSnapshot.notes),
    });
};

const buildPayslipEarningsRows = (snapshot) => {
    if (Array.isArray(snapshot.shiftItems) && snapshot.shiftItems.length) {
        const rows = snapshot.shiftItems.map((item) => ({
            label: `${item.shiftCode || `Shift ${item.shiftId}`}${item.date ? ` · ${item.date}` : ""}`,
            hours: item.hours,
            rate: item.hours > 0 ? roundPayrollNumber((item.base + item.premium + item.overtimePremium) / item.hours, 4) : item.payRate,
            amount: item.gross,
        }));
        if (snapshot.mileageKm > 0) {
            rows.push({ label: "Mileage", hours: null, rate: snapshot.mileageRate, amount: snapshot.mileagePayment, quantity: snapshot.mileageKm });
        }
        return rows;
    }
    const rows = [];
    if (snapshot.basicHours > 0) rows.push({ label: "Basic Hours", hours: snapshot.basicHours, rate: snapshot.basicRate, amount: snapshot.basicPay });
    if (snapshot.nightHours > 0) rows.push({ label: "Night Hours", hours: snapshot.nightHours, rate: snapshot.nightRate, amount: snapshot.nightPay });
    if (snapshot.weekendHours > 0) rows.push({ label: "Weekend Hours", hours: snapshot.weekendHours, rate: snapshot.weekendRate, amount: snapshot.weekendPay });
    if (snapshot.bankHolidayHours > 0) rows.push({ label: "Bank Holiday Hours", hours: snapshot.bankHolidayHours, rate: snapshot.bankHolidayRate, amount: snapshot.bankHolidayPay });
    if (snapshot.overtimeHours > 0) rows.push({ label: "Overtime Premium", hours: snapshot.overtimeHours, rate: snapshot.overtimeRate, amount: snapshot.overtimePay });
    if (snapshot.mileageKm > 0) rows.push({ label: "Mileage", hours: null, rate: snapshot.mileageRate, amount: snapshot.mileagePayment, quantity: snapshot.mileageKm });
    if (!rows.length) {
        rows.push({ label: "Approved payroll", hours: snapshot.totalHours || null, rate: snapshot.basicRate || null, amount: snapshot.grossPay });
    }
    return rows;
};

const buildPayslipDeductionRows = (snapshot) => ([
    { label: "PAYE (Income Tax)", current: snapshot.payeTax },
    { label: "PRSI (Employee)", current: snapshot.prsiAmount },
    { label: "USC (Universal Social Charge)", current: snapshot.uscAmount },
]);

const applyPayrollSnapshotToStaffRow = (staffRow, snapshot) => ({
    ...staffRow,
    staffName: snapshot.staffName || staffRow.staffName,
    staffRole: snapshot.staffRole || staffRow.staffRole,
    staffEmployeeNumber: snapshot.staffEmployeeNumber || staffRow.staffEmployeeNumber,
    hourlyRate: snapshot.basicRate,
    rateLabel: Array.isArray(snapshot.shiftItems) && new Set(snapshot.shiftItems.map((item) => item.payRate)).size > 1
        ? "Multiple rates"
        : `€${Number(snapshot.basicRate || (Array.isArray(snapshot.shiftItems) && snapshot.shiftItems[0] && snapshot.shiftItems[0].payRate) || 0).toFixed(2)}`,
    dayHours: snapshot.basicHours,
    nightHours: snapshot.nightHours,
    weekendHours: snapshot.weekendHours,
    bankHolidayHours: snapshot.bankHolidayHours,
    overtimeHours: snapshot.overtimeHours,
    totalHours: snapshot.totalHours,
    regularHours: snapshot.regularHours,
    mileageKm: snapshot.mileageKm,
    mileagePayment: snapshot.mileagePayment,
    grossPay: snapshot.grossPay,
    estimatedTax: snapshot.payeTax,
    prsiAmount: snapshot.prsiAmount,
    uscAmount: snapshot.uscAmount,
    totalDeductions: snapshot.totalDeductions,
    netPay: snapshot.netPay,
    baseGross: snapshot.basicPay,
    premiums: snapshot.nightPay + snapshot.weekendPay + snapshot.bankHolidayPay,
    homeCareHours: snapshot.homeCareHours,
    agencyHours: snapshot.agencyHours,
    overtimePremium: snapshot.overtimePay,
    payrollSnapshot: snapshot,
});

const calcShiftHours = (startStr, endStr, breakMinutes = 0) => {
    if (!startStr || !endStr) return 0;
    const start = new Date(String(startStr).replace(" ", "T"));
    const end = new Date(String(endStr).replace(" ", "T"));
    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime()) || end <= start) {
        return 0;
    }
    const workedMinutes = Math.max(0, ((end - start) / 60000) - parseNonNegativeNumber(breakMinutes, 0));
    return roundPayrollNumber(workedMinutes / 60, 4);
};

const classifyShiftType = (shift) => {
    const startStr = shift.actual_clock_in || shift.scheduled_start || "";
    if (!startStr) return "day";
    const dateKey = startStr.slice(0, 10);
    if (IRISH_BANK_HOLIDAYS.has(dateKey)) return "bank_holiday";
    const dow = new Date(`${dateKey}T12:00:00`).getDay(); // 0=Sun, 6=Sat
    if (dow === 0 || dow === 6) return "weekend";
    const hour = Number(String(startStr).slice(11, 13));
    if (hour >= 22 || hour < 8) return "night";
    return "day";
};

const calcShiftEarnings = (shift, payrollSettings = PAYROLL_RATES) => {
    const startStr = shift.actual_clock_in || "";
    const endStr = shift.actual_clock_out || "";
    const totalHours = calcShiftHours(startStr, endStr, shift.break_duration_minutes);
    const type = classifyShiftType(shift);
    const hasFrozenPayRate = shift.pay_rate !== null
        && shift.pay_rate !== undefined
        && String(shift.pay_rate).trim() !== "";
    const payRate = Number(shift.pay_rate);
    if (!hasFrozenPayRate || !Number.isFinite(payRate) || payRate < 0) {
        throw new Error(`Shift ${shift.id || shift.shift_code || "record"} has no frozen pay rate.`);
    }
    const base = roundPayrollNumber(totalHours * payRate, 2);
    let premium = 0;
    if (type === "night") premium = roundPayrollNumber(base * payrollSettings.nightPremium, 2);
    else if (type === "weekend") premium = roundPayrollNumber(base * payrollSettings.weekendPremium, 2);
    else if (type === "bank_holiday") premium = roundPayrollNumber(base * payrollSettings.bankHolidayPremium, 2);
    return { totalHours, type, payRate, base, premium, gross: roundPayrollNumber(base + premium, 2) };
};

const getPayrollPeriodDates = (query) => {
    const today = new Date();
    const todayKey = getBusinessDateKey(today);
    const period = String(query.period || "weekly").toLowerCase();

    if (period === "custom" && query.dateFrom && query.dateTo) {
        return { periodStart: String(query.dateFrom).slice(0, 10), periodEnd: String(query.dateTo).slice(0, 10), period: "custom" };
    }
    if (period === "monthly") {
        return { periodStart: `${todayKey.slice(0, 7)}-01`, periodEnd: getBusinessDateKey(new Date(`${todayKey}T12:00:00`).setMonth(new Date(`${todayKey}T12:00:00`).getMonth() + 1, 0)), period };
    }
    if (period === "fortnightly") {
        const start = new Date(`${todayKey}T12:00:00`);
        start.setDate(start.getDate() - 13);
        return { periodStart: getBusinessDateKey(start), periodEnd: todayKey, period };
    }
    // default: weekly — Mon to Sun of current week
    const businessToday = new Date(`${todayKey}T12:00:00`);
    const dayOfWeek = businessToday.getDay() || 7;
    const monday = new Date(businessToday);
    monday.setDate(businessToday.getDate() - (dayOfWeek - 1));
    const sunday = new Date(monday);
    sunday.setDate(monday.getDate() + 6);
    return { periodStart: getBusinessDateKey(monday), periodEnd: getBusinessDateKey(sunday), period: "weekly" };
};

const getPayrollModuleData = async (query = {}) => {
    const { periodStart, periodEnd, period } = getPayrollPeriodDates(query);
    const divisionFilter = String(query.division || "all").toLowerCase();
    const staffIdFilter = Number(query.staffId || 0);
    const roleFilter = String(query.role || "").trim().toLowerCase();
    const payrollSettings = await getPayrollSettings();

    const periodDays = Math.max(1, Math.round((new Date(periodEnd) - new Date(periodStart)) / 86400000) + 1);
    const overtimeThresholdHours = (periodDays / 7) * payrollSettings.overtimeWeeklyHours;

    let whereClause = "date(COALESCE(ss.scheduled_start, ss.shift_date)) BETWEEN ? AND ? AND ss.staff_id IS NOT NULL";
    const params = [periodStart, periodEnd];

    if (divisionFilter !== "all") {
        whereClause += " AND COALESCE(ss.service_division, 'home-care') = ?";
        params.push(divisionFilter);
    }
    if (staffIdFilter > 0) {
        whereClause += " AND ss.staff_id = ?";
        params.push(staffIdFilter);
    }

    const shiftRows = await allDb(`
        SELECT ss.id, ss.shift_code, ss.staff_id, ss.service_division, ss.status,
               ss.scheduled_start, ss.scheduled_end, ss.actual_clock_in, ss.actual_clock_out,
               ss.break_duration_minutes, ss.mileage_km, ss.payroll_status, ss.pay_rate, ss.pay_rate_source,
               COALESCE(ss.external_client_label, ca.organization_name, p.first_name || ' ' || p.last_name) AS assignment_name,
               p.home_care_client_id, ca.facility_id, ca.organization_name AS facility_name,
               COALESCE(s.first_name || ' ' || s.last_name, s.name, 'Staff member') AS staff_name,
               COALESCE(s.role, 'Staff') AS staff_role,
               s.employee_number AS staff_employee_number,
               COALESCE(NULLIF(s.hourly_rate, ''), '0') AS hourly_rate
        FROM staff_shifts ss
        INNER JOIN staff s ON s.id = ss.staff_id
        LEFT JOIN patients p ON p.id = ss.patient_id
        LEFT JOIN client_accounts ca ON ca.id = ss.client_account_id
        WHERE ${whereClause}
        ORDER BY ss.staff_id ASC, ss.scheduled_start ASC
    `, params);
    const now = new Date();
    const payableShiftRows = shiftRows.filter((row) => getEffectiveShiftState(row, now) === "completed");

    // Fetch existing payroll records for status
    const existingRecords = await allDb(
        "SELECT * FROM payroll_records WHERE period_start = ? AND period_end = ?",
        [periodStart, periodEnd]
    );
    const payrollStatusMap = new Map(existingRecords.map((r) => [Number(r.staff_id), r]));

    // All staff for filter dropdown
    const allStaffRows = await allDb("SELECT id, COALESCE(first_name || ' ' || last_name, name) AS name, role FROM staff ORDER BY name ASC");

    // Group shifts by staff
    const staffMap = new Map();
    for (const row of payableShiftRows) {
        const sId = Number(row.staff_id);
        if (!staffMap.has(sId)) {
            staffMap.set(sId, {
                staffId: sId,
                staffName: row.staff_name,
                staffRole: row.staff_role,
                staffEmployeeNumber: row.staff_employee_number || "",
                hourlyRate: Math.max(0, Number(row.hourly_rate) || 0),
                homeCareHours: 0, agencyHours: 0,
                dayHours: 0, nightHours: 0, weekendHours: 0, bankHolidayHours: 0,
                overtimeHours: 0, regularHours: 0,
                mileageKm: 0, mileagePayment: 0,
                baseGross: 0, premiums: 0, overtimePremium: 0, grossPay: 0,
                estimatedTax: 0, prsiAmount: 0, uscAmount: 0, totalDeductions: 0, netPay: 0,
                rates: new Set(),
                shifts: [],
            });
        }
        const entry = staffMap.get(sId);
        const div = getShiftDivision(row);
        const earnings = calcShiftEarnings(row, payrollSettings);
        const accumulatedHours = entry.homeCareHours + entry.agencyHours;
        const regularCapacity = Math.max(0, overtimeThresholdHours - accumulatedHours);
        const overtimeHours = Math.max(0, earnings.totalHours - regularCapacity);
        const overtimePremium = roundPayrollNumber(overtimeHours * earnings.payRate * payrollSettings.overtimePremium, 2);
        earnings.overtimeHours = overtimeHours;
        earnings.overtimePremium = overtimePremium;
        earnings.gross = roundPayrollNumber(earnings.gross + overtimePremium, 2);
        entry.rates.add(earnings.payRate);

        if (div === "agency-staffing") entry.agencyHours += earnings.totalHours;
        else entry.homeCareHours += earnings.totalHours;

        if (earnings.type === "night") entry.nightHours += earnings.totalHours;
        else if (earnings.type === "weekend") entry.weekendHours += earnings.totalHours;
        else if (earnings.type === "bank_holiday") entry.bankHolidayHours += earnings.totalHours;
        else entry.dayHours += earnings.totalHours;

        const shiftMileage = Math.max(0, Number(row.mileage_km) || 0);
        entry.mileageKm += shiftMileage;
        entry.mileagePayment += shiftMileage * payrollSettings.mileageRatePerKm;
        entry.baseGross += earnings.base;
        entry.premiums += earnings.premium;
        entry.overtimeHours += overtimeHours;
        entry.overtimePremium += overtimePremium;

        entry.shifts.push({
            shiftId: row.id,
            shiftCode: row.shift_code || buildShiftCode(div, row.id),
            division: div,
            assignmentName: row.assignment_name || "—",
            facilityId: row.facility_id || "",
            clientId: row.home_care_client_id || "",
            scheduledStart: row.scheduled_start || "",
            scheduledEnd: row.scheduled_end || "",
            actualClockIn: row.actual_clock_in || "",
            actualClockOut: row.actual_clock_out || "",
            status: "completed",
            hours: earnings.totalHours,
            breakMinutes: parseNonNegativeNumber(row.break_duration_minutes, 0),
            shiftType: earnings.type,
            payRate: earnings.payRate,
            payRateSource: row.pay_rate_source || "staff_rate_at_assignment",
            base: earnings.base,
            premium: earnings.premium,
            overtimeHours,
            overtimePremium,
            gross: earnings.gross,
            mileageKm: shiftMileage,
            mileagePayment: shiftMileage * payrollSettings.mileageRatePerKm,
        });
    }

    // Second pass: calculate overtime and totals
    const staffRows = [];
    for (const [, entry] of staffMap) {
        const totalHours = entry.homeCareHours + entry.agencyHours;
        const overtimeHours = entry.overtimeHours;
        const regularHours = Math.max(0, totalHours - overtimeHours);
        const overtimePremium = entry.overtimePremium;
        const grossPay = roundPayrollNumber(entry.baseGross + entry.premiums + overtimePremium + entry.mileagePayment, 2);
        const estimatedTax = 0;
        const rates = [...entry.rates];
        const hourlyRate = rates.length === 1 ? rates[0] : 0;

        // Skip role filter here (done after because role is on staff not shift)
        if (roleFilter && !entry.staffRole.toLowerCase().includes(roleFilter)) continue;

        const payrollRecord = payrollStatusMap.get(entry.staffId);
        const payrollStatus = payrollRecord ? payrollRecord.status : "draft";
        let staffRow = {
            ...entry,
            totalHours,
            regularHours,
            overtimeHours,
            overtimePremium,
            hourlyRate,
            rateLabel: rates.length > 1 ? "Multiple rates" : `€${hourlyRate.toFixed(2)}`,
            grossPay,
            estimatedTax,
            prsiAmount: 0,
            uscAmount: 0,
            totalDeductions: 0,
            netPay: grossPay,
            payrollStatus,
        };
        if (payrollRecord) {
            const payrollSnapshot = getPayrollSnapshotForRecord(payrollRecord, staffRow, payrollSettings);
            staffRow = applyPayrollSnapshotToStaffRow(staffRow, payrollSnapshot);
        }

        staffRows.push(staffRow);
    }

    // Summary cards
    const totalPayroll = staffRows.reduce((s, r) => s + r.grossPay, 0);
    const homeCarePayroll = staffRows.filter((r) => r.homeCareHours > 0).reduce((s, r) => s + (r.homeCareHours / Math.max(r.totalHours, 1)) * r.grossPay, 0);
    const agencyPayroll = staffRows.filter((r) => r.agencyHours > 0).reduce((s, r) => s + (r.agencyHours / Math.max(r.totalHours, 1)) * r.grossPay, 0);
    const totalMileageClaims = staffRows.reduce((s, r) => s + r.mileagePayment, 0);
    const totalNightPremiums = staffRows.reduce((s, r) => s + (r.nightHours * r.hourlyRate * payrollSettings.nightPremium), 0);
    const totalOvertimeHours = staffRows.reduce((s, r) => s + r.overtimeHours, 0);
    const approvedCount = staffRows.filter((r) => r.payrollStatus === "approved" || r.payrollStatus === "paid").length;
    const pendingCount = staffRows.filter((r) => r.payrollStatus === "draft").length;

    return {
        period,
        periodStart,
        periodEnd,
        payrollSettings,
        staffRows,
        allStaff: allStaffRows,
        filters: {
            division: divisionFilter,
            staffId: staffIdFilter,
            role: roleFilter,
            period,
            dateFrom: query.dateFrom || "",
            dateTo: query.dateTo || "",
        },
        summary: {
            totalPayroll,
            staffAwaitingPayroll: staffRows.length,
            approvedCount,
            pendingCount,
            homeCarePayroll,
            agencyPayroll,
            totalMileageClaims,
            totalNightPremiums,
            totalOvertimeHours,
            estimatedTotal: totalPayroll,
        },
    };
};

const getDuplicateIdentityReport = async () => {
    const [administrators, staffMembers, applications] = await Promise.all([
        allDb("SELECT id, username AS email, phone FROM admin_users WHERE is_active = 1"),
        allDb("SELECT id, email, COALESCE(NULLIF(mobile_number, ''), phone) AS phone FROM staff WHERE COALESCE(is_archived, 0) = 0"),
        allDb("SELECT id, email, phone FROM applications WHERE archived_at IS NULL"),
    ]);
    const records = [
        ...administrators.map((record) => ({ ...record, source: "Administrator" })),
        ...staffMembers.map((record) => ({ ...record, source: "Staff" })),
        ...applications.map((record) => ({ ...record, source: "Application" })),
    ];
    const collect = (field, normalize) => {
        const groups = new Map();
        for (const record of records) {
            const normalized = normalize(record[field]);
            if (!normalized) continue;
            const entries = groups.get(normalized) || [];
            entries.push({ source: record.source, id: record.id });
            groups.set(normalized, entries);
        }
        return [...groups.entries()]
            .filter(([, entries]) => entries.length > 1)
            .map(([normalized, entries]) => ({ normalized, entries }));
    };
    return {
        emails: collect("email", normalizeEmailAddress),
        phones: collect("phone", normalizePhoneForUniqueness),
    };
};

const getSettingsModuleData = async (access) => {
    const canAccess = (permission) => Boolean(access && hasPermission(access.permissions, permission));
    const [adminUsers, activeStaff, auditRows, appStatusRows, payrollSettings, roles, settingRows] = await Promise.all([
        canAccess("users.view")
            ? allDb(
                `SELECT admin_users.id, admin_users.name, admin_users.username AS email,
                        admin_users.phone, admin_users.department, admin_users.is_active, admin_users.last_login,
                        admin_users.created_at, admin_users.auth_version,
                        admin_users.mfa_enabled, admin_users.email_verified,
                        admin_users.phone_verified, admin_users.totp_verified_at,
                        COALESCE(roles.role_key, admin_users.role) AS role,
                        COALESCE(roles.label, admin_users.role) AS role_label
                 FROM admin_users
                 LEFT JOIN user_roles
                    ON user_roles.admin_user_id = admin_users.id
                   AND user_roles.is_primary = 1
                 LEFT JOIN roles ON roles.id = user_roles.role_id
                 ORDER BY admin_users.created_at DESC`
            )
            : Promise.resolve([]),
        getDb("SELECT COUNT(*) AS count FROM staff WHERE lower(COALESCE(status, '')) = 'active'"),
        canAccess("audit.view")
            ? allDb(
                `SELECT actor_type, actor_identifier, actor_role, action, target_type,
                        target_identifier, outcome, reason, metadata, ip_address,
                        user_agent, created_at
                 FROM audit_events
                 ORDER BY created_at DESC LIMIT 50`
            )
            : Promise.resolve([]),
        canAccess("system.manage")
            ? allDb("SELECT CAST(id AS TEXT) AS key, status AS value, updated_at FROM app_status ORDER BY id ASC")
            : Promise.resolve([]),
        getPayrollSettings(),
        canAccess("roles.view")
            ? allDb(
                `SELECT roles.id, roles.role_key, roles.label, roles.description, roles.is_system,
                        GROUP_CONCAT(permissions.permission_key, ',') AS permission_keys
                 FROM roles
                 LEFT JOIN role_permissions ON role_permissions.role_id = roles.id
                 LEFT JOIN permissions ON permissions.id = role_permissions.permission_id
                 GROUP BY roles.id
                 ORDER BY roles.is_system DESC, roles.label ASC`
            )
            : Promise.resolve([]),
        canAccess("settings.view")
            ? allDb("SELECT key, value, updated_at FROM system_settings ORDER BY key")
            : Promise.resolve([]),
    ]);
    const duplicateIdentities = canAccess("security.manage")
        ? await getDuplicateIdentityReport()
        : { emails: [], phones: [] };
    return {
        adminUsers,
        activeStaffCount: Number(activeStaff ? activeStaff.count : 0),
        auditRows,
        appStatusRows,
        payrollSettings,
        roles: roles.map((role) => ({
            ...role,
            permissions: String(role.permission_keys || "").split(",").filter(Boolean),
        })),
        modules: RBAC_MODULES,
        actions: RBAC_ACTIONS,
        settingsValues: Object.fromEntries(settingRows.map((row) => [row.key, row.value])),
        duplicateIdentities,
    };
};

// === PAYSLIP GENERATOR ===

const fmtCurrency = (n) => "€" + Number(n || 0).toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
const fmtDate = (d) => {
    if (!d) return "";
    const dt = new Date(String(d).replace(" ", "T"));
    return isNaN(dt) ? String(d) : dt.toLocaleDateString("en-IE", { day: "2-digit", month: "short", year: "numeric" });
};
const maskPPS = (pps) => {
    if (!pps || pps.length < 4) return "***";
    return "***" + pps.slice(-4).toUpperCase();
};

const generatePayslipPDF = (staffData, periodStart, periodEnd, options = {}) => {
    return new Promise((resolve, reject) => {
        const chunks = [];
        const doc = new PDFDocument({ size: "A4", margin: 40, info: { Title: "Payslip", Author: companyName, Creator: "Everkind Care System" } });
        doc.on("data", (c) => chunks.push(c));
        doc.on("end", () => resolve(Buffer.concat(chunks)));
        doc.on("error", reject);

        const W = doc.page.width - 80; // usable width
        const GREEN = "#1a7c3e";
        const DARK = "#17324b";
        const GREY = "#64748b";
        const LGREY = "#f1f5f9";
        const BLACK = "#0f172a";
        const paymentDate = options.paymentDate || staffData.paymentDate || "";
        const payslipRef = options.payslipRef || "PS-000";
        const payrollSnapshot = buildPayrollSnapshotFromStaffRow(staffData, PAYROLL_RATES, {
            ...staffData,
            paymentDate,
            staffName: staffData.staffName || staffData.name || "Staff Member",
            staffRole: staffData.staffRole || staffData.role || "",
        });
        const earningsRows = buildPayslipEarningsRows(payrollSnapshot);
        const deductionRows = buildPayslipDeductionRows(payrollSnapshot);

        // ─── HEADER ────────────────────────────────────────────────────────────
        doc.rect(40, 40, W, 70).fill(GREEN);
        doc.fillColor("#fff").font("Helvetica-Bold").fontSize(18).text(companyName, 55, 52);
        doc.fillColor("rgba(255,255,255,0.8)").font("Helvetica").fontSize(8.5);
        if (companyReg) doc.text(`Company Reg: ${companyReg}`, 55, 74);
        if (companyErn) doc.text(`ERN: ${companyErn}`, 55, 85);

        doc.fillColor("#fff").font("Helvetica-Bold").fontSize(22).text("PAYSLIP", 0, 52, { align: "right", width: W + 40 });
        doc.fillColor("rgba(255,255,255,0.9)").font("Helvetica").fontSize(8.5);
        doc.text(`Period: ${fmtDate(periodStart)} – ${fmtDate(periodEnd)}`, 0, 78, { align: "right", width: W + 40 });
        doc.text(`Payment Date: ${paymentDate ? fmtDate(paymentDate) : "TBC"}`, 0, 90, { align: "right", width: W + 40 });
        doc.text(`Ref: ${payslipRef}`, 0, 102, { align: "right", width: W + 40 });

        doc.y = 125;

        // ─── EMPLOYEE INFO ──────────────────────────────────────────────────────
        const eLeft = 40, eRight = doc.page.width / 2 + 20;
        const drawLabel = (x, y, label, value) => {
            doc.fillColor(GREY).font("Helvetica").fontSize(7.5).text(label.toUpperCase(), x, y);
            doc.fillColor(BLACK).font("Helvetica-Bold").fontSize(9).text(value || "—", x, y + 9, { width: 200 });
        };
        drawLabel(eLeft, doc.y, "Employee Name", payrollSnapshot.staffName);
        drawLabel(eRight, doc.y - 18, "Employee No.", payrollSnapshot.staffEmployeeNumber || "—");
        doc.moveDown(0.35);
        drawLabel(eLeft, doc.y + 10, "Role", payrollSnapshot.staffRole || "—");
        drawLabel(eRight, doc.y + 10, "PRSI Class", staffData.prsiClass || "A1");
        doc.moveDown(0.35);
        drawLabel(eLeft, doc.y + 20, "Employment Type", staffData.employmentType || "—");
        drawLabel(eRight, doc.y + 20, "PPS Number", maskPPS(staffData.ppsNumber));
        doc.moveDown(1.8);

        // divider
        doc.moveTo(40, doc.y).lineTo(40 + W, doc.y).strokeColor("#cbd5e1").lineWidth(0.5).stroke();
        doc.moveDown(0.4);

        // ─── EARNINGS TABLE ─────────────────────────────────────────────────────
        const tY = doc.y;
        const col = { desc: 40, hrs: 280, rate: 360, amount: 450, end: 40 + W };
        const rowH = 16;

        const drawTableHeader = (y, labels) => {
            doc.rect(40, y, W, rowH).fill(DARK);
            doc.fillColor("#fff").font("Helvetica-Bold").fontSize(8);
            labels.forEach(([text, x, w]) => doc.text(text, x, y + 4, { width: w || 80, align: "left" }));
            return y + rowH;
        };

        const drawTableRow = (y, cols, shade) => {
            if (shade) doc.rect(40, y, W, rowH).fill(LGREY);
            doc.fillColor(BLACK).font("Helvetica").fontSize(8.5);
            cols.forEach(([text, x, w, align]) => doc.text(text, x, y + 3, { width: w || 80, align: align || "left" }));
            return y + rowH;
        };

        let ry = drawTableHeader(tY, [["EARNINGS", col.desc, 220], ["HOURS", col.hrs, 70], ["RATE", col.rate, 80], ["AMOUNT", col.amount, 90]]);

        earningsRows.forEach((row, i) => {
            const label = row.quantity ? `${row.label} (${Number(row.quantity).toFixed(1)} km)` : row.label;
            const hours = row.hours === null || row.hours === undefined ? "—" : `${Number(row.hours).toFixed(1)}`;
            const rate = row.rate === null || row.rate === undefined ? "—" : fmtCurrency(row.rate) + (row.quantity ? "/km" : "/hr");
            ry = drawTableRow(ry, [[label, col.desc, 230], [hours, col.hrs, 70], [rate, col.rate, 80], [fmtCurrency(row.amount), col.amount, 90, "left"]], i % 2 === 0);
        });
        // Totals row
        doc.rect(40, ry, W, rowH).fill("#e2f0ea");
        doc.fillColor(GREEN).font("Helvetica-Bold").fontSize(8.5).text("TOTAL GROSS PAY", col.desc, ry + 3, { width: 300 });
        doc.text(fmtCurrency(payrollSnapshot.grossPay), col.amount, ry + 3, { width: 90 });
        ry += rowH + 8;

        // ─── DEDUCTIONS TABLE ────────────────────────────────────────────────────
        ry = drawTableHeader(ry, [["DEDUCTIONS", col.desc, 220], ["CURRENT PERIOD", col.hrs, 140], ["YEAR TO DATE (EST.)", col.rate, 150]]);
        deductionRows.forEach((row, i) => {
            ry = drawTableRow(ry, [[row.label, col.desc, 230], [fmtCurrency(row.current), col.hrs, 140], [fmtCurrency(row.current * 4), col.rate, 150]], i % 2 === 0);
        });
        doc.rect(40, ry, W, rowH).fill("#fef2f2");
        doc.fillColor("#dc2626").font("Helvetica-Bold").fontSize(8.5).text("TOTAL DEDUCTIONS", col.desc, ry + 3, { width: 300 });
        doc.text(fmtCurrency(payrollSnapshot.totalDeductions), col.hrs, ry + 3, { width: 140 });
        doc.fillColor(GREY).text(fmtCurrency(payrollSnapshot.totalDeductions * 4), col.rate, ry + 3, { width: 150 });
        ry += rowH + 10;

        // ─── PAY SUMMARY ─────────────────────────────────────────────────────────
        const summaryW = W;
        doc.rect(40, ry, summaryW, 42).fill(GREEN);
        doc.fillColor("#fff").font("Helvetica").fontSize(8.5);
        doc.text("GROSS PAY", 55, ry + 6);
        doc.text("TOTAL DEDUCTIONS", 200, ry + 6);
        doc.text("NET PAY", 380, ry + 6);
        doc.font("Helvetica-Bold").fontSize(13);
        doc.text(fmtCurrency(payrollSnapshot.grossPay), 55, ry + 17);
        doc.text(fmtCurrency(payrollSnapshot.totalDeductions), 200, ry + 17);
        doc.fillColor("#d4f7e3").fontSize(14).text(fmtCurrency(payrollSnapshot.netPay), 380, ry + 17);
        ry += 52;

        // ─── WORKED HOURS SUMMARY ────────────────────────────────────────────────
        const compactStats = [
            ["Total Hours", `${Number(payrollSnapshot.totalHours || 0).toFixed(1)}h`],
            ["Regular Hours", `${Number(payrollSnapshot.regularHours || 0).toFixed(1)}h`],
            ["Overtime", `${Number(payrollSnapshot.overtimeHours || 0).toFixed(1)}h`],
            ["Mileage", `${Number(payrollSnapshot.mileageKm || 0).toFixed(1)} km`],
            ["Home Care", `${Number(payrollSnapshot.homeCareHours || 0).toFixed(1)}h`],
            ["Agency", `${Number(payrollSnapshot.agencyHours || 0).toFixed(1)}h`],
        ];
        const statGap = 10;
        const statWidth = (W - statGap * 2) / 3;
        const statHeight = 34;
        doc.fillColor(BLACK).font("Helvetica-Bold").fontSize(9.5).text("PAY SUMMARY DETAILS", 40, ry);
        ry += 14;
        compactStats.forEach(([label, value], index) => {
            const colIndex = index % 3;
            const rowIndex = Math.floor(index / 3);
            const x = 40 + colIndex * (statWidth + statGap);
            const y = ry + rowIndex * (statHeight + 8);
            doc.roundedRect(x, y, statWidth, statHeight, 8).fillAndStroke("#f8fafc", "#dbe3ee");
            doc.fillColor(GREY).font("Helvetica").fontSize(7.2).text(label.toUpperCase(), x + 10, y + 7, { width: statWidth - 20 });
            doc.fillColor(BLACK).font("Helvetica-Bold").fontSize(9.5).text(value, x + 10, y + 18, { width: statWidth - 20 });
        });
        ry += statHeight * 2 + 20;
        doc.fillColor(GREY).font("Helvetica").fontSize(7.3).text(
            "Detailed shift-level activity is available in the staff payroll portal. This payslip is intentionally formatted to remain on one page for printing.",
            40,
            ry,
            { width: W, align: "left" }
        );
        ry += 18;

        // ─── FOOTER ──────────────────────────────────────────────────────────────
        const pageCount = doc.bufferedPageRange ? doc.bufferedPageRange().count : 1;
        const footY = doc.page.height - 45;
        doc.rect(40, footY, W, 0.5).fill("#cbd5e1");
        doc.fillColor(GREY).font("Helvetica").fontSize(7);
        doc.text(`CONFIDENTIAL – ${companyName}`, 40, footY + 6, { align: "left", width: W / 2 });
        doc.text(`Payslip Ref: ${payslipRef}  |  Generated: ${new Date().toLocaleString("en-IE")}`, 40, footY + 6, { align: "right", width: W });

        // Watermark
        doc.save();
        doc.rotate(-45, { origin: [doc.page.width / 2, doc.page.height / 2] });
        doc.fillColor("#e2e8f0").font("Helvetica-Bold").fontSize(60).opacity(0.08);
        doc.text("CONFIDENTIAL", 60, doc.page.height / 2 - 30, { align: "center", width: doc.page.width - 120 });
        doc.restore();

        doc.end();
    });
};

// Build a nodemailer transporter (returns null if SMTP not configured)
const getMailTransporter = () => {
    if (!smtpHost || !smtpUser || !smtpPass) return null;
    return nodemailer.createTransport({
        host: smtpHost,
        port: smtpPort,
        secure: smtpPort === 465,
        auth: { user: smtpUser, pass: smtpPass },
        tls: { rejectUnauthorized: process.env.SMTP_TLS_REJECT_UNAUTHORIZED !== "0" },
    });
};

const sendMfaEmail = async (email, code) => {
    const transporter = getMailTransporter();
    if (!transporter) {
        const error = new Error("Email MFA requires SMTP_HOST, SMTP_USER, SMTP_PASS, and SMTP_FROM configuration.");
        error.code = "MFA_EMAIL_NOT_CONFIGURED";
        throw error;
    }
    await transporter.sendMail({
        from: smtpFrom,
        to: email,
        subject: "Your Everkind verification code",
        text: `Your Everkind verification code is ${code}. It expires in ${mfaChallengeLifetimeMinutes} minutes. If you did not request this code, contact your administrator.`,
        html: `<p>Your Everkind verification code is:</p><p style="font-size:28px;font-weight:700;letter-spacing:6px">${code}</p><p>This code expires in ${mfaChallengeLifetimeMinutes} minutes. If you did not request it, contact your administrator.</p>`,
    });
};

const sendMfaSms = async (phone, code) => {
    if (!isSmsMfaConfigured()) {
        const error = new Error("SMS MFA requires TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_FROM_NUMBER configuration.");
        error.code = "MFA_SMS_NOT_CONFIGURED";
        throw error;
    }
    const normalizedPhone = normalizePhoneForUniqueness(phone);
    if (!normalizedPhone) throw new Error("A valid verified mobile number is required for SMS MFA.");
    const body = new URLSearchParams({
        To: `+${normalizedPhone}`,
        From: twilioFromNumber,
        Body: `Your Everkind verification code is ${code}. It expires in ${mfaChallengeLifetimeMinutes} minutes.`,
    }).toString();
    await new Promise((resolve, reject) => {
        const request = https.request({
            hostname: "api.twilio.com",
            path: `/2010-04-01/Accounts/${encodeURIComponent(twilioAccountSid)}/Messages.json`,
            method: "POST",
            auth: `${twilioAccountSid}:${twilioAuthToken}`,
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "Content-Length": Buffer.byteLength(body),
            },
        }, (response) => {
            response.resume();
            response.on("end", () => {
                if (response.statusCode >= 200 && response.statusCode < 300) resolve();
                else reject(new Error(`SMS provider rejected the request with status ${response.statusCode}.`));
            });
        });
        request.setTimeout(10_000, () => request.destroy(new Error("SMS provider request timed out.")));
        request.on("error", reject);
        request.end(body);
    });
};

const createMfaChallenge = async ({ account, purpose, method }) => {
    if (!["email", "sms"].includes(method)) throw new Error("Select Email or SMS.");
    const now = new Date();
    const recentCount = await getDb(
        `SELECT COUNT(*) AS count FROM mfa_challenges
         WHERE account_type = ? AND account_id = ? AND purpose = ? AND method = ?
           AND created_at > datetime('now', '-15 minutes')`,
        [account.accountType, account.id, purpose, method]
    );
    if (Number(recentCount?.count || 0) >= 5) {
        const error = new Error("Too many verification codes requested. Try again in 15 minutes.");
        error.code = "MFA_RATE_LIMITED";
        throw error;
    }
    const existing = await getDb(
        `SELECT resend_after FROM mfa_challenges
         WHERE account_type = ? AND account_id = ? AND purpose = ? AND method = ?
           AND consumed_at IS NULL
         ORDER BY id DESC LIMIT 1`,
        [account.accountType, account.id, purpose, method]
    );
    if (existing && new Date(existing.resend_after).getTime() > now.getTime()) {
        const error = new Error("Please wait before requesting another verification code.");
        error.code = "MFA_RESEND_DELAY";
        throw error;
    }
    await runDb(
        `UPDATE mfa_challenges SET consumed_at = CURRENT_TIMESTAMP
         WHERE account_type = ? AND account_id = ? AND purpose = ? AND consumed_at IS NULL`,
        [account.accountType, account.id, purpose]
    );
    const code = mfaSecurity.createVerificationCode();
    const nonce = crypto.randomBytes(24).toString("base64url");
    const expiresAt = new Date(now.getTime() + mfaChallengeLifetimeMinutes * 60_000).toISOString();
    const resendAfter = new Date(now.getTime() + mfaResendDelaySeconds * 1000).toISOString();
    const result = await runDb(
        `INSERT INTO mfa_challenges
         (account_type, account_id, purpose, method, nonce, code_hash, attempts_remaining, expires_at, resend_after)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
            account.accountType,
            account.id,
            purpose,
            method,
            nonce,
            mfaSecurity.hashChallenge(nonce, code),
            mfaChallengeAttemptLimit,
            expiresAt,
            resendAfter,
        ]
    );
    try {
        if (method === "email") await sendMfaEmail(account.email, code);
        else await sendMfaSms(account.phone, code);
    } catch (error) {
        await runDb("DELETE FROM mfa_challenges WHERE id = ?", [result.lastID]);
        throw error;
    }
    return {
        expiresAt,
        expiresInSeconds: mfaChallengeLifetimeMinutes * 60,
        destination: method === "email" ? maskEmail(account.email) : maskPhone(account.phone),
    };
};

const verifyMfaChallenge = async ({ account, purpose, method, code }) => {
    const challenge = await getDb(
        `SELECT * FROM mfa_challenges
         WHERE account_type = ? AND account_id = ? AND purpose = ? AND method = ?
           AND consumed_at IS NULL
         ORDER BY id DESC LIMIT 1`,
        [account.accountType, account.id, purpose, method]
    );
    if (!challenge || new Date(challenge.expires_at).getTime() <= Date.now() || Number(challenge.attempts_remaining) <= 0) {
        return { valid: false, verified: false, reason: "expired_or_missing" };
    }
    if (!mfaSecurity.verifyChallenge(challenge.nonce, code, challenge.code_hash)) {
        await runDb(
            "UPDATE mfa_challenges SET attempts_remaining = MAX(0, attempts_remaining - 1) WHERE id = ?",
            [challenge.id]
        );
        return { valid: false, verified: false, reason: "invalid_code" };
    }
    await runDb("UPDATE mfa_challenges SET consumed_at = CURRENT_TIMESTAMP WHERE id = ?", [challenge.id]);
    return { valid: true, verified: true, challenge };
};

const sendPayslipEmail = async (payslipId, staffId, toEmail, staffName, periodStart, periodEnd, paymentDate, pdfBuffer, payslipRef) => {
    const transporter = getMailTransporter();
    const now = new Date().toISOString();
    if (!transporter) {
        await runDb("UPDATE payslips SET email_status = 'smtp_not_configured', email_sent_at = ? WHERE id = ?", [now, payslipId]);
        await runDb("INSERT INTO payslip_email_log (payslip_id, staff_id, email_address, subject, status, error_message) VALUES (?,?,?,?,?,?)",
            [payslipId, staffId, toEmail, "", "failed", "SMTP not configured"]);
        return { success: false, error: "SMTP not configured" };
    }
    const subject = `Everkind Payslip – Period Ending ${fmtDate(periodEnd)}`;
    const html = `
<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;">
  <div style="background:#1a7c3e;padding:24px 32px;border-radius:8px 8px 0 0;">
    <h2 style="color:#fff;margin:0;font-size:20px;">Everkind Home Care</h2>
    <p style="color:rgba(255,255,255,0.8);margin:4px 0 0;">Payslip Notification</p>
  </div>
  <div style="background:#f8fafc;padding:28px 32px;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 8px 8px;">
    <p style="color:#334155;font-size:15px;">Dear ${staffName},</p>
    <p style="color:#475569;">Your payslip for the payroll period ending <strong>${fmtDate(periodEnd)}</strong> is attached to this email.</p>
    ${paymentDate ? `<p style="color:#475569;">Your salary is scheduled to be paid on <strong>${fmtDate(paymentDate)}</strong>.</p>` : ""}
    <p style="color:#475569;">If you have any payroll queries, please contact us at <a href="mailto:${companyEmail}" style="color:#1a7c3e;">${companyEmail}</a>.</p>
    <p style="color:#475569;margin-top:24px;">Thank you for your continued dedication and support.</p>
    <p style="color:#334155;font-weight:600;">Kind regards,<br>Payroll Department<br>${companyName}</p>
    <hr style="border:none;border-top:1px solid #e2e8f0;margin:20px 0;">
    <p style="color:#94a3b8;font-size:11px;">This payslip is confidential. Ref: ${payslipRef}</p>
  </div>
</div>`;
    try {
        await transporter.sendMail({
            from: `"${companyName} Payroll" <${smtpFrom}>`,
            to: toEmail,
            subject,
            html,
            attachments: [{ filename: `payslip-${payslipRef}.pdf`, content: pdfBuffer, contentType: "application/pdf" }],
        });
        await runDb("UPDATE payslips SET email_status = 'sent', email_sent_at = ? WHERE id = ?", [now, payslipId]);
        await runDb("INSERT INTO payslip_email_log (payslip_id, staff_id, email_address, subject, status) VALUES (?,?,?,?,?)",
            [payslipId, staffId, toEmail, subject, "sent"]);
        return { success: true };
    } catch (err) {
        await runDb("UPDATE payslips SET email_status = 'failed' WHERE id = ?", [payslipId]);
        await runDb("INSERT INTO payslip_email_log (payslip_id, staff_id, email_address, subject, status, error_message) VALUES (?,?,?,?,?,?)",
            [payslipId, staffId, toEmail, subject, "failed", err.message]);
        return { success: false, error: err.message };
    }
};

// Generate and store a payslip PDF for an approved payroll record
const generateAndStorePayslip = async (staffRow, periodStart, periodEnd, paymentDate, generatedBy) => {
    if (!fs.existsSync(payslipsDir)) fs.mkdirSync(payslipsDir, { recursive: true });

    const payslipRef = `PS-${String(staffRow.staffId).padStart(4,"0")}-${periodStart.replace(/-/g,"")}`;
    const fileName = `payslip-${staffRow.staffId}-${periodStart}-${periodEnd}.pdf`;
    const filePath = path.join(payslipsDir, fileName);
    const payrollSettings = await getPayrollSettings();
    const payrollRecord = await getDb("SELECT * FROM payroll_records WHERE staff_id = ? AND period_start = ? AND period_end = ?", [staffRow.staffId, periodStart, periodEnd]);
    if (!payrollRecord || !["approved", "paid"].includes(String(payrollRecord.status || "").toLowerCase())) {
        throw new Error("Payroll must be approved before a payslip can be generated.");
    }
    const normalizedSnapshot = getPayrollSnapshotForRecord(payrollRecord, staffRow, payrollSettings);

    const staffRecord = await getDb("SELECT pps_number, employment_type, email FROM staff WHERE id = ?", [staffRow.staffId]);
    const pdfBuffer = await generatePayslipPDF(
        { ...normalizedSnapshot, ppsNumber: staffRecord ? staffRecord.pps_number : "", employmentType: staffRecord ? staffRecord.employment_type : "", paymentDate },
        periodStart, periodEnd, { payslipRef, paymentDate }
    );
    fs.writeFileSync(filePath, pdfBuffer);

    const now = new Date().toISOString();
    const pd2 = normalizedSnapshot.paymentDate || new Date(new Date(periodEnd).getTime() + 2 * 86400000).toISOString().slice(0, 10);
    const schedAt = new Date(new Date(pd2).getTime() - 2 * 86400000).toISOString().slice(0, 10) + "T09:00:00.000Z";

    await runDb(`
        INSERT INTO payslips (staff_id, payroll_record_id, period_start, period_end, gross_pay, net_pay, file_path, payment_date, email_status, email_scheduled_at, generated_at, generated_by, payslip_ref)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'scheduled', ?, ?, ?, ?)
        ON CONFLICT(payslip_ref) DO UPDATE SET
            gross_pay = excluded.gross_pay, net_pay = excluded.net_pay, file_path = excluded.file_path,
            payment_date = excluded.payment_date, email_status = 'scheduled', email_scheduled_at = excluded.email_scheduled_at,
            generated_at = excluded.generated_at, generated_by = excluded.generated_by
    `, [staffRow.staffId, payrollRecord.id, periodStart, periodEnd,
        normalizedSnapshot.grossPay, normalizedSnapshot.netPay, filePath, pd2, schedAt, now, generatedBy || "system", payslipRef]);

    return { filePath, pdfBuffer, payslipRef };
};

const ensurePayslipFileExists = async (payslipRecord, generatedBy) => {
    if (!payslipRecord) {
        return null;
    }
    if (payslipRecord.file_path && fs.existsSync(payslipRecord.file_path)) {
        return payslipRecord.file_path;
    }

    const staffRecord = await getDb("SELECT first_name, last_name, name, email, role, pps_number, employment_type, hourly_rate FROM staff WHERE id = ?", [payslipRecord.staff_id]);
    const payrollRecord = await getDb("SELECT * FROM payroll_records WHERE staff_id = ? AND period_start = ? AND period_end = ?", [payslipRecord.staff_id, payslipRecord.period_start, payslipRecord.period_end]);
    const fallbackStaffRow = {
        staffId: payslipRecord.staff_id,
        staffName: staffRecord ? (staffRecord.name || formatName(staffRecord.first_name, staffRecord.last_name)) : "Staff Member",
        staffRole: staffRecord ? (staffRecord.role || "") : "",
        staffEmployeeNumber: "",
        hourlyRate: staffRecord ? Number(staffRecord.hourly_rate || 0) : 0,
        grossPay: Number(payslipRecord.gross_pay || 0),
        netPay: Number(payslipRecord.net_pay || 0),
        totalHours: Number(payrollRecord ? payrollRecord.total_hours : 0),
        mileageKm: Number(payrollRecord ? payrollRecord.mileage_km : 0),
        mileagePayment: Number(payrollRecord ? payrollRecord.mileage_payment : 0),
        estimatedTax: Number(payrollRecord ? payrollRecord.estimated_tax || 0 : 0),
        paymentDate: payslipRecord.payment_date || "",
    };
    const payrollSettings = await getPayrollSettings();
    const staffRow = payrollRecord ? getPayrollSnapshotForRecord(payrollRecord, fallbackStaffRow, payrollSettings) : fallbackStaffRow;
    const result = await generateAndStorePayslip(staffRow, payslipRecord.period_start, payslipRecord.period_end, payslipRecord.payment_date, generatedBy || "system");
    return result.filePath;
};

const buildPayslipDetailData = async (payslipRecord) => {
    if (!payslipRecord) {
        return null;
    }

    const payrollRecord = await getDb("SELECT * FROM payroll_records WHERE staff_id = ? AND period_start = ? AND period_end = ?", [payslipRecord.staff_id, payslipRecord.period_start, payslipRecord.period_end]);
    if (!payrollRecord || !payrollRecord.snapshot_json) {
        return null;
    }
    const payrollSettings = await getPayrollSettings();
    const fallbackRow = {
        staffId: Number(payslipRecord.staff_id),
        staffName: payslipRecord.staff_name || "Staff Member",
        staffRole: payslipRecord.staff_role || "",
        staffEmployeeNumber: "",
        hourlyRate: 0,
        dayHours: 0,
        nightHours: 0,
        weekendHours: 0,
        bankHolidayHours: 0,
        overtimeHours: 0,
        mileageKm: Number(payrollRecord ? payrollRecord.mileage_km : 0),
        mileagePayment: Number(payrollRecord ? payrollRecord.mileage_payment : 0),
        estimatedTax: 0,
        grossPay: Number(payslipRecord.gross_pay || 0),
        netPay: Number(payslipRecord.net_pay || 0),
        totalHours: Number(payrollRecord ? payrollRecord.total_hours : 0),
        regularHours: Number(payrollRecord ? payrollRecord.total_hours : 0),
        homeCareHours: 0,
        agencyHours: 0,
        shifts: [],
    };
    const snapshot = getPayrollSnapshotForRecord(payrollRecord, fallbackRow, payrollSettings);

    return {
        ...snapshot,
        liveSnapshot: snapshot,
        storedOverrides: parseJsonObjectField(payrollRecord.snapshot_json),
        earningsRows: buildPayslipEarningsRows(snapshot),
        deductionRows: buildPayslipDeductionRows(snapshot),
        payrollRecordId: payrollRecord.id,
        payrollStatus: payrollRecord.status,
        payrollSettings,
    };
};

// Scheduled job: send emails for due payslips
const runPayslipEmailScheduler = async () => {
    try {
        const now = new Date().toISOString();
        const due = await allDb(`
            SELECT ps.*, s.email AS staff_email, s.first_name, s.last_name, s.name AS staff_full_name
            FROM payslips ps
            JOIN staff s ON s.id = ps.staff_id
            WHERE ps.email_status = 'scheduled' AND ps.email_scheduled_at <= ?
        `, [now]);
        for (const ps of due) {
            const toEmail = ps.staff_email;
            const staffName = ps.first_name ? `${ps.first_name} ${ps.last_name || ""}`.trim() : (ps.staff_full_name || "Staff Member");
            if (!toEmail || !ps.file_path || !fs.existsSync(ps.file_path)) {
                await runDb("UPDATE payslips SET email_status = 'no_file_or_email' WHERE id = ?", [ps.id]);
                continue;
            }
            const pdfBuffer = fs.readFileSync(ps.file_path);
            await sendPayslipEmail(ps.id, ps.staff_id, toEmail, staffName, ps.period_start, ps.period_end, ps.payment_date, pdfBuffer, ps.payslip_ref || `PS-${ps.id}`);
        }
    } catch (err) {
        console.error("Payslip email scheduler error:", err.message);
    }
};

const startPayslipEmailScheduler = () => {
    setInterval(runPayslipEmailScheduler, 5 * 60 * 1000); // every 5 minutes
};

app.get("/api/admin/home-visits", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getHomeVisitModuleData(req.query || {});
        return res.json({ success: true, ...data });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get("/api/admin/dashboard", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getDashboardModuleData();
        return res.json({ success: true, ...data });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get("/api/admin/home-care-clients", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getHomeCareClientsModuleData();
        return res.json({ success: true, ...data });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get("/api/admin/open-shifts", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getOpenShiftsModuleData();
        return res.json({ success: true, ...data });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get("/api/admin/schedule", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getScheduleModuleData(req.query || {}, Number(req.session.staffId) || null);
        return res.json({ success: true, ...data });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get("/api/admin/live-tracking", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getLiveTrackingModuleData();
        return res.json({ success: true, ...data });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.post("/api/admin/live-tracking/:shiftId/reminder", requirePortal, requireAdmin, async (req, res) => {
    try {
        const shiftId = Number(req.params.shiftId);
        if (!Number.isInteger(shiftId) || shiftId <= 0) {
            return res.status(400).json({ success: false, message: "Valid shift ID is required." });
        }
        const shift = await getDb(
            `SELECT ss.id, ss.staff_id, ss.scheduled_start, ss.status,
                    COALESCE(ss.external_client_label, ca.organization_name, p.first_name || ' ' || p.last_name, 'Client') AS assignment_name
             FROM staff_shifts ss
             LEFT JOIN patients p ON p.id = ss.patient_id
             LEFT JOIN client_accounts ca ON ca.id = ss.client_account_id
             WHERE ss.id = ?`,
            [shiftId]
        );
        if (!shift) {
            return res.status(404).json({ success: false, message: "Shift not found." });
        }
        if (!shift.staff_id) {
            return res.status(409).json({ success: false, message: "No staff member is assigned to this shift." });
        }
        const scheduledLabel = shift.scheduled_start ? String(shift.scheduled_start).slice(11, 16) : "the scheduled time";
        await queueStaffNotification(
            Number(shift.staff_id),
            "Clock-in reminder",
            `Please clock in for ${shift.assignment_name || "your assigned shift"} scheduled at ${scheduledLabel}.`,
            "shift",
            "/portal/staff-schedule"
        );
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "live_tracking_reminder_sent",
            targetType: "shift",
            targetIdentifier: String(shiftId),
            outcome: "success",
        });
        return res.json({ success: true });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get("/api/admin/attendance", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getAttendanceModuleData(req.query || {});
        return res.json({ success: true, ...data });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get("/api/admin/compliance", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getComplianceModuleData();
        return res.json({ success: true, ...data });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get("/api/admin/reports", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getReportsModuleData();
        return res.json({ success: true, ...data });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get("/api/admin/care-reviews", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getCareReviewsModuleData();
        return res.json({ success: true, ...data });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get("/api/admin/facilities", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getFacilityModuleData();
        return res.json({ success: true, ...data });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get("/api/admin/facility-portal", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getFacilityPortalModuleData();
        return res.json({ success: true, ...data });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get("/api/admin/shift-requests", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getShiftRequestsModuleData();
        return res.json({ success: true, ...data });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get("/api/admin/payroll", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getPayrollModuleData(req.query || {});
        return res.json({ success: true, ...data });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get("/api/admin/settings", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getSettingsModuleData(res.locals.adminAccess);
        return res.json({ success: true, ...data });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

app.get("/admin/dashboard", requirePortal, requireAdmin, async (req, res) => {
    try {
        if (res.locals.adminAccess.effectiveRole === "hr") {
            return res.redirect("/admin/hr-dashboard");
        }
        if (res.locals.adminAccess.effectiveRole === "payroll") {
            return res.redirect("/admin/payroll");
        }
        const data = await getDashboardModuleData();
        return res.render("portal-dashboard", {
            title: "Dashboard",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            metrics: data.metrics,
            recentActivity: data.recentActivity,
            upcomingVisits: data.upcomingVisits,
            staffPreview: data.staffPreview,
        });
    } catch (error) {
        console.error("Error loading admin dashboard module:", error.message);
        return res.status(500).render("error", {
            title: "Dashboard unavailable",
            message: "The dashboard module could not be loaded.",
            isAdmin: true,
            returnPath: "/admin/dashboard",
        });
    }
});

app.get("/admin/hr-dashboard", requirePortal, requireAdmin, async (req, res) => {
    try {
        if (res.locals.adminAccess.effectiveRole !== "hr") {
            return res.redirect("/admin/dashboard");
        }
        const data = await getHrDashboardModuleData();
        return res.render("portal-hr-dashboard", {
            title: "HR Dashboard",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || req.session.adminName || "HR Administrator",
            currentStaffEmail: req.session.staffEmail || req.session.adminEmail || adminEmail,
            ...data,
        });
    } catch (error) {
        console.error("Error loading HR dashboard:", error.message);
        return res.status(500).render("error", {
            title: "HR dashboard unavailable",
            message: "The HR dashboard could not be loaded.",
            isAdmin: true,
            returnPath: "/admin/dashboard",
        });
    }
});

app.get("/admin/training", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getHrDashboardModuleData();
        return res.render("portal-admin-training", {
            title: "Staff Training",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || req.session.adminName || "Administrator",
            currentStaffEmail: req.session.staffEmail || req.session.adminEmail || adminEmail,
            metrics: data.metrics,
            trainingAlerts: data.trainingAlerts,
        });
    } catch (error) {
        console.error("Error loading staff training:", error.message);
        return res.status(500).render("error", {
            title: "Staff training unavailable",
            message: "Staff training records could not be loaded.",
        });
    }
});

app.get("/admin/home-care-clients", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getHomeCareClientsModuleData();
        return res.render("patients", {
            title: "Home Care Clients",
            patients: data.patients,
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            message: String(req.query.message || ""),
        });
    } catch (error) {
        console.error("Error loading home care clients module:", error.message);
        return res.status(500).render("error", {
            title: "Clients unavailable",
            message: "The home care clients module could not be loaded.",
        });
    }
});

app.get("/admin/home-visits", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getHomeVisitModuleData(req.query || {});
        return res.render("portal-home-visits", {
            title: "Home Visits",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            visits: data.visits,
            summary: data.summary,
            filter: data.filter,
            dateFrom: data.fromDate,
            dateTo: data.toDate,
        });
    } catch (error) {
        console.error("Error loading home visits module:", error.message);
        return res.status(500).render("error", { title: "Home visits unavailable", message: "The home visits module could not be loaded." });
    }
});

app.get("/admin/care-reviews", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getCareReviewsModuleData();
        return res.render("portal-care-reviews", {
            title: "Care Reviews",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            reviews: data.reviews,
            summary: data.summary,
            staff: data.staff,
            clients: data.clients,
            reviewTypes: ["care", "risk", "medication"],
        });
    } catch (error) {
        console.error("Error loading care reviews module:", error.message);
        return res.status(500).render("error", { title: "Care reviews unavailable", message: "The care reviews module could not be loaded." });
    }
});

app.post("/portal/care-reviews", requirePortal, requireAdmin, async (req, res) => {
    const patientId = Number(req.body.patient_id);
    const reviewType = String(req.body.review_type || "care").trim().toLowerCase();
    const dueDate = String(req.body.due_date || "").trim();
    const reviewerStaffId = Number(req.body.reviewer_staff_id) || null;
    if (!Number.isInteger(patientId) || patientId <= 0 || !dueDate) {
        return res.redirect("/admin/care-reviews?error=missing-review-fields");
    }
    try {
        await runDb(
            `INSERT INTO care_reviews (patient_id, review_type, reviewer_staff_id, due_date, status, notes, created_at, updated_at)
             VALUES (?, ?, ?, ?, 'upcoming', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
            [patientId, reviewType, reviewerStaffId, dueDate, String(req.body.notes || "").trim()]
        );
        return res.redirect("/admin/care-reviews");
    } catch (error) {
        console.error("Error creating care review:", error.message);
        return res.redirect("/admin/care-reviews?error=create-review-failed");
    }
});

app.post("/portal/care-reviews/:id/assign", requirePortal, requireAdmin, async (req, res) => {
    const reviewId = Number(req.params.id);
    const reviewerStaffId = Number(req.body.reviewer_staff_id) || null;
    try {
        await runDb(
            "UPDATE care_reviews SET reviewer_staff_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            [reviewerStaffId, reviewId]
        );
        return res.redirect("/admin/care-reviews");
    } catch (error) {
        console.error("Error assigning care review:", error.message);
        return res.redirect("/admin/care-reviews?error=assign-review-failed");
    }
});

app.post("/portal/care-reviews/:id/complete", requirePortal, requireAdmin, async (req, res) => {
    const reviewId = Number(req.params.id);
    try {
        await runDb(
            "UPDATE care_reviews SET status = 'completed', completed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            [reviewId]
        );
        return res.redirect("/admin/care-reviews");
    } catch (error) {
        console.error("Error completing care review:", error.message);
        return res.redirect("/admin/care-reviews?error=complete-review-failed");
    }
});

app.get("/admin/care-reviews/export", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getCareReviewsModuleData();
        res.setHeader("Content-Type", "text/csv");
        res.setHeader("Content-Disposition", "attachment; filename=\"care-reviews.csv\"");
        let csv = "Client ID,Client Name,Review Type,Due Date,Reviewer,Status,Completed At\n";
        for (const review of data.reviews) {
            csv += `"${review.home_care_client_id || ""}","${review.patient_name || ""}","${review.review_type || ""}","${review.due_date || ""}","${review.reviewer_name || ""}","${review.status || ""}","${review.completed_at || ""}"\n`;
        }
        return res.send(csv);
    } catch (error) {
        return res.status(500).send("Could not export care reviews.");
    }
});

app.get("/admin/facilities", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getFacilityModuleData();
        return res.render("portal-facilities", {
            title: "Healthcare Facilities",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            facilities: data.facilities,
            summary: data.summary,
        });
    } catch (error) {
        console.error("Error loading facilities module:", error.message);
        return res.status(500).render("error", { title: "Facilities unavailable", message: "The healthcare facilities module could not be loaded." });
    }
});

app.get("/admin/facility-portal", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getFacilityPortalModuleData();
        return res.render("portal-facility-portal", {
            title: "Facility Portal",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            registrations: data.registrations,
            summary: data.summary,
            registrationStatuses: clientPortalRegistrationStatuses,
            approvedFacilityEmail: String(req.query.facility_email || "").trim(),
            approvedFacilityTemporaryPassword: String(req.query.temp_password || "").trim(),
        });
    } catch (error) {
        console.error("Error loading facility portal module:", error.message);
        return res.status(500).render("error", { title: "Facility portal unavailable", message: "The facility portal module could not be loaded." });
    }
});

app.get("/admin/shift-requests", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getShiftRequestsModuleData();
        return res.render("portal-shift-requests", {
            title: "Shift Requests",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            requests: data.requests,
            staff: data.staff,
            summary: data.summary,
            requestStatuses: clientPortalRequestStatuses,
        });
    } catch (error) {
        console.error("Error loading shift requests module:", error.message);
        return res.status(500).render("error", { title: "Shift requests unavailable", message: "The shift requests module could not be loaded." });
    }
});

app.get("/admin/open-shifts", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getOpenShiftsModuleData();
        return res.render("portal-open-shifts", {
            title: "Open Shifts",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            openShifts: data.openShifts,
            patients: data.patients,
        });
    } catch (error) {
        console.error("Error loading open shifts module:", error.message);
        return res.status(500).render("error", { title: "Open Shifts unavailable", message: "Could not load open shifts." });
    }
});

app.get("/admin/schedule", requirePortal, requireAdmin, async (req, res) => {
    try {
        const staffId = Number(req.session.staffId) || null;
        const data = await getScheduleModuleData(req.query || {}, staffId);
        return res.render("portal-shifts", {
            title: "Schedule",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Operations team",
            liveShift: data.liveShift,
            shifts: data.shifts,
            userHasStaffProfile: Boolean(staffId),
            shiftStatus: req.query.status || "",
            patients: data.patients,
            staff: data.staff,
            facilities: data.facilities,
            facilityTypes: data.facilityTypes,
            counties: data.counties,
            scheduleSummary: data.scheduleSummary,
            scheduleFilters: data.scheduleFilters,
        });
    } catch (error) {
        console.error("Error loading schedule module:", error.message);
        return res.status(500).render("error", {
            title: "Schedule unavailable",
            message: "The schedule module could not be loaded.",
        });
    }
});

app.get("/admin/live-tracking", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getLiveTrackingModuleData();
        return res.render("portal-live-tracking", {
            title: "Live Tracking",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            liveTracking: data,
        });
    } catch (error) {
        console.error("Error loading live tracking module:", error.message);
        return res.status(500).render("error", { title: "Live Tracking unavailable", message: "Could not load live tracking." });
    }
});

app.get("/admin/attendance", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getAttendanceModuleData(req.query || {});
        return res.render("portal-attendance", {
            title: "Attendance",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            records: data.records,
            selectedDate: data.selectedDate,
            filters: data.filters,
            stats: data.stats,
        });
    } catch (error) {
        console.error("Error loading attendance module:", error.message);
        return res.status(500).render("error", { title: "Attendance unavailable", message: "Could not load attendance records." });
    }
});

app.get("/admin/compliance", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getComplianceModuleData();
        return res.render("portal-compliance", {
            title: "Compliance Controls",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            patients: data.patients,
            subjectRequests: data.subjectRequests,
        });
    } catch (error) {
        console.error("Error loading compliance module:", error.message);
        return res.status(500).render("error", {
            title: "Compliance controls unavailable",
            message: "The compliance control centre could not be loaded.",
        });
    }
});

app.get("/admin/payroll", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getPayrollModuleData(req.query || {});
        return res.render("portal-payroll", {
            title: "Payroll",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            staffRows: data.staffRows,
            summary: data.summary,
            periodStart: data.periodStart,
            periodEnd: data.periodEnd,
            period: data.period,
            allStaff: data.allStaff,
            filters: data.filters,
        });
    } catch (error) {
        console.error("Error loading payroll module:", error.message);
        return res.status(500).render("error", { title: "Payroll unavailable", message: "The payroll module could not be loaded." });
    }
});

// Payroll: get per-shift breakdown for a staff member
app.get("/api/admin/payroll/breakdown/:staffId", requirePortal, requireAdmin, async (req, res) => {
    try {
        const staffId = Number(req.params.staffId);
        if (!staffId) return res.status(400).json({ success: false, message: "Invalid staff ID" });
        const query = { ...req.query };
        query.staffId = staffId;
        const data = await getPayrollModuleData(query);
        const staffRow = data.staffRows.find((r) => r.staffId === staffId);
        if (!staffRow) return res.json({ success: true, shifts: [], staffName: "" });
        return res.json({ success: true, staffName: staffRow.staffName, staffRole: staffRow.staffRole, hourlyRate: staffRow.hourlyRate, shifts: staffRow.shifts });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

// Payroll: approve a staff payroll record
app.post("/api/admin/payroll/:staffId/approve", requirePortal, requireAdmin, async (req, res) => {
    try {
        const staffId = Number(req.params.staffId);
        const { periodStart, periodEnd, paymentDate } = req.body || {};
        if (!staffId || !periodStart || !periodEnd) return res.status(400).json({ success: false, message: "Missing required fields" });
        const existingPayrollRecord = await getDb(
            "SELECT status FROM payroll_records WHERE staff_id = ? AND period_start = ? AND period_end = ?",
            [staffId, periodStart, periodEnd]
        );
        if (String(existingPayrollRecord && existingPayrollRecord.status || "").toLowerCase() === "paid") {
            return res.status(409).json({ success: false, message: "Paid payroll cannot be approved again." });
        }
        const payrollData = await getPayrollModuleData({ period: "custom", dateFrom: periodStart, dateTo: periodEnd, staffId });
        const staffRow = payrollData.staffRows.find((row) => row.staffId === staffId);
        if (!staffRow || !staffRow.shifts.length) {
            return res.status(409).json({ success: false, message: "No completed shifts with valid clock-in and clock-out are available for approval." });
        }
        const payrollSettings = await getPayrollSettings();
        const approvedBy = req.session.staffEmail || adminEmail;
        const now = new Date().toISOString();
        const pd = paymentDate || new Date(new Date(periodEnd).getTime() + 2 * 86400000).toISOString().slice(0, 10);
        const snapshot = buildPayrollSnapshotFromStaffRow(staffRow, payrollSettings, { paymentDate: pd });
        const shiftIds = snapshot.shiftItems.map((shift) => shift.shiftId).filter((shiftId) => Number.isInteger(shiftId) && shiftId > 0);

        await withTransaction(async ({ runDb: runTransactionDb }) => {
            await runTransactionDb(`
                INSERT INTO payroll_records (staff_id, period_start, period_end, total_hours, gross_pay, net_pay, mileage_km, mileage_payment, status, approved_by, approved_at, payment_date, snapshot_json, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'approved', ?, ?, ?, ?, ?)
                ON CONFLICT(staff_id, period_start, period_end) DO UPDATE SET
                    status = 'approved', approved_by = excluded.approved_by, approved_at = excluded.approved_at,
                    total_hours = excluded.total_hours, gross_pay = excluded.gross_pay, net_pay = excluded.net_pay,
                    mileage_km = excluded.mileage_km, mileage_payment = excluded.mileage_payment,
                    payment_date = excluded.payment_date, snapshot_json = excluded.snapshot_json, updated_at = excluded.updated_at
            `, [staffId, periodStart, periodEnd, snapshot.totalHours, snapshot.grossPay, snapshot.netPay, snapshot.mileageKm, snapshot.mileagePayment, approvedBy, now, pd, JSON.stringify(snapshot), now]);
            if (shiftIds.length) {
                await runTransactionDb(
                    `UPDATE staff_shifts SET payroll_status = 'approved' WHERE id IN (${shiftIds.map(() => "?").join(", ")})`,
                    shiftIds
                );
            }
        });
        await writeAuditEvent(req, { ...getActorContext(req), action: "payroll_approved", targetType: "staff", targetIdentifier: String(staffId), outcome: "success" });

        // Auto-generate payslip PDF in background
        try {
            await generateAndStorePayslip(staffRow, periodStart, periodEnd, pd, approvedBy);
        } catch (psErr) {
            console.error("Payslip auto-generation failed:", psErr.message);
        }

        return res.json({ success: true });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

// Payroll: mark as paid
app.post("/api/admin/payroll/:staffId/mark-paid", requirePortal, requireAdmin, async (req, res) => {
    try {
        const staffId = Number(req.params.staffId);
        const { periodStart, periodEnd } = req.body || {};
        if (!staffId || !periodStart || !periodEnd) return res.status(400).json({ success: false, message: "Missing required fields" });
        const payrollRecord = await getDb(
            "SELECT * FROM payroll_records WHERE staff_id = ? AND period_start = ? AND period_end = ?",
            [staffId, periodStart, periodEnd]
        );
        if (!payrollRecord || String(payrollRecord.status || "").toLowerCase() !== "approved") {
            return res.status(409).json({ success: false, message: "Only approved payroll can be marked as paid." });
        }
        const snapshotShiftItems = parseJsonObjectField(payrollRecord.snapshot_json).shiftItems;
        const shiftIds = Array.isArray(snapshotShiftItems) ? snapshotShiftItems : [];
        const now = new Date().toISOString();
        await withTransaction(async ({ runDb: runTransactionDb }) => {
            await runTransactionDb(`
                UPDATE payroll_records SET status = 'paid', paid_at = ?, updated_at = ?
                WHERE id = ?
            `, [now, now, payrollRecord.id]);
            const payableShiftIds = shiftIds.map((shift) => Number(shift.shiftId)).filter((shiftId) => Number.isInteger(shiftId) && shiftId > 0);
            if (payableShiftIds.length) {
                await runTransactionDb(
                    `UPDATE staff_shifts SET payroll_status = 'paid' WHERE id IN (${payableShiftIds.map(() => "?").join(", ")})`,
                    payableShiftIds
                );
            }
        });
        await writeAuditEvent(req, { ...getActorContext(req), action: "payroll_paid", targetType: "staff", targetIdentifier: String(staffId), outcome: "success" });
        return res.json({ success: true });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

// Payroll: mark back to draft
app.post("/api/admin/payroll/:staffId/revert", requirePortal, requireAdmin, async (req, res) => {
    try {
        const staffId = Number(req.params.staffId);
        const { periodStart, periodEnd } = req.body || {};
        if (!staffId || !periodStart || !periodEnd) return res.status(400).json({ success: false, message: "Missing required fields" });
        const payrollRecord = await getDb(
            "SELECT * FROM payroll_records WHERE staff_id = ? AND period_start = ? AND period_end = ?",
            [staffId, periodStart, periodEnd]
        );
        if (!payrollRecord) {
            return res.status(404).json({ success: false, message: "Payroll record not found." });
        }
        if (String(payrollRecord.status || "").toLowerCase() === "paid") {
            return res.status(409).json({ success: false, message: "Paid payroll cannot be reverted. Record a correction through the existing payroll adjustment workflow." });
        }
        const snapshotShiftItems = parseJsonObjectField(payrollRecord.snapshot_json).shiftItems;
        const shiftItems = Array.isArray(snapshotShiftItems) ? snapshotShiftItems : [];
        const shiftIds = shiftItems.map((shift) => Number(shift.shiftId)).filter((shiftId) => Number.isInteger(shiftId) && shiftId > 0);
        await withTransaction(async ({ runDb: runTransactionDb }) => {
            await runTransactionDb(
                `UPDATE payroll_records
                 SET status = 'draft', approved_by = NULL, approved_at = NULL, updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?`,
                [payrollRecord.id]
            );
            await runTransactionDb("UPDATE payslips SET email_status = 'voided' WHERE payroll_record_id = ?", [payrollRecord.id]);
            if (shiftIds.length) {
                await runTransactionDb(
                    `UPDATE staff_shifts SET payroll_status = 'draft' WHERE id IN (${shiftIds.map(() => "?").join(", ")})`,
                    shiftIds
                );
            }
        });
        return res.json({ success: true });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

// Payroll: CSV export
app.get("/admin/payroll/export", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getPayrollModuleData(req.query || {});
        res.setHeader("Content-Type", "text/csv");
        res.setHeader("Content-Disposition", `attachment; filename="payroll-${data.periodStart}-to-${data.periodEnd}.csv"`);
        const cols = ["Staff Name","Employee No.","Role","Period","Home Care Hrs","Agency Hrs","Day Hrs","Night Hrs","Weekend Hrs","Bank Hol Hrs","Overtime Hrs","Total Hrs","Mileage km","Mileage €","Pay Rate","Base Gross","Premiums","Total Gross","Deductions","Net Pay","Status"];
        let csv = cols.join(",") + "\n";
        for (const r of data.staffRows) {
            csv += [
                `"${r.staffName}"`,`"${r.staffEmployeeNumber}"`,`"${r.staffRole}"`,
                `"${data.periodStart} to ${data.periodEnd}"`,
                r.homeCareHours.toFixed(2), r.agencyHours.toFixed(2),
                r.dayHours.toFixed(2), r.nightHours.toFixed(2),
                r.weekendHours.toFixed(2), r.bankHolidayHours.toFixed(2),
                r.overtimeHours.toFixed(2), r.totalHours.toFixed(2),
                r.mileageKm.toFixed(2), r.mileagePayment.toFixed(2),
                `"${r.rateLabel || `€${r.hourlyRate.toFixed(2)}`}"`, r.baseGross.toFixed(2),
                (r.premiums + r.overtimePremium).toFixed(2), r.grossPay.toFixed(2),
                Number(r.totalDeductions || 0).toFixed(2), r.netPay.toFixed(2),
                `"${r.payrollStatus}"`
            ].join(",") + "\n";
        }
        return res.send(csv);
    } catch (error) {
        return res.status(500).send("Export error: " + error.message);
    }
});

// Payslips: admin management page
app.get("/admin/payroll/payslips", requirePortal, requireAdmin, async (req, res) => {
    try {
        const payslips = await allDb(`
            SELECT ps.*, COALESCE(s.first_name || ' ' || s.last_name, s.name) AS staff_name, s.email AS staff_email, s.role AS staff_role
            FROM payslips ps
            JOIN staff s ON s.id = ps.staff_id
            ORDER BY ps.generated_at DESC
            LIMIT 200
        `);
        const emailLogCounts = await allDb("SELECT payslip_id, COUNT(*) AS cnt FROM payslip_email_log GROUP BY payslip_id");
        const emailMap = new Map(emailLogCounts.map((r) => [r.payslip_id, r.cnt]));
        payslips.forEach((p) => { p.emailCount = emailMap.get(p.id) || 0; });
        return res.render("portal-payslips", {
            title: "Payslips",
            active: "payslips",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            payslips,
        });
    } catch (error) {
        console.error("Error loading payslips:", error.message);
        return res.status(500).render("error", { title: "Payslips unavailable", message: error.message });
    }
});

// Payslips: download a PDF
app.get("/admin/payroll/payslip/:id/download", requirePortal, requireAdmin, async (req, res) => {
    try {
        const ps = await getDb("SELECT * FROM payslips WHERE id = ?", [Number(req.params.id)]);
        if (!ps) return res.status(404).send("Payslip not found");
        const filePath = await ensurePayslipFileExists(ps, req.session.staffEmail || adminEmail);
        if (!filePath || !fs.existsSync(filePath)) return res.status(404).send("Payslip file not found");
        const fileName = `payslip-${ps.payslip_ref || ps.id}.pdf`;
        res.setHeader("Content-Type", "application/pdf");
        res.setHeader("Content-Disposition", `attachment; filename="${fileName}"`);
        return res.send(fs.readFileSync(filePath));
    } catch (error) {
        return res.status(500).send("Download error: " + error.message);
    }
});

app.get("/admin/payroll/payslip/:id", requirePortal, requireAdmin, async (req, res) => {
    try {
        const ps = await getDb(`
            SELECT ps.*, COALESCE(s.first_name || ' ' || s.last_name, s.name) AS staff_name, s.email AS staff_email, s.role AS staff_role
            FROM payslips ps
            LEFT JOIN staff s ON s.id = ps.staff_id
            WHERE ps.id = ?
        `, [Number(req.params.id)]);
        if (!ps) {
            return res.status(404).render("portal-payslip-detail", {
                title: "Payslip not found",
                payslip: null,
                isAdmin: true,
                isLoggedIn: true,
                currentStaffName: req.session.staffName || "Administrator",
                currentStaffEmail: req.session.staffEmail || adminEmail,
            });
        }
        await ensurePayslipFileExists(ps, req.session.staffEmail || adminEmail);
        const payslipDetail = await buildPayslipDetailData(ps);
        return res.render("portal-payslip-detail", {
            title: "Payslip details",
            payslip: ps,
            payslipDetail,
            printMode: String(req.query.print || "") === "1",
            message: String(req.query.message || ""),
            error: String(req.query.error || ""),
            isAdmin: true,
            isLoggedIn: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
        });
    } catch (error) {
        return res.status(500).render("error", { title: "Payslip unavailable", message: error.message });
    }
});

app.post("/admin/payroll/payslip/:id/update", requirePortal, requireAdmin, async (req, res) => {
    const payslipId = Number(req.params.id);
    try {
        const ps = await getDb(`
            SELECT ps.*, COALESCE(s.first_name || ' ' || s.last_name, s.name) AS staff_name, s.role AS staff_role
            FROM payslips ps
            LEFT JOIN staff s ON s.id = ps.staff_id
            WHERE ps.id = ?
        `, [payslipId]);
        if (!ps) {
            return res.redirect("/admin/payroll/payslips?error=" + encodeURIComponent("Payslip not found."));
        }
        const payslipDetail = await buildPayslipDetailData(ps);
        if (!payslipDetail || !payslipDetail.payrollRecordId) {
            return res.redirect(`/admin/payroll/payslip/${payslipId}?error=` + encodeURIComponent("This payslip cannot be edited because the payroll record is missing."));
        }
        if (String(payslipDetail.payrollStatus || "").toLowerCase() === "paid") {
            return res.redirect(`/admin/payroll/payslip/${payslipId}?error=` + encodeURIComponent("Paid payroll is final and cannot be edited."));
        }

        const updatedSnapshot = recalculatePayrollSnapshot({
            ...payslipDetail,
            staffName: String(req.body.staffName || payslipDetail.staffName || "").trim() || payslipDetail.staffName,
            staffRole: String(req.body.staffRole || payslipDetail.staffRole || "").trim(),
            staffEmployeeNumber: String(req.body.staffEmployeeNumber || payslipDetail.staffEmployeeNumber || "").trim(),
            paymentDate: String(req.body.paymentDate || payslipDetail.paymentDate || "").trim().slice(0, 10),
            notes: String(req.body.notes || "").trim(),
            payeTax: req.body.payeTax,
            prsiAmount: req.body.prsiAmount,
            uscAmount: req.body.uscAmount,
        });
        await runDb(
            `UPDATE payroll_records
             SET total_hours = ?, gross_pay = ?, net_pay = ?, mileage_km = ?, mileage_payment = ?,
                 payment_date = ?, notes = ?, snapshot_json = ?, updated_at = ?
             WHERE id = ?`,
            [
                updatedSnapshot.totalHours,
                updatedSnapshot.grossPay,
                updatedSnapshot.netPay,
                updatedSnapshot.mileageKm,
                updatedSnapshot.mileagePayment,
                updatedSnapshot.paymentDate || ps.payment_date || "",
                updatedSnapshot.notes || "",
                JSON.stringify(updatedSnapshot),
                new Date().toISOString(),
                payslipDetail.payrollRecordId,
            ]
        );

        await generateAndStorePayslip(updatedSnapshot, ps.period_start, ps.period_end, updatedSnapshot.paymentDate || ps.payment_date || "", req.session.staffEmail || adminEmail);
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "payslip_updated",
            targetType: "payslip",
            targetIdentifier: String(payslipId),
            outcome: "success",
            metadata: serializeJsonField({
                grossPay: updatedSnapshot.grossPay,
                netPay: updatedSnapshot.netPay,
                totalHours: updatedSnapshot.totalHours,
                adjustmentType: "metadata_and_deductions",
            }),
        });
        return res.redirect(`/admin/payroll/payslip/${payslipId}?message=` + encodeURIComponent("Payslip updated successfully."));
    } catch (error) {
        return res.redirect(`/admin/payroll/payslip/${payslipId}?error=` + encodeURIComponent(error.message || "Payslip could not be updated."));
    }
});

// Payslips: (re)generate payslip for a staff member
app.post("/api/admin/payroll/:staffId/generate-payslip", requirePortal, requireAdmin, async (req, res) => {
    try {
        const staffId = Number(req.params.staffId);
        const { periodStart, periodEnd, paymentDate } = req.body || {};
        if (!staffId || !periodStart || !periodEnd) return res.status(400).json({ success: false, message: "Missing fields" });
        const payrollData = await getPayrollModuleData({ period: "custom", dateFrom: periodStart, dateTo: periodEnd, staffId });
        const staffRow = payrollData.staffRows.find((r) => r.staffId === staffId);
        if (!staffRow) return res.status(404).json({ success: false, message: "No payroll data found for this period" });
        const result = await generateAndStorePayslip(staffRow, periodStart, periodEnd, paymentDate || "", req.session.staffEmail || adminEmail);
        const ps = await getDb("SELECT id FROM payslips WHERE payslip_ref = ?", [result.payslipRef]);
        return res.json({ success: true, payslipId: ps ? ps.id : null, payslipRef: result.payslipRef });
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

// Payslips: email payslip manually
app.post("/api/admin/payroll/:staffId/email-payslip", requirePortal, requireAdmin, async (req, res) => {
    try {
        const staffId = Number(req.params.staffId);
        const { periodStart, periodEnd } = req.body || {};
        if (!staffId || !periodStart || !periodEnd) return res.status(400).json({ success: false, message: "Missing fields" });
        const ps = await getDb(`
            SELECT ps.*, s.email AS staff_email, COALESCE(s.first_name || ' ' || s.last_name, s.name) AS staff_name
            FROM payslips ps JOIN staff s ON s.id = ps.staff_id
            WHERE ps.staff_id = ? AND ps.period_start = ? AND ps.period_end = ?
              AND COALESCE(ps.email_status, '') != 'voided'
            ORDER BY ps.generated_at DESC LIMIT 1
        `, [staffId, periodStart, periodEnd]);
        if (!ps) return res.status(404).json({ success: false, message: "Payslip not found — generate it first" });
        if (!ps.file_path || !fs.existsSync(ps.file_path)) return res.status(404).json({ success: false, message: "Payslip PDF file not found" });
        if (!ps.staff_email) return res.status(400).json({ success: false, message: "Staff member has no email address" });
        const pdfBuffer = fs.readFileSync(ps.file_path);
        const result = await sendPayslipEmail(ps.id, staffId, ps.staff_email, ps.staff_name, periodStart, periodEnd, ps.payment_date, pdfBuffer, ps.payslip_ref || `PS-${ps.id}`);
        return res.json(result);
    } catch (error) {
        return res.status(500).json({ success: false, message: error.message });
    }
});

// Staff portal: view own payslips
app.get("/portal/payslips", requireStaffOnly, async (req, res) => {
    try {
        const staffId = req.session.staffId;
        const payslips = await allDb(`
            SELECT * FROM payslips
            WHERE staff_id = ? AND COALESCE(email_status, '') != 'voided'
            ORDER BY period_start DESC LIMIT 50
        `, [staffId]);
        return res.render("portal-staff-payslips", {
            title: "My Payslips",
            active: "payslips",
            isLoggedIn: true,
            isAdmin: false,
            currentStaffName: req.session.staffName || "Staff",
            currentStaffEmail: req.session.staffEmail || "",
            payslips,
        });
    } catch (error) {
        return res.status(500).render("error", { title: "Payslips unavailable", message: error.message });
    }
});

// Staff portal: download own payslip
app.get("/portal/payslip/:id/download", requireStaffOnly, async (req, res) => {
    try {
        const staffId = req.session.staffId;
        const ps = await getDb("SELECT * FROM payslips WHERE id = ? AND staff_id = ? AND COALESCE(email_status, '') != 'voided'", [Number(req.params.id), staffId]);
        if (!ps) return res.status(404).send("Payslip not found");
        const filePath = await ensurePayslipFileExists(ps, req.session.staffEmail || req.session.staffName || "staff");
        if (!filePath || !fs.existsSync(filePath)) return res.status(404).send("Payslip file not found");
        res.setHeader("Content-Type", "application/pdf");
        res.setHeader("Content-Disposition", `attachment; filename="payslip-${ps.payslip_ref || ps.id}.pdf"`);
        return res.send(fs.readFileSync(filePath));
    } catch (error) {
        return res.status(500).send("Download error: " + error.message);
    }
});

app.get("/portal/payslip/:id", requireStaffOnly, async (req, res) => {
    try {
        const staffId = req.session.staffId;
        const ps = await getDb(`
            SELECT ps.*, COALESCE(s.first_name || ' ' || s.last_name, s.name) AS staff_name, s.email AS staff_email, s.role AS staff_role
            FROM payslips ps
            LEFT JOIN staff s ON s.id = ps.staff_id
            WHERE ps.id = ? AND ps.staff_id = ? AND COALESCE(ps.email_status, '') != 'voided'
        `, [Number(req.params.id), staffId]);
        if (!ps) {
            return res.status(404).render("portal-payslip-detail", {
                title: "Payslip not found",
                payslip: null,
                isAdmin: false,
                isLoggedIn: true,
                currentStaffName: req.session.staffName || "Staff",
                currentStaffEmail: req.session.staffEmail || "",
            });
        }
        await ensurePayslipFileExists(ps, req.session.staffEmail || req.session.staffName || "staff");
        const payslipDetail = await buildPayslipDetailData(ps);
        return res.render("portal-payslip-detail", {
            title: "Payslip details",
            payslip: ps,
            payslipDetail,
            printMode: String(req.query.print || "") === "1",
            isAdmin: false,
            isLoggedIn: true,
            currentStaffName: req.session.staffName || "Staff",
            currentStaffEmail: req.session.staffEmail || "",
        });
    } catch (error) {
        return res.status(500).render("error", { title: "Payslip unavailable", message: error.message });
    }
});

app.get("/admin/reports", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getReportsModuleData();
        return res.render("portal-reports", {
            title: "Reports",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            shiftSummary: data.shiftSummary,
        });
    } catch (error) {
        console.error("Error loading reports module:", error.message);
        return res.status(500).render("error", {
            title: "Reports unavailable",
            message: "The reports module could not be loaded.",
        });
    }
});

app.get("/admin/website-content", requirePortal, requireAdmin, async (req, res) => {
    try {
        const [announcements, jobs] = await Promise.all([
            allDb("SELECT * FROM website_announcements ORDER BY created_at DESC"),
            allDb("SELECT * FROM website_jobs ORDER BY created_at DESC"),
        ]);

        const announcementId = Number(req.query.announcementId || "");
        const jobId = Number(req.query.jobId || "");
        const editAnnouncement = Number.isFinite(announcementId) && announcementId > 0
            ? announcements.find((row) => Number(row.id) === announcementId) || null
            : null;
        const editJob = Number.isFinite(jobId) && jobId > 0
            ? jobs.find((row) => Number(row.id) === jobId) || null
            : null;

        return res.render("admin-website-content", {
            title: "Website Content",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            announcements,
            jobs,
            editAnnouncement,
            editJob,
            message: req.query.message || "",
            error: req.query.error || "",
        });
    } catch (error) {
        console.error("Error loading website content admin page:", error.message);
        return res.status(500).render("error", { title: "Website content unavailable", message: "The website content management screen could not be loaded." });
    }
});

app.post("/admin/website-content/announcements", requirePortal, requireAdmin, async (req, res) => {
    try {
        const id = req.body.id ? Number(req.body.id) : null;
        const headline = String(req.body.headline || "").trim();
        const message = String(req.body.message || "").trim();
        const color = String(req.body.color || "emerald").trim() || "emerald";
        const priority = String(req.body.priority || "normal").trim() || "normal";
        const enabled = toFlagInteger(req.body.enabled);
        const autoScroll = toFlagInteger(req.body.auto_scroll);
        const startDate = String(req.body.start_date || "").trim() || null;
        const endDate = String(req.body.end_date || "").trim() || null;

        if (!headline) {
            return res.redirect("/admin/website-content?error=Announcement headline is required");
        }

        if (id) {
            await runDb(
                `UPDATE website_announcements SET headline = ?, message = ?, color = ?, priority = ?, enabled = ?, auto_scroll = ?, start_date = ?, end_date = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
                [headline, message, color, priority, enabled, autoScroll, startDate, endDate, id]
            );
        } else {
            await runDb(
                `INSERT INTO website_announcements (headline, message, color, priority, enabled, auto_scroll, start_date, end_date, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
                [headline, message, color, priority, enabled, autoScroll, startDate, endDate]
            );
        }

        return res.redirect("/admin/website-content?message=Announcement saved successfully");
    } catch (error) {
        console.error("Error saving website announcement:", error.message);
        return res.redirect("/admin/website-content?error=The announcement could not be saved");
    }
});

app.post("/admin/website-content/announcements/delete", requirePortal, requireAdmin, async (req, res) => {
    try {
        const id = req.body.id ? Number(req.body.id) : null;
        if (id) {
            await runDb("DELETE FROM website_announcements WHERE id = ?", [id]);
        }
        return res.redirect("/admin/website-content?message=Announcement deleted");
    } catch (error) {
        console.error("Error deleting website announcement:", error.message);
        return res.redirect("/admin/website-content?error=The announcement could not be deleted");
    }
});

app.post("/admin/website-content/jobs", requirePortal, requireAdmin, async (req, res) => {
    try {
        const id = req.body.id ? Number(req.body.id) : null;
        const title = String(req.body.title || "").trim();
        const location = String(req.body.location || "").trim();
        const county = String(req.body.county || "").trim();
        const employmentType = String(req.body.employment_type || "").trim();
        const salary = String(req.body.salary || "").trim();
        const description = String(req.body.description || "").trim();
        const requirements = String(req.body.requirements || "").trim();
        const benefits = String(req.body.benefits || "").trim();
        const closingDate = String(req.body.closing_date || "").trim() || null;
        const featured = toFlagInteger(req.body.featured);
        const urgent = toFlagInteger(req.body.urgent);
        const published = toFlagInteger(req.body.published);
        const archived = toFlagInteger(req.body.archived);

        if (!title) {
            return res.redirect("/admin/website-content?error=Job title is required");
        }

        if (id) {
            await runDb(
                `UPDATE website_jobs SET title = ?, location = ?, county = ?, employment_type = ?, salary = ?, description = ?, requirements = ?, benefits = ?, closing_date = ?, featured = ?, urgent = ?, published = ?, archived = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
                [title, location, county, employmentType, salary, description, requirements, benefits, closingDate, featured, urgent, published, archived, id]
            );
        } else {
            await runDb(
                `INSERT INTO website_jobs (title, location, county, employment_type, salary, description, requirements, benefits, closing_date, featured, urgent, published, archived, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`,
                [title, location, county, employmentType, salary, description, requirements, benefits, closingDate, featured, urgent, published, archived]
            );
        }

        return res.redirect("/admin/website-content?message=Job saved successfully");
    } catch (error) {
        console.error("Error saving website job:", error.message);
        return res.redirect("/admin/website-content?error=The job could not be saved");
    }
});

app.post("/admin/website-content/jobs/delete", requirePortal, requireAdmin, async (req, res) => {
    try {
        const id = req.body.id ? Number(req.body.id) : null;
        if (id) {
            await runDb("DELETE FROM website_jobs WHERE id = ?", [id]);
        }
        return res.redirect("/admin/website-content?message=Job deleted");
    } catch (error) {
        console.error("Error deleting website job:", error.message);
        return res.redirect("/admin/website-content?error=The job could not be deleted");
    }
});

app.get("/admin/settings", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getSettingsModuleData(res.locals.adminAccess);
        return res.render("portal-settings", {
            title: "Settings",
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.adminName || "Administrator",
            currentStaffEmail: req.session.adminEmail || adminEmail,
            ...data,
            activeTab: String(req.query.tab || "company"),
            message: String(req.query.message || ""),
            error: String(req.query.error || ""),
        });
    } catch (error) {
        console.error("Error loading settings module:", error.message);
    return res.status(500).render("error", {
        title: "Settings unavailable",
        message: "The settings module could not be loaded.",
        isAdmin: true,
        returnPath: "/admin/dashboard",
    });
}
});

app.post("/admin/settings/payroll", requirePortal, requireAdmin, async (req, res) => {
    try {
        const overtimeWeeklyHours = parseFloatOrNull(req.body.overtimeWeeklyHours);
        if (overtimeWeeklyHours === null || overtimeWeeklyHours <= 0) {
            return res.redirect("/admin/settings?error=" + encodeURIComponent("Overtime threshold hours must be greater than zero."));
        }
        const updatedSettings = await savePayrollSettings({
            nightPremium: parseFloatOrNull(req.body.nightPremium),
            weekendPremium: parseFloatOrNull(req.body.weekendPremium),
            bankHolidayPremium: parseFloatOrNull(req.body.bankHolidayPremium),
            overtimePremium: parseFloatOrNull(req.body.overtimePremium),
            overtimeWeeklyHours,
            mileageRatePerKm: parseFloatOrNull(req.body.mileageRatePerKm),
        });
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "payroll_settings_updated",
            targetType: "settings",
            targetIdentifier: "payroll",
            outcome: "success",
            metadata: serializeJsonField(updatedSettings),
        });
        return res.redirect("/admin/settings?message=" + encodeURIComponent("Payroll settings updated successfully."));
    } catch (error) {
        return res.redirect("/admin/settings?error=" + encodeURIComponent(error.message || "Payroll settings could not be updated."));
    }
});

const editableSettings = {
    company: [
        "company_name", "company_email", "company_phone", "company_address", "company_website",
        "company_business_hours", "company_emergency_contact",
    ],
    branding: ["branding_logo_url", "branding_accent_note"],
    recruitment: [
        "recruitment_job_positions", "recruitment_stages", "recruitment_required_information",
        "recruitment_required_documents", "recruitment_email_template", "recruitment_notify_applicants",
        "recruitment_duplicate_email", "recruitment_duplicate_phone",
    ],
    staff: [
        "staff_categories", "staff_employment_types", "staff_statuses", "staff_onboarding_documents",
        "staff_training_requirements", "staff_id_prefix",
    ],
    scheduling: [
        "scheduling_shift_types", "scheduling_default_times", "scheduling_availability_options",
        "scheduling_cancellation_hours", "scheduling_notifications_enabled",
    ],
    notifications: [
        "notifications_enabled", "expiry_reminder_days", "shift_notification_channel",
        "notification_events",
    ],
    security: [
        "security_session_timeout_minutes", "security_password_min_length",
        "mfa_global_enabled", "mfa_role_super_admin", "mfa_role_hr",
        "mfa_role_payroll", "mfa_role_manager", "mfa_role_staff",
    ],
    compliance: [
        "compliance_expiry_warning_days", "compliance_block_expired", "compliance_required_documents",
        "compliance_training_requirements", "compliance_default_expiry_months",
    ],
    payroll: ["payroll_period", "payslip_delivery", "payroll_approval_required"],
    homecare: [
        "homecare_services", "homecare_categories", "homecare_visit_types",
        "homecare_visit_durations", "homecare_client_statuses", "homecare_plan_review_days",
    ],
    website: [
        "website_contact_email", "website_contact_phone", "website_careers_enabled",
        "website_consultation_enabled", "website_social_links", "website_footer_text",
        "website_notifications_enabled",
    ],
    privacy: ["privacy_retention_days", "privacy_deletion_review_required"],
};

app.post("/admin/settings/general/:section", requirePortal, requireAdmin, async (req, res) => {
    const section = String(req.params.section || "").trim().toLowerCase();
    const allowedKeys = editableSettings[section];
    if (!allowedKeys) {
        return res.status(404).render("error", {
            title: "Settings section not found",
            message: "The requested settings section does not exist.",
        });
    }

    try {
        if (section === "security") {
            const mfaKeys = allowedKeys.filter((key) => key.startsWith("mfa_"));
            if (mfaKeys.some((key) => !["0", "1"].includes(String(req.body[key] || "")))) {
                throw new Error("MFA policy values must be explicitly set to On or Off.");
            }
            if (String(req.body.mfa_global_enabled) === "1") {
                const requiredRoleKeys = ["super_admin", "hr", "payroll", "manager"]
                    .filter((role) => String(req.body[`mfa_role_${role}`]) === "1");
                const activeAdmins = await allDb(
                    `SELECT admin_users.id, COALESCE(roles.role_key, admin_users.role) AS role
                     FROM admin_users
                     LEFT JOIN user_roles ON user_roles.admin_user_id = admin_users.id AND user_roles.is_primary = 1
                     LEFT JOIN roles ON roles.id = user_roles.role_id
                     WHERE admin_users.is_active = 1`
                );
                const missingAccounts = [];
                for (const adminUser of activeAdmins.filter((user) => requiredRoleKeys.includes(user.role))) {
                    const account = await getMfaAccount("admin", adminUser.id);
                    if (!(await getMfaMethods(account)).length) missingAccounts.push(`${account.name || account.email} (${account.role})`);
                }
                if (String(req.body.mfa_role_staff) === "1") {
                    const activeStaffRows = await allDb(
                        `SELECT id FROM staff
                         WHERE COALESCE(portal_login_enabled, 1) = 1
                           AND COALESCE(portal_login_suspended, 0) = 0
                           AND COALESCE(portal_login_deactivated, 0) = 0
                           AND lower(COALESCE(status, 'active')) NOT IN ('inactive', 'archived', 'deleted')`
                    );
                    for (const staffMember of activeStaffRows) {
                        const account = await getMfaAccount("staff", staffMember.id);
                        if (!(await getMfaMethods(account)).length) missingAccounts.push(`${account.name || account.email} (staff)`);
                    }
                }
                if (missingAccounts.length) {
                    throw new Error(`Global MFA cannot be enabled until required accounts have a configured method: ${missingAccounts.slice(0, 8).join(", ")}${missingAccounts.length > 8 ? ` and ${missingAccounts.length - 8} more` : ""}.`);
                }
            }
        }
        for (const key of allowedKeys) {
            const value = String(req.body[key] || "").trim();
            await runDb(
                `INSERT INTO system_settings (key, value, updated_at)
                 VALUES (?, ?, CURRENT_TIMESTAMP)
                 ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = CURRENT_TIMESTAMP`,
                [key, value]
            );
        }
        if (section === "security") {
            securityPolicyCache = { loadedAt: 0, values: null };
        }
        await writeAuditEvent(req, {
            action: "settings_updated",
            targetType: "settings",
            targetIdentifier: section,
            outcome: "success",
            metadata: { keys: allowedKeys },
        });
        return res.redirect(
            `/admin/settings?tab=${encodeURIComponent(section)}&message=`
            + encodeURIComponent("Settings saved successfully.")
        );
    } catch (error) {
        return res.redirect(
            `/admin/settings?tab=${encodeURIComponent(section)}&error=`
            + encodeURIComponent(error.message || "Settings could not be saved.")
        );
    }
});

app.post("/admin/settings/system/backup", requirePortal, requireAdmin, async (req, res) => {
    const backupsDirectory = path.join(path.dirname(dbPath), "backups");
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const backupPath = path.join(backupsDirectory, `everkind-${timestamp}.db`);

    try {
        await fs.promises.mkdir(backupsDirectory, { recursive: true });
        await backupDatabase(backupPath);
        await writeAuditEvent(req, {
            action: "database_backup_created",
            targetType: "database",
            targetIdentifier: path.basename(backupPath),
            outcome: "success",
        });
        return res.redirect(
            "/admin/settings?tab=system&message="
            + encodeURIComponent(`Database backup created: ${path.basename(backupPath)}`)
        );
    } catch (error) {
        await writeAuditEvent(req, {
            action: "database_backup_created",
            targetType: "database",
            outcome: "failed",
            reason: error.message,
        });
        return res.redirect(
            "/admin/settings?tab=system&error="
            + encodeURIComponent("The database backup could not be created.")
        );
    }
});

app.get("/admin/settings/system/export", requirePortal, requireAdmin, async (req, res) => {
    try {
        const [settings, roles, permissions, rolePermissions, adminAccounts, applicationStatus] = await Promise.all([
            allDb("SELECT key, value, updated_at FROM system_settings ORDER BY key"),
            allDb("SELECT role_key, label, description, is_system, updated_at FROM roles ORDER BY role_key"),
            allDb("SELECT permission_key, module_key, action, description FROM permissions ORDER BY permission_key"),
            allDb(
                `SELECT roles.role_key, permissions.permission_key
                 FROM role_permissions
                 JOIN roles ON roles.id = role_permissions.role_id
                 JOIN permissions ON permissions.id = role_permissions.permission_id
                 ORDER BY roles.role_key, permissions.permission_key`
            ),
            allDb(
                `SELECT admin_users.id, admin_users.name, admin_users.username AS email,
                        admin_users.department, admin_users.role, admin_users.is_active,
                        admin_users.last_login, admin_users.created_at, admin_users.updated_at
                 FROM admin_users
                 ORDER BY admin_users.id`
            ),
            allDb("SELECT id, status, NULL AS updated_at FROM app_status ORDER BY id"),
        ]);
        const payload = {
            exportedAt: new Date().toISOString(),
            application: "Everkind Care System",
            settings,
            roles,
            permissions,
            rolePermissions,
            adminAccounts,
            applicationStatus,
        };
        await writeAuditEvent(req, {
            action: "system_configuration_exported",
            targetType: "system",
            targetIdentifier: "configuration",
            outcome: "success",
        });
        const filename = `everkind-system-export-${new Date().toISOString().slice(0, 10)}.json`;
        res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
        return res.type("application/json").send(JSON.stringify(payload, null, 2));
    } catch (error) {
        await writeAuditEvent(req, {
            action: "system_configuration_exported",
            targetType: "system",
            targetIdentifier: "configuration",
            outcome: "failed",
            reason: error.message,
        });
        return res.status(500).json({ success: false, message: "System configuration could not be exported." });
    }
});

const getAdminUserWithRole = (id) => getDb(
    `SELECT admin_users.*, COALESCE(roles.role_key, admin_users.role) AS assigned_role
     FROM admin_users
     LEFT JOIN user_roles
        ON user_roles.admin_user_id = admin_users.id
       AND user_roles.is_primary = 1
     LEFT JOIN roles ON roles.id = user_roles.role_id
     WHERE admin_users.id = ?`,
    [id]
);

const countActiveSuperAdmins = async () => {
    const row = await getDb(
        `SELECT COUNT(DISTINCT admin_users.id) AS count
         FROM admin_users
         LEFT JOIN user_roles
            ON user_roles.admin_user_id = admin_users.id
           AND user_roles.is_primary = 1
         LEFT JOIN roles ON roles.id = user_roles.role_id
         WHERE admin_users.is_active = 1
           AND COALESCE(roles.role_key, admin_users.role) = 'super_admin'`
    );
    return Number(row?.count || 0);
};

const assignPrimaryAdminRole = async (adminUserId, roleKey) => {
    const role = await getDb("SELECT id, role_key FROM roles WHERE role_key = ?", [roleKey]);
    if (!role) throw new Error("Select a valid administrator role.");
    await runDb("DELETE FROM user_roles WHERE admin_user_id = ? AND is_primary = 1", [adminUserId]);
    await runDb(
        `INSERT INTO user_roles
         (admin_user_id, role_id, scope_type, scope_value, is_primary)
         VALUES (?, ?, 'global', '', 1)
         ON CONFLICT(admin_user_id, role_id, scope_type, scope_value)
         DO UPDATE SET is_primary = excluded.is_primary`,
        [adminUserId, role.id]
    );
    await runDb(
        "UPDATE admin_users SET role = ?, auth_version = COALESCE(auth_version, 1) + 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        [role.role_key, adminUserId]
    );
    return role.role_key;
};

app.post("/admin/settings/users", requirePortal, requireAdmin, async (req, res) => {
    const name = String(req.body.name || "").trim();
    const email = normalizeEmailAddress(req.body.email);
    const phone = String(req.body.phone || "").trim();
    const department = String(req.body.department || "").trim();
    const roleKey = normalizeAdminRole(req.body.role);
    const password = String(req.body.password || "");
    const securityPolicy = await getSecurityPolicy();

    if (!name || !isValidEmailAddress(email) || password.length < securityPolicy.passwordMinimumLength) {
        return res.redirect(
            "/admin/settings?tab=users&error="
            + encodeURIComponent(`Name, a valid email, and a password of at least ${securityPolicy.passwordMinimumLength} characters are required.`)
        );
    }
    if (!ROLE_DEFINITIONS[roleKey]) {
        return res.redirect("/admin/settings?tab=users&error=" + encodeURIComponent("Select a valid role."));
    }

    try {
        const identity = await enforceApplicationUniqueness({ email, phone });
        const passwordHash = await hashPassword(password);
        const created = await runDb(
            `INSERT INTO admin_users
             (username, email_normalized, phone, phone_normalized, password_hash, role, name, department, is_active, auth_version, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 1, CURRENT_TIMESTAMP)`,
            [email, identity.normalizedEmail, phone || null, identity.normalizedPhone || null, passwordHash, roleKey, name, department || null]
        );
        await recordPasswordHistory("admin", created.lastID, passwordHash);
        await assignPrimaryAdminRole(created.lastID, roleKey);
        await writeAuditEvent(req, {
            action: "admin_user_created",
            targetType: "admin_user",
            targetIdentifier: String(created.lastID),
            outcome: "success",
            metadata: { email, role: roleKey, department: department || null },
        });
        return res.redirect(
            "/admin/settings?tab=users&message="
            + encodeURIComponent("Administrator created successfully.")
        );
    } catch (error) {
        await recordDuplicateIdentityAttempt(req, error, "admin_user");
        return res.redirect(
            "/admin/settings?tab=users&error="
            + encodeURIComponent(error.message || "Administrator could not be created.")
        );
    }
});

app.post("/admin/settings/users/:id", requirePortal, requireAdmin, async (req, res) => {
    const userId = Number(req.params.id);
    const name = String(req.body.name || "").trim();
    const email = normalizeEmailAddress(req.body.email);
    const phone = String(req.body.phone || "").trim();
    const department = String(req.body.department || "").trim();
    const roleKey = normalizeAdminRole(req.body.role);

    if (!Number.isInteger(userId) || !name || !isValidEmailAddress(email) || !ROLE_DEFINITIONS[roleKey]) {
        return res.redirect("/admin/settings?tab=users&error=" + encodeURIComponent("Enter valid user details."));
    }

    try {
        const target = await getAdminUserWithRole(userId);
        if (!target) throw new Error("Administrator not found.");
        if (userId === Number(req.session.adminUserId) && roleKey !== "super_admin") {
            throw new Error("You cannot remove your own Super Admin role.");
        }
        if (target.assigned_role === "super_admin" && roleKey !== "super_admin" && await countActiveSuperAdmins() <= 1) {
            throw new Error("At least one active Super Admin is required.");
        }
        const identity = await enforceApplicationUniqueness({ email, phone, excludeAdminId: userId });

        await runDb(
            `UPDATE admin_users
             SET username = ?, email_normalized = ?, phone = ?, phone_normalized = ?,
                 email_verified = CASE WHEN COALESCE(email_normalized, lower(username)) = ? THEN email_verified ELSE 0 END,
                 phone_verified = CASE WHEN COALESCE(phone_normalized, '') = COALESCE(?, '') THEN phone_verified ELSE 0 END,
                 name = ?, department = ?, updated_at = CURRENT_TIMESTAMP
             WHERE id = ?`,
            [
                email, identity.normalizedEmail, phone || null, identity.normalizedPhone || null,
                identity.normalizedEmail, identity.normalizedPhone || null,
                name, department || null, userId,
            ]
        );
        const assignedRole = await assignPrimaryAdminRole(userId, roleKey);
        await writeAuditEvent(req, {
            action: "admin_user_updated",
            targetType: "admin_user",
            targetIdentifier: String(userId),
            outcome: "success",
            metadata: { email, role: assignedRole, department: department || null },
        });
        return res.redirect(
            "/admin/settings?tab=users&message="
            + encodeURIComponent("Administrator updated successfully.")
        );
    } catch (error) {
        await recordDuplicateIdentityAttempt(req, error, "admin_user");
        return res.redirect(
            "/admin/settings?tab=users&error="
            + encodeURIComponent(error.message || "Administrator could not be updated.")
        );
    }
});

app.post("/admin/settings/users/:id/toggle", requirePortal, requireAdmin, async (req, res) => {
    const userId = Number(req.params.id);
    try {
        const target = await getAdminUserWithRole(userId);
        if (!target) throw new Error("Administrator not found.");
        if (userId === Number(req.session.adminUserId)) {
            throw new Error("You cannot disable your own account.");
        }
        const nextActive = Number(target.is_active) === 1 ? 0 : 1;
        if (!nextActive && target.assigned_role === "super_admin" && await countActiveSuperAdmins() <= 1) {
            throw new Error("At least one active Super Admin is required.");
        }
        if (nextActive) {
            await enforceApplicationUniqueness({
                email: target.username,
                phone: target.phone,
                excludeAdminId: userId,
            });
        }
        await runDb(
            `UPDATE admin_users
             SET is_active = ?, auth_version = COALESCE(auth_version, 1) + 1, updated_at = CURRENT_TIMESTAMP
             WHERE id = ?`,
            [nextActive, userId]
        );
        await writeAuditEvent(req, {
            action: nextActive ? "admin_user_enabled" : "admin_user_disabled",
            targetType: "admin_user",
            targetIdentifier: String(userId),
            outcome: "success",
            metadata: { email: target.username },
        });
        return res.redirect(
            "/admin/settings?tab=users&message="
            + encodeURIComponent(nextActive ? "Administrator enabled." : "Administrator disabled.")
        );
    } catch (error) {
        return res.redirect(
            "/admin/settings?tab=users&error="
            + encodeURIComponent(error.message || "Administrator status could not be changed.")
        );
    }
});

app.post("/admin/settings/users/:id/reset-access", requirePortal, requireAdmin, async (req, res) => {
    const userId = Number(req.params.id);
    try {
        const target = await getAdminUserWithRole(userId);
        if (!target) throw new Error("Administrator not found.");
        await runDb(
            `UPDATE admin_users
             SET auth_version = COALESCE(auth_version, 1) + 1,
                 is_active = 1,
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = ?`,
            [userId]
        );
        await writeAuditEvent(req, {
            action: "admin_access_reset",
            targetType: "admin_user",
            targetIdentifier: String(userId),
            outcome: "success",
            metadata: { email: target.username },
        });
        return res.redirect(
            "/admin/settings?tab=users&message="
            + encodeURIComponent("Access reset. Existing sessions have been revoked.")
        );
    } catch (error) {
        return res.redirect(
            "/admin/settings?tab=users&error="
            + encodeURIComponent(error.message || "Access could not be reset.")
        );
    }
});

app.post("/admin/settings/users/:id/reset-mfa", requirePortal, requireAdmin, async (req, res) => {
    const userId = Number(req.params.id);
    try {
        const target = await getAdminUserWithRole(userId);
        if (!target) throw new Error("Administrator not found.");
        if (userId === Number(req.session.adminUserId)) {
            throw new Error("Use Sign-in Security to change MFA on your own account.");
        }
        await runDb(
            `UPDATE admin_users
             SET mfa_enabled = 0,
                 totp_secret_encrypted = NULL,
                 totp_verified_at = NULL,
                 mfa_preferred_method = NULL,
                 mfa_reset_required = 1,
                 mfa_version = COALESCE(mfa_version, 1) + 1,
                 auth_version = COALESCE(auth_version, 1) + 1,
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = ?`,
            [userId]
        );
        await runDb("DELETE FROM mfa_recovery_codes WHERE account_type = 'admin' AND account_id = ?", [userId]);
        await runDb("DELETE FROM mfa_challenges WHERE account_type = 'admin' AND account_id = ?", [userId]);
        await writeAuditEvent(req, {
            action: "mfa_reset",
            targetType: "admin_user",
            targetIdentifier: String(userId),
            outcome: "success",
            metadata: { email: target.username },
        });
        return res.redirect(
            "/admin/settings?tab=users&message="
            + encodeURIComponent("MFA reset. Existing sessions were revoked and setup is required again when policy enforcement is enabled.")
        );
    } catch (error) {
        return res.redirect(
            "/admin/settings?tab=users&error="
            + encodeURIComponent(error.message || "MFA could not be reset.")
        );
    }
});

app.post("/admin/view-as", requirePortal, requireAdmin, async (req, res) => {
    const previewRole = String(req.body.role || "").trim().toLowerCase();
    if (!ROLE_DEFINITIONS[previewRole] && previewRole !== "staff") {
        return res.redirect("/admin/settings?error=" + encodeURIComponent("Select a valid preview role."));
    }
    req.session.adminPreviewRole = previewRole;
    await writeAuditEvent(req, {
        action: "role_preview_started",
        targetType: "role",
        targetIdentifier: previewRole,
        outcome: "success",
    });
    const redirectByRole = {
        hr: "/admin/hr-dashboard",
        payroll: "/admin/payroll",
        manager: "/admin/dashboard",
        staff: "/admin/preview/staff",
    };
    return res.redirect(redirectByRole[previewRole] || "/admin/dashboard");
});

app.post("/admin/view-as/exit", requirePortal, requireAdmin, async (req, res) => {
    const previousRole = req.session.adminPreviewRole || null;
    req.session.adminPreviewRole = null;
    await writeAuditEvent(req, {
        action: "role_preview_ended",
        targetType: "role",
        targetIdentifier: previousRole,
        outcome: "success",
    });
    return res.redirect("/admin/dashboard?message=" + encodeURIComponent("Role preview ended."));
});

app.get("/admin/preview/staff", requirePortal, async (req, res) => {
    const adminUser = await getDb("SELECT * FROM admin_users WHERE id = ?", [Number(req.session.adminUserId) || -1]);
    if (!adminUser || Number(adminUser.is_active) !== 1) {
        return res.status(403).render("access-denied", {
            title: "Access denied",
            message: "Super Admin access is required.",
            requiredPermission: "users.manage",
            currentRole: "Unknown",
            currentStaffName: "Administrator",
            currentStaffEmail: "",
            isAdmin: false,
        });
    }
    const access = await loadAdminAccessContext(adminUser, req.session.adminPreviewRole);
    if (access.actualRole !== "super_admin" || access.effectiveRole !== "staff") {
        return res.redirect("/admin/settings");
    }
    return res.render("role-preview", {
        title: "Staff Portal Preview",
        isAdmin: true,
        currentStaffName: adminUser.name || "Administrator",
        currentStaffEmail: adminUser.username,
        adminAccess: access,
    });
});

const renderPatientForm = async (req, res, { title, mode, patient, error = null, statusCode = 200 }) => {
    const staffOptions = await getActiveStaffMembers();
    return res.status(statusCode).render("patient-form", {
        title,
        mode,
        patient: createPatientFormState(patient),
        error,
        staffOptions,
        patientStatusOptions,
        careNeedCatalog,
        schedulingPreferenceOptions,
        careTeamRoles,
        documentCategories,
        isLoggedIn: true,
        isAdmin: true,
        currentStaffName: req.session.staffName || "Administrator",
        currentStaffEmail: req.session.staffEmail || adminEmail,
    });
};

app.get("/patients/new", requirePortal, requireAdmin, async (req, res) => {
    try {
        return renderPatientForm(req, res, {
            title: "Add client",
            mode: "new",
            patient: createPatientFormState(),
        });
    } catch (error) {
        console.error("Error loading patient form:", error.message);
        return res.status(500).render("error", { title: "Client form unavailable", message: "The client form could not be loaded." });
    }
});

app.post("/patients", requirePortal, requireAdmin, async (req, res) => {
    try {
        const payload = buildPatientPayloadFromBody(req.body);
        const validationError = validatePatientPayload(payload);
        if (validationError) {
            return renderPatientForm(req, res, {
                title: "Add client",
                mode: "new",
                patient: payload,
                error: validationError,
                statusCode: 400,
            });
        }

        const values = patientWritableColumns.map((column) => payload[column]);
        const result = await runDb(
            `INSERT INTO patients (${patientWritableColumns.join(", ")}, name, created_at, updated_at)
             VALUES (${patientWritableColumns.map(() => "?").join(", ")}, ?, datetime('now'), datetime('now'))`,
            [...values, formatName(payload.first_name, payload.last_name)]
        );
        await runDb("UPDATE patients SET home_care_client_id = ? WHERE id = ?", [`HC-${String(result.lastID || "").padStart(5, "0")}`, Number(result.lastID)]);
        await syncPatientAssignments(result.lastID, payload.assignments);
        await syncPatientDocuments(result.lastID, payload.documents, getActorContext(req).actorIdentifier || "system");

        for (const assignment of payload.assignments) {
            await queueStaffNotification(
                assignment.staffId,
                "New client assigned",
                `${formatName(payload.first_name, payload.last_name)} has been assigned to you as ${assignment.assignmentLabel}.`,
                "shift",
                "/portal/home"
            );
        }

        if (payload.status !== "Active") {
            await applyPatientStatusAutomation(result.lastID, payload.status, formatName(payload.first_name, payload.last_name), payload.assignments.map((assignment) => assignment.staffId));
        }

        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "patient_created",
            targetType: "patient",
            targetIdentifier: String(result.lastID),
            outcome: "success",
        });
        emitPortalEvent("patient_update", { action: "created", patientId: Number(result.lastID) });
        return res.redirect(`/patients/${result.lastID}?message=${encodeURIComponent("Client created successfully.")}`);
    } catch (error) {
        console.error("Error creating patient:", error.message);
        return renderPatientForm(req, res, {
            title: "Add client",
            mode: "new",
            patient: buildPatientPayloadFromBody(req.body),
            error: "The client record could not be saved.",
            statusCode: 500,
        });
    }
});

app.get("/patients", requirePortal, requireAdmin, async (req, res) => {
    try {
        const data = await getHomeCareClientsModuleData();

        res.render("patients", {
            title: "Home Care Clients",
            patients: data.patients,
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            message: String(req.query.message || ""),
        });
    } catch (error) {
        console.error("Error loading patients:", error.message);
        res.status(500).render("error", {
            title: "Patients unavailable",
            message: "The patient directory could not be loaded.",
        });
    }
});

app.get("/patients/:id/edit", requirePortal, requireAdmin, async (req, res) => {
    try {
        const patientId = Number(req.params.id);
        const patient = mapPatientRow(await getDb("SELECT * FROM patients WHERE id = ? AND COALESCE(is_archived, 0) = 0", [patientId]));
        if (!patient) {
            return res.status(404).render("error", { title: "Client not found", message: "The requested client record could not be found." });
        }

        const [assignments, documents] = await Promise.all([
            getPatientAssignments(patientId),
            allDb("SELECT * FROM patient_documents WHERE patient_id = ? ORDER BY category, title", [patientId]),
        ]);

        return renderPatientForm(req, res, {
            title: `Edit ${patient.name}`,
            mode: "edit",
            patient: {
                ...patient,
                assignments: assignments.map((assignment) => ({
                    assignmentRole: assignment.assignment_role,
                    staffId: Number(assignment.staff_id),
                    assignmentLabel: careTeamRoles.find((role) => role.key === assignment.assignment_role)?.label || assignment.assignment_role,
                })),
                documents: documents.map((document) => ({
                    id: document.id,
                    title: document.title,
                    category: document.category,
                    fileName: document.file_name,
                    mimeType: document.mime_type,
                    dataUrl: document.data_url,
                    isStaffVisible: Boolean(Number(document.is_staff_visible || 0)),
                })),
            },
        });
    } catch (error) {
        console.error("Error loading patient edit form:", error.message);
        return res.status(500).render("error", { title: "Client form unavailable", message: "The client form could not be loaded." });
    }
});

app.post("/patients/:id/update", requirePortal, requireAdmin, async (req, res) => {
    try {
        const patientId = Number(req.params.id);
        const existingPatient = mapPatientRow(await getDb("SELECT * FROM patients WHERE id = ? AND COALESCE(is_archived, 0) = 0", [patientId]));
        if (!existingPatient) {
            return res.status(404).render("error", { title: "Client not found", message: "The requested client record could not be found." });
        }

        const previousAssignments = await getPatientAssignments(patientId);
        const previousStaffIds = previousAssignments.map((assignment) => Number(assignment.staff_id)).filter(Boolean);
        const payload = buildPatientPayloadFromBody(req.body);
        const validationError = validatePatientPayload(payload);
        if (validationError) {
            return renderPatientForm(req, res, {
                title: `Edit ${existingPatient.name}`,
                mode: "edit",
                patient: { ...payload, id: patientId },
                error: validationError,
                statusCode: 400,
            });
        }

        const updateAssignments = patientWritableColumns.map((column) => `${column} = ?`);
        const updateValues = patientWritableColumns.map((column) => payload[column]);
        await runDb(
            `UPDATE patients
             SET ${updateAssignments.join(", ")},
                 name = ?,
                 updated_at = datetime('now'),
                 is_archived = CASE WHEN ? = 'Archived' OR ? = 'Deceased' THEN 1 ELSE 0 END,
                 archived_at = CASE WHEN ? = 'Archived' OR ? = 'Deceased' THEN datetime('now') ELSE archived_at END
             WHERE id = ?`,
            [
                ...updateValues,
                formatName(payload.first_name, payload.last_name),
                payload.status,
                payload.status,
                payload.status,
                payload.status,
                patientId,
            ]
        );
        await syncPatientAssignments(patientId, payload.assignments);
        await syncPatientDocuments(patientId, payload.documents, getActorContext(req).actorIdentifier || "system");

        await runDb(
            `UPDATE staff_shifts
             SET care_instructions = CASE
                 WHEN COALESCE(care_instructions, '') = '' THEN ?
                 ELSE care_instructions
             END
             WHERE patient_id = ?
               AND datetime(COALESCE(scheduled_start, shift_date)) >= datetime('now')
               AND status IN ('scheduled', 'clocked_in', 'clocked_out')`,
            [payload.shift_instructions, patientId]
        );

        const assignmentStaffIds = payload.assignments.map((assignment) => assignment.staffId);
        const allAffectedStaffIds = [...new Set([...previousStaffIds, ...assignmentStaffIds])];
        for (const staffId of assignmentStaffIds.filter((staffId) => !previousStaffIds.includes(staffId))) {
            const assignment = payload.assignments.find((entry) => entry.staffId === staffId);
            await queueStaffNotification(
                staffId,
                "Client assigned",
                `${formatName(payload.first_name, payload.last_name)} has been assigned to you as ${assignment ? assignment.assignmentLabel : "care team member"}.`,
                "shift",
                "/portal/home"
            );
        }
        for (const staffId of allAffectedStaffIds) {
            await queueStaffNotification(
                staffId,
                "Client profile updated",
                `${formatName(payload.first_name, payload.last_name)}'s client profile has been updated.`,
                "info",
                "/portal/home"
            );
        }

        if (existingPatient.status !== payload.status) {
            await applyPatientStatusAutomation(patientId, payload.status, formatName(payload.first_name, payload.last_name), allAffectedStaffIds);
            await writeAuditEvent(req, {
                ...getActorContext(req),
                action: "patient_status_updated",
                targetType: "patient",
                targetIdentifier: String(patientId),
                outcome: "success",
                reason: `${existingPatient.status} -> ${payload.status}`,
            });
        } else {
            emitPortalEvent("patient_update", { action: "updated", patientId: Number(patientId) });
        }

        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "patient_updated",
            targetType: "patient",
            targetIdentifier: String(patientId),
            outcome: "success",
        });
        return res.redirect(`/patients/${patientId}?message=${encodeURIComponent("Client record updated successfully.")}`);
    } catch (error) {
        console.error("Error updating patient:", error.message);
        return renderPatientForm(req, res, {
            title: "Edit client",
            mode: "edit",
            patient: { ...buildPatientPayloadFromBody(req.body), id: Number(req.params.id) },
            error: "The client record could not be updated.",
            statusCode: 500,
        });
    }
});

app.post("/patients/:id/delete", requirePortal, requireAdmin, async (req, res) => {
    try {
        const patientId = Number(req.params.id);
        const patient = mapPatientRow(await getDb("SELECT * FROM patients WHERE id = ? AND COALESCE(is_archived, 0) = 0", [patientId]));
        if (!patient) {
            return res.status(404).render("error", { title: "Client not found", message: "The requested client record could not be found." });
        }
        const assignments = await getPatientAssignments(patientId);
        await runDb(
            `UPDATE patients
             SET status = 'Archived',
                 is_archived = 1,
                 archived_at = datetime('now'),
                 updated_at = datetime('now')
             WHERE id = ?`,
            [patientId]
        );
        await applyPatientStatusAutomation(patientId, "Archived", patient.name, assignments.map((assignment) => Number(assignment.staff_id)).filter(Boolean));
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "patient_archived",
            targetType: "patient",
            targetIdentifier: String(patientId),
            outcome: "success",
        });
        return res.redirect(`/patients?message=${encodeURIComponent(`${patient.name} was archived.`)}`);
    } catch (error) {
        console.error("Error archiving patient:", error.message);
        return res.status(500).render("error", { title: "Archive failed", message: "The client record could not be archived." });
    }
});

app.get("/patients/:id", requirePortal, requireAdmin, async (req, res) => {
    try {
        const patientId = Number(req.params.id);
        const patient = mapPatientRow(await getDb(
            "SELECT * FROM patients WHERE id = ? AND COALESCE(is_archived, 0) = 0",
            [patientId]
        ));

        if (!patient) {
            return res.status(404).render("error", {
                title: "Patient not found",
                message: "The requested patient record could not be found.",
            });
        }

        const [notes, assignments, documents, auditEvents] = await Promise.all([
            allDb("SELECT * FROM care_notes WHERE patient_id = ? ORDER BY created_at DESC", [patientId]),
            getPatientAssignments(patientId),
            allDb("SELECT * FROM patient_documents WHERE patient_id = ? ORDER BY category, title", [patientId]),
            allDb(
                `SELECT actor_type, actor_identifier, action, outcome, reason, created_at
                 FROM audit_events
                 WHERE target_type = 'patient' AND target_identifier = ?
                 ORDER BY created_at DESC
                 LIMIT 20`,
                [String(patientId)]
            ),
        ]);

        return res.render("patient-detail", {
            title: `${patient.name} | Home Care Client Detail`,
            patient,
            notes,
            assignments,
            documents,
            auditEvents,
            message: String(req.query.message || ""),
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
        });
    } catch (error) {
        console.error("Error loading patient detail:", error.message);
        return res.status(500).render("error", {
            title: "Patient details unavailable",
            message: "The patient record could not be loaded.",
        });
    }
});

app.post("/patients/:id/notes", requirePortal, requireAdmin, async (req, res) => {
    try {
        const patientId = Number(req.params.id);
        const author = String(req.body.author || "").trim();
        const severity = ["Normal", "Watch", "Critical"].includes(String(req.body.severity || "").trim())
            ? String(req.body.severity).trim()
            : "Normal";
        const note = String(req.body.note || "").trim();

        if (!Number.isInteger(patientId) || patientId <= 0) {
            return res.status(400).render("error", { title: "Invalid client", message: "A valid client id is required." });
        }
        if (!author || !note) {
            return res.redirect(`/patients/${patientId}?message=${encodeURIComponent("Author and care observation are required.")}`);
        }

        await runDb(
            `INSERT INTO care_notes (patient_id, author, note, severity, retention_expires_at)
             VALUES (?, ?, ?, ?, datetime('now', '+${defaultPatientRetentionDays} days'))`,
            [patientId, author, note, severity]
        );
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "patient_note_added",
            targetType: "patient",
            targetIdentifier: String(patientId),
            outcome: "success",
        });
        emitPortalEvent("patient_update", { action: "note_added", patientId });
        return res.redirect(`/patients/${patientId}?message=${encodeURIComponent("Care note added successfully.")}`);
    } catch (error) {
        console.error("Error saving patient note:", error.message);
        return res.redirect(`/patients/${req.params.id}?message=${encodeURIComponent("The care note could not be saved.")}`);
    }
});

app.get("/patients/:patientId/documents/:documentId/download", requirePortal, async (req, res) => {
    try {
        const patientId = Number(req.params.patientId);
        const documentId = Number(req.params.documentId);
        if (!Number.isInteger(patientId) || patientId <= 0 || !Number.isInteger(documentId) || documentId <= 0) {
            return res.status(400).render("error", { title: "Invalid document", message: "A valid client document is required." });
        }

        const document = await getDb("SELECT * FROM patient_documents WHERE id = ? AND patient_id = ?", [documentId, patientId]);
        if (!document) {
            return res.status(404).render("error", { title: "Document not found", message: "The requested client document could not be found." });
        }

        if (!req.session.isAdmin) {
            const assignment = await getDb(
                `SELECT id FROM patient_assignments
                 WHERE patient_id = ? AND staff_id = ?`,
                [patientId, Number(req.session.staffId)]
            );
            const shiftAccess = await getDb(
                `SELECT id FROM staff_shifts
                 WHERE patient_id = ? AND staff_id = ?`,
                [patientId, Number(req.session.staffId)]
            );
            if ((!assignment && !shiftAccess) || !Number(document.is_staff_visible || 0)) {
                return res.status(403).render("error", { title: "Access denied", message: "You do not have permission to access this client document." });
            }
        }

        const dataUrlMatch = String(document.data_url || "").match(/^data:(.*?);base64,(.*)$/);
        if (!dataUrlMatch) {
            res.setHeader("Content-Type", document.mime_type || "text/plain; charset=utf-8");
            res.setHeader("Content-Disposition", `attachment; filename="${document.file_name || "client-document"}"`);
            return res.send(document.data_url || document.title);
        }

        const [, mimeType, base64Payload] = dataUrlMatch;
        const buffer = Buffer.from(base64Payload, "base64");
        res.setHeader("Content-Type", mimeType || "application/octet-stream");
        res.setHeader("Content-Disposition", `attachment; filename="${document.file_name || "client-document"}"`);
        return res.send(buffer);
    } catch (error) {
        console.error("Error downloading client document:", error.message);
        return res.status(500).render("error", { title: "Document unavailable", message: "The client document could not be downloaded." });
    }
});

const syncStaffDocuments = async (staffId, documentsPayload = {}) => {
    if (!staffId) {
        return;
    }

    await runDb("DELETE FROM staff_documents WHERE staff_id = ?", [staffId]);
    const documentEntries = Object.entries(documentsPayload || {}).filter(([, value]) => value && String(value).trim());

    for (const [category, value] of documentEntries) {
        const dataUrl = String(value || "").trim();
        if (!dataUrl) {
            continue;
        }

        const title = category.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
        const fileName = `${slugifyValue(category)}-${Date.now()}${dataUrl.startsWith("data:image") ? ".png" : ".txt"}`;
        await runDb(
            `INSERT INTO staff_documents (staff_id, title, category, file_name, download_text)
             VALUES (?, ?, ?, ?, ?)`,
            [staffId, title, category, fileName, dataUrl]
        );
    }
};

app.get("/staff", requirePortal, requireAdmin, async (req, res) => {
    try {
        const staff = (await allDb("SELECT * FROM staff ORDER BY id")).map(mapStaffRow);
        const inductionStaff = staff.filter((member) => String(member.status || "").toLowerCase() === "induction");
        const activeStaff = staff.filter((member) => String(member.status || "").toLowerCase() !== "induction");
        const rosterStaff = staff.filter((member) => {
            const normalizedStatus = String(member.status || "").toLowerCase();
            return !["archived", "resigned", "suspended", "inactive"].includes(normalizedStatus);
        });
        res.render("staff", {
            title: "Staff Management",
            staff,
            inductionStaff,
            activeStaff,
            rosterStaff,
            highlightedStaffId: Number(req.query.highlight || 0),
            activeSection: String(req.query.section || "").trim().toLowerCase(),
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
        });
    } catch (error) {
        console.error("Error loading staff directory:", error.message);
        res.status(500).render("error", {
            title: "Staff directory unavailable",
            message: "The staff directory could not be loaded.",
        });
    }
});

app.post("/staff/:id/approve-employment", requirePortal, requireAdmin, async (req, res) => {
    try {
        const staffId = Number(req.params.id);
        if (!Number.isInteger(staffId) || staffId <= 0) {
            return res.status(400).render("error", {
                title: "Invalid staff member",
                message: "A valid staff member is required.",
            });
        }

        const staffMember = await getDb("SELECT id FROM staff WHERE id = ?", [staffId]);
        if (!staffMember) {
            return res.status(404).render("error", {
                title: "Staff member not found",
                message: "The selected staff member could not be found.",
            });
        }

        await runDb(
            `UPDATE staff
             SET status = 'Active',
                 employment_status = 'Active',
                 portal_login_enabled = 1,
                 portal_login_suspended = 0,
                 portal_login_deactivated = 0
             WHERE id = ?`,
            [staffId]
        );

        return res.redirect(`/staff?highlight=${staffId}`);
    } catch (error) {
        console.error("Error approving staff employment:", error.message);
        return res.status(500).render("error", {
            title: "Approval failed",
            message: "The staff member could not be approved for full employment.",
        });
    }
});

app.post("/staff/:id/induction-checklist", requirePortal, requireAdmin, async (req, res) => {
    try {
        const staffId = Number(req.params.id);
        if (!Number.isInteger(staffId) || staffId <= 0) {
            return res.status(400).render("error", {
                title: "Invalid staff member",
                message: "A valid staff member is required.",
            });
        }

        const staffMember = mapStaffRow(await getDb("SELECT * FROM staff WHERE id = ?", [staffId]));
        if (!staffMember) {
            return res.status(404).render("error", {
                title: "Staff member not found",
                message: "The selected staff member could not be found.",
            });
        }

        const existingByKey = new Map((staffMember.inductionChecklist || []).map((item) => [item.key, item]));
        const completedAt = new Date().toISOString();
        const checklist = inductionChecklistTemplates.map((template) => {
            const current = existingByKey.get(template.key);
            const completed = toFlagInteger(req.body[`induction_${template.key}`]) === 1;
            return {
                key: template.key,
                label: template.label,
                description: template.description,
                completed,
                completedAt: completed ? (current && current.completed ? current.completedAt : completedAt) : null,
                notes: current && current.notes ? current.notes : "",
            };
        });

        await runDb("UPDATE staff SET induction_checklist = ? WHERE id = ?", [serializeJsonField(checklist), staffId]);
        return res.redirect(`/staff/${staffId}#induction-checklist`);
    } catch (error) {
        console.error("Error updating induction checklist:", error.message);
        return res.status(500).render("error", {
            title: "Checklist update failed",
            message: "The induction checklist could not be updated.",
        });
    }
});

app.get("/staff/new", requirePortal, requireAdmin, async (req, res) => {
    try {
        const patients = (await allDb("SELECT id, first_name, last_name, name FROM patients ORDER BY first_name")).map(mapPatientRow);
        res.render("staff-form", {
            title: "Add staff member",
            mode: "new",
            staffMember: null,
            assignedClientIds: [],
            patients,
            error: null,
            isLoggedIn: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            staffRoleOptions,
            staffEmploymentTypeOptions,
            staffServiceTypeOptions,
            staffStatusOptions,
            staffQualificationOptions,
            staffSkillOptions,
            staffMandatoryTrainingOptions,
            staffCertificationOptions,
            staffLanguageOptions,
            staffAvailabilityDayOptions,
            staffShiftPreferenceOptions,
            staffDocumentCategories,
        });
    } catch (error) {
        console.error("Error loading staff form:", error.message);
        return res.status(500).render("error", {
            title: "Staff form unavailable",
            message: "The staff form could not be loaded.",
        });
    }
});

app.get("/staff/:id/edit", requirePortal, requireAdmin, async (req, res) => {
    try {
        const staffMember = mapStaffRow(await getDb("SELECT * FROM staff WHERE id = ?", [Number(req.params.id)]));

        if (!staffMember) {
            return res.status(404).render("error", {
                title: "Staff member not found",
                message: "The requested staff record could not be found.",
            });
        }

        const patients = (await allDb("SELECT id, first_name, last_name, name FROM patients ORDER BY first_name")).map(mapPatientRow);
        const assignedClientRows = await allDb(
            "SELECT patient_id FROM patient_assignments WHERE staff_id = ? AND assignment_role = 'assigned' ORDER BY patient_id",
            [staffMember.id]
        );
        const assignedClientIds = assignedClientRows.map((row) => Number(row.patient_id));

        return res.render("staff-form", {
            title: `Edit ${staffMember.name}`,
            mode: "edit",
            staffMember,
            assignedClientIds,
            patients,
            error: null,
            isLoggedIn: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            staffRoleOptions,
            staffEmploymentTypeOptions,
            staffServiceTypeOptions,
            staffStatusOptions,
            staffQualificationOptions,
            staffSkillOptions,
            staffMandatoryTrainingOptions,
            staffCertificationOptions,
            staffLanguageOptions,
            staffAvailabilityDayOptions,
            staffShiftPreferenceOptions,
            staffDocumentCategories,
        });
    } catch (error) {
        console.error("Error loading staff form:", error.message);
        return res.status(500).render("error", {
            title: "Staff form unavailable",
            message: "The staff form could not be loaded.",
        });
    }
});

app.post("/staff", requirePortal, requireAdmin, async (req, res) => {
    try {
        const profilePayload = buildStaffProfilePayload(req.body);
        const email = profilePayload.email;
        const patients = (await allDb("SELECT id, first_name, last_name, name FROM patients ORDER BY first_name")).map(mapPatientRow);

        if (!profilePayload.name) {
            return res.status(400).render("staff-form", {
                title: "Add staff member",
                mode: "new",
                staffMember: null,
                assignedClientIds: profilePayload.assignedClientIds.map((value) => Number(value)).filter((value) => Number.isFinite(value)),
                patients,
                error: "A staff member name is required.",
                isLoggedIn: true,
                currentStaffName: req.session.staffName || "Administrator",
                currentStaffEmail: req.session.staffEmail || adminEmail,
                staffRoleOptions,
                staffEmploymentTypeOptions,
                staffServiceTypeOptions,
                staffStatusOptions,
                staffQualificationOptions,
                staffSkillOptions,
                staffMandatoryTrainingOptions,
                staffCertificationOptions,
                staffLanguageOptions,
                staffAvailabilityDayOptions,
                staffShiftPreferenceOptions,
                staffDocumentCategories,
            });
        }

        if (!email) {
            return res.status(400).render("staff-form", {
                title: "Add staff member",
                mode: "new",
                staffMember: null,
                assignedClientIds: profilePayload.assignedClientIds.map((value) => Number(value)).filter((value) => Number.isFinite(value)),
                patients,
                error: "A staff email is required so the account can be created automatically.",
                isLoggedIn: true,
                currentStaffName: req.session.staffName || "Administrator",
                currentStaffEmail: req.session.staffEmail || adminEmail,
                staffRoleOptions,
                staffEmploymentTypeOptions,
                staffServiceTypeOptions,
                staffStatusOptions,
                staffQualificationOptions,
                staffSkillOptions,
                staffMandatoryTrainingOptions,
                staffCertificationOptions,
                staffLanguageOptions,
                staffAvailabilityDayOptions,
                staffShiftPreferenceOptions,
                staffDocumentCategories,
            });
        }

        const identity = await enforceApplicationUniqueness({
            email: profilePayload.email,
            phone: profilePayload.mobileNumber || profilePayload.phone,
        });
        const passwordHash = await hashPassword(staffDefaultPassword);
        const insertResult = await runDb(
            `INSERT INTO staff
             (name, first_name, last_name, role, email, phone, status, password_hash, shift, address, emergency_contact, availability, manager_name, start_date, nationality, languages, employee_number, preferred_name, profile_photo, date_of_birth, gender, pps_number, driving_licence_number, driving_licence_categories, own_vehicle, right_to_work, visa_type, visa_expiry_date, passport_number, passport_expiry_date, mobile_number, alternative_phone, home_address, eircode, county, emergency_contact_name, emergency_contact_relationship, emergency_contact_phone, emergency_contact_email, employment_type, service_types, employment_status, end_date, hourly_rate, payroll_number, branch, qqi_qualifications, professional_registration, other_qualifications, skills_specialities, mandatory_training, additional_certifications, availability_days, shift_preferences, weekend_availability, bank_holidays, max_weekly_hours, preferred_working_area, internal_notes, staff_notes, compliance_summary, portal_login_enabled, portal_login_suspended, portal_login_deactivated, welcome_email_sent)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)` ,
            [
                profilePayload.name,
                profilePayload.firstName,
                profilePayload.lastName,
                profilePayload.role,
                profilePayload.email,
                profilePayload.phone,
                profilePayload.status,
                passwordHash,
                profilePayload.shift,
                profilePayload.homeAddress,
                profilePayload.emergencyContactName,
                profilePayload.availability,
                profilePayload.managerName,
                profilePayload.startDate,
                profilePayload.nationality,
                profilePayload.languages,
                profilePayload.employeeNumber,
                profilePayload.preferredName,
                profilePayload.profilePhoto,
                profilePayload.dateOfBirth,
                profilePayload.gender,
                profilePayload.ppsNumber,
                profilePayload.drivingLicenceNumber,
                profilePayload.drivingLicenceCategories,
                profilePayload.ownVehicle,
                profilePayload.rightToWork,
                profilePayload.visaType,
                profilePayload.visaExpiryDate,
                profilePayload.passportNumber,
                profilePayload.passportExpiryDate,
                profilePayload.mobileNumber,
                profilePayload.alternativePhone,
                profilePayload.homeAddress,
                profilePayload.eircode,
                profilePayload.county,
                profilePayload.emergencyContactName,
                profilePayload.emergencyContactRelationship,
                profilePayload.emergencyContactPhone,
                profilePayload.emergencyContactEmail,
                profilePayload.employmentType,
                profilePayload.serviceTypes,
                profilePayload.employmentStatus,
                profilePayload.endDate,
                profilePayload.hourlyRate,
                profilePayload.payrollNumber,
                profilePayload.branch,
                profilePayload.qqiQualifications,
                profilePayload.professionalRegistration,
                profilePayload.otherQualifications,
                profilePayload.skillsSpecialities,
                profilePayload.mandatoryTraining,
                profilePayload.additionalCertifications,
                profilePayload.availabilityDays,
                profilePayload.shiftPreferences,
                profilePayload.weekendAvailability,
                profilePayload.bankHolidays,
                profilePayload.maxWeeklyHours,
                profilePayload.preferredWorkingArea,
                profilePayload.internalNotes,
                profilePayload.staffNotes,
                profilePayload.complianceSummary,
                profilePayload.portalLoginEnabled,
                profilePayload.portalLoginSuspended,
                profilePayload.portalLoginDeactivated,
                profilePayload.welcomeEmailSent,
            ]
        );
        const newStaffId = insertResult.lastID;
        await runDb(
            "UPDATE staff SET email_normalized = ?, phone_normalized = ? WHERE id = ?",
            [identity.normalizedEmail || null, identity.normalizedPhone || null, newStaffId]
        );
        await recordPasswordHistory("staff", newStaffId, passwordHash);
        await runDb(
            `UPDATE staff
             SET training_records = ?, certification_records = ?, nmbi_number = ?, nmbi_expiry_date = ?,
                 garda_vetting_status = ?, garda_vetting_expiry_date = ?, force_password_reset = ?
             WHERE id = ?`,
            [
                profilePayload.trainingRecords,
                profilePayload.certificationRecords,
                profilePayload.nmbiNumber,
                profilePayload.nmbiExpiryDate,
                profilePayload.gardaVettingStatus,
                profilePayload.gardaVettingExpiryDate,
                profilePayload.forcePasswordReset,
                newStaffId,
            ]
        );
        await runDb("DELETE FROM patient_assignments WHERE staff_id = ? AND assignment_role = 'assigned'", [newStaffId]);
        for (const patientId of profilePayload.assignedClientIds) {
            const numericId = Number(patientId);
            if (Number.isFinite(numericId) && numericId > 0) {
                await runDb("INSERT INTO patient_assignments (patient_id, staff_id, assignment_role) VALUES (?, ?, 'assigned')", [numericId, newStaffId]);
            }
        }

        await syncStaffDocuments(newStaffId, req.body.documents || {});
        await writeAuditEvent(req, { action: "create", targetType: "staff", targetIdentifier: String(newStaffId), outcome: "success", reason: "Created a staff member via the admin form" });
        return res.redirect(`/staff/${newStaffId}`);
    } catch (error) {
        await recordDuplicateIdentityAttempt(req, error, "staff");
        console.error("Error creating staff member:", error.message);
        const duplicateIdentity = ["APPLICATION_DUPLICATE_EMAIL", "APPLICATION_DUPLICATE_PHONE"].includes(error.code);
        return res.status(duplicateIdentity ? 409 : 500).render("staff-form", {
            title: "Add staff member",
            mode: "new",
            staffMember: null,
            assignedClientIds: [],
            patients: (await allDb("SELECT id, first_name, last_name, name FROM patients ORDER BY first_name")).map(mapPatientRow),
            error: duplicateIdentity ? error.message : "The staff record could not be saved.",
            isLoggedIn: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            staffRoleOptions,
            staffEmploymentTypeOptions,
            staffServiceTypeOptions,
            staffStatusOptions,
            staffQualificationOptions,
            staffSkillOptions,
            staffMandatoryTrainingOptions,
            staffCertificationOptions,
            staffLanguageOptions,
            staffAvailabilityDayOptions,
            staffShiftPreferenceOptions,
            staffDocumentCategories,
        });
    }
});

app.post("/staff/:id/reset-mfa", requirePortal, requireAdmin, requireSuperAdmin, async (req, res) => {
    const staffId = Number(req.params.id);
    try {
        const staffMember = await getDb("SELECT id, email FROM staff WHERE id = ?", [staffId]);
        if (!staffMember) throw new Error("Staff member not found.");
        await runDb(
            `UPDATE staff
             SET mfa_enabled = 0,
                 totp_secret_encrypted = NULL,
                 totp_verified_at = NULL,
                 mfa_preferred_method = NULL,
                 mfa_reset_required = 1,
                 mfa_version = COALESCE(mfa_version, 1) + 1,
                 updated_at = CURRENT_TIMESTAMP
             WHERE id = ?`,
            [staffId]
        );
        await runDb("DELETE FROM mfa_recovery_codes WHERE account_type = 'staff' AND account_id = ?", [staffId]);
        await runDb("DELETE FROM mfa_challenges WHERE account_type = 'staff' AND account_id = ?", [staffId]);
        await writeAuditEvent(req, {
            action: "mfa_reset",
            targetType: "staff_user",
            targetIdentifier: String(staffId),
            outcome: "success",
            metadata: { email: staffMember.email },
        });
        return res.redirect(`/staff/${staffId}/edit?message=${encodeURIComponent("MFA reset. Existing sessions were revoked and MFA setup is required again when enforced.")}`);
    } catch (error) {
        return res.redirect(`/staff/${staffId}/edit?error=${encodeURIComponent(error.message || "MFA could not be reset.")}`);
    }
});

app.post("/staff/:id/update", requirePortal, requireAdmin, async (req, res) => {
    try {
        const id = Number(req.params.id);
        const profilePayload = buildStaffProfilePayload(req.body, await getDb("SELECT * FROM staff WHERE id = ?", [id]));
        const patients = (await allDb("SELECT id, first_name, last_name, name FROM patients ORDER BY first_name")).map(mapPatientRow);
        const assignedClientIds = profilePayload.assignedClientIds.map((value) => Number(value)).filter((value) => Number.isFinite(value));

        if (!profilePayload.name) {
            const currentStaffMember = mapStaffRow(await getDb("SELECT * FROM staff WHERE id = ?", [id]));
            return res.status(400).render("staff-form", {
                title: `Edit ${currentStaffMember ? currentStaffMember.name : "staff member"}`,
                mode: "edit",
                staffMember: currentStaffMember,
                assignedClientIds,
                patients,
                error: "A staff member name is required.",
                isLoggedIn: true,
                currentStaffName: req.session.staffName || "Administrator",
                currentStaffEmail: req.session.staffEmail || adminEmail,
                staffRoleOptions,
                staffEmploymentTypeOptions,
                staffServiceTypeOptions,
                staffStatusOptions,
                staffQualificationOptions,
                staffSkillOptions,
                staffMandatoryTrainingOptions,
                staffCertificationOptions,
                staffLanguageOptions,
                staffAvailabilityDayOptions,
                staffShiftPreferenceOptions,
                staffDocumentCategories,
            });
        }

        if (!profilePayload.email) {
            const currentStaffMember = mapStaffRow(await getDb("SELECT * FROM staff WHERE id = ?", [id]));
            return res.status(400).render("staff-form", {
                title: `Edit ${currentStaffMember ? currentStaffMember.name : "staff member"}`,
                mode: "edit",
                staffMember: currentStaffMember,
                assignedClientIds,
                patients,
                error: "A staff email is required.",
                isLoggedIn: true,
                currentStaffName: req.session.staffName || "Administrator",
                currentStaffEmail: req.session.staffEmail || adminEmail,
                staffRoleOptions,
                staffEmploymentTypeOptions,
                staffServiceTypeOptions,
                staffStatusOptions,
                staffQualificationOptions,
                staffSkillOptions,
                staffMandatoryTrainingOptions,
                staffCertificationOptions,
                staffLanguageOptions,
                staffAvailabilityDayOptions,
                staffShiftPreferenceOptions,
                staffDocumentCategories,
            });
        }

        const identity = await enforceApplicationUniqueness({
            email: profilePayload.email,
            phone: profilePayload.mobileNumber || profilePayload.phone,
            excludeStaffId: id,
        });
        await runDb(
            `UPDATE staff
             SET name = ?, first_name = ?, last_name = ?, role = ?,
                 email = ?, email_verified = CASE WHEN COALESCE(email_normalized, lower(email)) = ? THEN email_verified ELSE 0 END,
                 email_normalized = ?,
                 phone = ?, phone_verified = CASE WHEN COALESCE(phone_normalized, '') = COALESCE(?, '') THEN phone_verified ELSE 0 END,
                 phone_normalized = ?, status = ?, shift = ?,
                 address = ?, emergency_contact = ?, availability = ?, manager_name = ?, start_date = ?, nationality = ?, languages = ?,
                 employee_number = ?, preferred_name = ?, profile_photo = ?, date_of_birth = ?, gender = ?, pps_number = ?,
                 driving_licence_number = ?, driving_licence_categories = ?, own_vehicle = ?, right_to_work = ?, visa_type = ?,
                 visa_expiry_date = ?, passport_number = ?, passport_expiry_date = ?, mobile_number = ?, alternative_phone = ?,
                 home_address = ?, eircode = ?, county = ?, emergency_contact_name = ?, emergency_contact_relationship = ?,
                 emergency_contact_phone = ?, emergency_contact_email = ?, employment_type = ?, service_types = ?, employment_status = ?, end_date = ?,
                 hourly_rate = ?, payroll_number = ?, branch = ?, qqi_qualifications = ?, professional_registration = ?,
                 other_qualifications = ?, skills_specialities = ?, mandatory_training = ?, additional_certifications = ?, availability_days = ?,
                 shift_preferences = ?, weekend_availability = ?, bank_holidays = ?, max_weekly_hours = ?, preferred_working_area = ?,
                 internal_notes = ?, staff_notes = ?, compliance_summary = ?, portal_login_enabled = ?, portal_login_suspended = ?,
                 portal_login_deactivated = ?, welcome_email_sent = ?
             WHERE id = ?`,
            [
                profilePayload.name,
                profilePayload.firstName,
                profilePayload.lastName,
                profilePayload.role,
                profilePayload.email,
                identity.normalizedEmail,
                identity.normalizedEmail,
                profilePayload.phone,
                identity.normalizedPhone || null,
                identity.normalizedPhone || null,
                profilePayload.status,
                profilePayload.shift,
                profilePayload.homeAddress,
                profilePayload.emergencyContactName,
                profilePayload.availability,
                profilePayload.managerName,
                profilePayload.startDate,
                profilePayload.nationality,
                profilePayload.languages,
                profilePayload.employeeNumber,
                profilePayload.preferredName,
                profilePayload.profilePhoto,
                profilePayload.dateOfBirth,
                profilePayload.gender,
                profilePayload.ppsNumber,
                profilePayload.drivingLicenceNumber,
                profilePayload.drivingLicenceCategories,
                profilePayload.ownVehicle,
                profilePayload.rightToWork,
                profilePayload.visaType,
                profilePayload.visaExpiryDate,
                profilePayload.passportNumber,
                profilePayload.passportExpiryDate,
                profilePayload.mobileNumber,
                profilePayload.alternativePhone,
                profilePayload.homeAddress,
                profilePayload.eircode,
                profilePayload.county,
                profilePayload.emergencyContactName,
                profilePayload.emergencyContactRelationship,
                profilePayload.emergencyContactPhone,
                profilePayload.emergencyContactEmail,
                profilePayload.employmentType,
                profilePayload.serviceTypes,
                profilePayload.employmentStatus,
                profilePayload.endDate,
                profilePayload.hourlyRate,
                profilePayload.payrollNumber,
                profilePayload.branch,
                profilePayload.qqiQualifications,
                profilePayload.professionalRegistration,
                profilePayload.otherQualifications,
                profilePayload.skillsSpecialities,
                profilePayload.mandatoryTraining,
                profilePayload.additionalCertifications,
                profilePayload.availabilityDays,
                profilePayload.shiftPreferences,
                profilePayload.weekendAvailability,
                profilePayload.bankHolidays,
                profilePayload.maxWeeklyHours,
                profilePayload.preferredWorkingArea,
                profilePayload.internalNotes,
                profilePayload.staffNotes,
                profilePayload.complianceSummary,
                profilePayload.portalLoginEnabled,
                profilePayload.portalLoginSuspended,
                profilePayload.portalLoginDeactivated,
                profilePayload.welcomeEmailSent,
                id,
            ]
        );
        await runDb(
            `UPDATE staff
             SET training_records = ?, certification_records = ?, nmbi_number = ?, nmbi_expiry_date = ?,
                 garda_vetting_status = ?, garda_vetting_expiry_date = ?, force_password_reset = ?
             WHERE id = ?`,
            [
                profilePayload.trainingRecords,
                profilePayload.certificationRecords,
                profilePayload.nmbiNumber,
                profilePayload.nmbiExpiryDate,
                profilePayload.gardaVettingStatus,
                profilePayload.gardaVettingExpiryDate,
                profilePayload.forcePasswordReset,
                id,
            ]
        );

        await runDb("DELETE FROM patient_assignments WHERE staff_id = ? AND assignment_role = 'assigned'", [id]);
        for (const patientId of profilePayload.assignedClientIds) {
            const numericId = Number(patientId);
            if (Number.isFinite(numericId) && numericId > 0) {
                await runDb("INSERT INTO patient_assignments (patient_id, staff_id, assignment_role) VALUES (?, ?, 'assigned')", [numericId, id]);
            }
        }

        await syncStaffDocuments(id, req.body.documents || {});
        await writeAuditEvent(req, { action: "update", targetType: "staff", targetIdentifier: String(id), outcome: "success", reason: "Updated a staff member via the admin form" });
        return res.redirect(`/staff/${id}`);
    } catch (error) {
        await recordDuplicateIdentityAttempt(req, error, "staff");
        console.error("Error updating staff member:", error.message);
        const currentStaffMember = mapStaffRow(await getDb("SELECT * FROM staff WHERE id = ?", [Number(req.params.id)]));
        const duplicateIdentity = ["APPLICATION_DUPLICATE_EMAIL", "APPLICATION_DUPLICATE_PHONE"].includes(error.code);
        return res.status(duplicateIdentity ? 409 : 500).render("staff-form", {
            title: `Edit ${currentStaffMember ? currentStaffMember.name : "staff member"}`,
            mode: "edit",
            staffMember: currentStaffMember,
            assignedClientIds: [],
            patients: (await allDb("SELECT id, first_name, last_name, name FROM patients ORDER BY first_name")).map(mapPatientRow),
            error: duplicateIdentity ? error.message : "The staff record could not be updated.",
            isLoggedIn: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
            staffRoleOptions,
            staffEmploymentTypeOptions,
            staffServiceTypeOptions,
            staffStatusOptions,
            staffQualificationOptions,
            staffSkillOptions,
            staffMandatoryTrainingOptions,
            staffCertificationOptions,
            staffLanguageOptions,
            staffAvailabilityDayOptions,
            staffShiftPreferenceOptions,
            staffDocumentCategories,
        });
    }
});

app.post("/staff/:id/delete", requirePortal, requireAdmin, async (req, res) => {
    try {
        await runDb("DELETE FROM patient_assignments WHERE staff_id = ?", [Number(req.params.id)]);
        await runDb("DELETE FROM staff WHERE id = ?", [Number(req.params.id)]);
        return res.redirect("/staff");
    } catch (error) {
        console.error("Error deleting staff member:", error.message);
        return res.status(500).render("error", {
            title: "Staff deletion failed",
            message: "The staff record could not be deleted.",
        });
    }
});

app.get("/staff/:id", requirePortal, requireAdmin, async (req, res) => {
    try {
        const staffMember = mapStaffRow(await getDb("SELECT * FROM staff WHERE id = ?", [Number(req.params.id)]));

        if (!staffMember) {
            return res.status(404).render("error", {
                title: "Staff member not found",
                message: "The requested staff record could not be found.",
            });
        }

        const assignedClientRows = await allDb(
            "SELECT p.id, p.first_name, p.last_name, p.name FROM patient_assignments pa JOIN patients p ON p.id = pa.patient_id WHERE pa.staff_id = ? AND pa.assignment_role = 'assigned' ORDER BY p.first_name",
            [staffMember.id]
        );
        const assignedClients = assignedClientRows.map((patient) => ({
            id: patient.id,
            name: patient.name || formatName(patient.first_name, patient.last_name),
        }));
        const staffDocuments = await allDb("SELECT id, title, category, file_name, download_text, created_at FROM staff_documents WHERE staff_id = ? ORDER BY created_at DESC", [staffMember.id]);
        const upcomingShifts = (await allDb(
            `SELECT ss.id, ss.scheduled_start, ss.scheduled_end, ss.status, p.first_name, p.last_name, p.name
             FROM staff_shifts ss
             LEFT JOIN patients p ON p.id = ss.patient_id
             WHERE ss.staff_id = ?
               AND datetime(COALESCE(ss.scheduled_start, ss.shift_date)) >= datetime('now')
             ORDER BY COALESCE(ss.scheduled_start, ss.shift_date) ASC
             LIMIT 5`,
            [staffMember.id]
        )).map((row) => ({
            id: row.id,
            status: row.status || "scheduled",
            scheduledStart: row.scheduled_start || row.shift_date || "",
            scheduledEnd: row.scheduled_end || "",
            patientName: row.name || formatName(row.first_name, row.last_name),
        }));
        const attendanceSummary = await getDb(
            `SELECT
                COUNT(*) AS totalShifts,
                SUM(CASE WHEN actual_clock_in IS NOT NULL THEN 1 ELSE 0 END) AS clockIns,
                SUM(CASE WHEN actual_clock_out IS NOT NULL THEN 1 ELSE 0 END) AS clockOuts
             FROM staff_shifts
             WHERE staff_id = ?`,
            [staffMember.id]
        );

        return res.render("staff-detail", {
            title: `${staffMember.name} | Staff Profile`,
            staffMember,
            assignedClients,
            staffDocuments,
            upcomingShifts,
            attendanceSummary: {
                totalShifts: Number(attendanceSummary ? attendanceSummary.totalShifts : 0),
                clockIns: Number(attendanceSummary ? attendanceSummary.clockIns : 0),
                clockOuts: Number(attendanceSummary ? attendanceSummary.clockOuts : 0),
            },
            isLoggedIn: true,
            currentStaffName: req.session.staffName || "Administrator",
            currentStaffEmail: req.session.staffEmail || adminEmail,
        });
    } catch (error) {
        console.error("Error loading staff detail:", error.message);
        return res.status(500).render("error", {
            title: "Staff profile unavailable",
            message: "The staff record could not be loaded.",
        });
    }
});

app.get("/calendar", requirePortal, requireAdmin, async (req, res) => {
    try {
        const appointments = (await allDb(`
            SELECT ss.id, ss.patient_id, ss.staff_id, ss.scheduled_start AS start, ss.scheduled_end AS end, ss.status,
                   p.first_name || ' ' || p.last_name AS client,
                   s.first_name || ' ' || s.last_name AS staff_name,
                   s.status AS staff_status
            FROM staff_shifts ss
            LEFT JOIN patients p ON p.id = ss.patient_id
            LEFT JOIN staff s ON s.id = ss.staff_id
            ORDER BY ss.scheduled_start ASC
        `)).map(mapAppointmentRow);

        const patients = (await allDb(
            "SELECT id, first_name, last_name, name FROM patients WHERE COALESCE(is_archived, 0) = 0 ORDER BY first_name"
        )).map(mapPatientRow);

        const staff = (await allDb(
            "SELECT id, first_name, last_name, name, role, status FROM staff ORDER BY first_name"
        )).map(mapStaffRow);

        const now = new Date();
        const year = now.getFullYear();
        const month = now.getMonth(); // 0-indexed
        const MONTH_NAMES = ["January","February","March","April","May","June","July","August","September","October","November","December"];
        const monthLabel = MONTH_NAMES[month] + " " + year;

        res.render("calendar", {
            title: "Care Calendar",
            appointments,
            patients,
            staff,
            isLoggedIn: true,
            isAdmin: true,
            currentStaffName: req.session.staffName || "Administrator",
            year,
            month,
            monthLabel,
        });
    } catch (error) {
        console.error("Error loading calendar:", error.message);
        res.status(500).render("error", {
            title: "Calendar unavailable",
            message: "The care calendar could not be loaded.",
        });
    }
});

app.post("/api/shifts", requirePortal, requireAdmin, async (req, res) => {
    const patientId = Number(req.body.patient_id);
    const staffId = Number(req.body.staff_id);
    const shiftDate = String(req.body.shift_date || "").trim();
    const startTime = String(req.body.start_time || "").trim();
    const endTime = String(req.body.end_time || "").trim();
    const serviceTypeInput = String(req.body.service_type || "").trim();
    const requestedDivision = String(req.body.service_division || "").trim().toLowerCase();
    const serviceDivision = shiftDivisionOptions.includes(requestedDivision) ? requestedDivision : "home-care";
    if (serviceDivision === "agency-staffing") {
        return res.status(400).json({ success: false, message: "Agency shifts are created from approved facility requests to preserve facility linkage." });
    }

    if (!patientId || !staffId || !shiftDate || !startTime || !endTime) {
        return res.status(400).json({ success: false, message: "Patient, staff, date, start time, and end time are all required." });
    }

    const scheduledStart = shiftDate + "T" + startTime + ":00";
    const scheduledEnd = shiftDate + "T" + endTime + ":00";

    try {
        const patient = mapPatientRow(await getDb("SELECT * FROM patients WHERE id = ? AND COALESCE(is_archived, 0) = 0", [patientId]));
        if (!patient) {
            return res.status(404).json({ success: false, message: "Patient not found." });
        }
        if (["In Hospital", "On Holiday", "Temporarily Suspended", "Discharged", "Deceased", "Archived"].includes(patient.status)) {
            return res.status(409).json({ success: false, message: `New schedules are blocked while this client is marked as ${patient.status}.` });
        }

        const staffMember = mapStaffRow(await getDb("SELECT * FROM staff WHERE id = ?", [staffId]));
        if (!staffMember) {
            return res.status(404).json({ success: false, message: "Staff member not found." });
        }
        const serviceType = serviceTypeInput || patient.serviceTypes[0] || "Personal Care";
        const careInstructions = String(req.body.care_instructions || req.body.notes || patient.shift_instructions || "").trim();
        const assignedHourlyRate = await getValidStaffHourlyRate(staffId);

        const result = await runDb(
            `INSERT INTO staff_shifts (patient_id, staff_id, shift_date, scheduled_start, scheduled_end, status, service_type, notes, care_instructions, service_division, role_required)
             VALUES (?, ?, ?, ?, ?, 'scheduled', ?, ?, ?, ?, ?)`,
            [patientId, staffId, shiftDate, scheduledStart, scheduledEnd, serviceType, careInstructions || null, careInstructions || null, serviceDivision, staffMember.role || serviceType]
        );
        await runDb("UPDATE staff_shifts SET shift_code = ? WHERE id = ?", [buildShiftCode(serviceDivision, result.lastID), Number(result.lastID)]);
        await snapshotShiftPayRate(result.lastID, staffId, assignedHourlyRate);

        if (staffMember.notifyNewShift) {
            await queueStaffNotification(
                staffId,
                "New shift assigned",
                `You have been assigned a shift on ${shiftDate} from ${startTime} to ${endTime}.`,
                "shift",
                `/portal/shifts/${result.lastID}`
            );
        }
        emitPortalEvent(
            "shift_update",
            { action: "created", shiftId: Number(result.lastID), staffId: Number(staffId) },
            { staffIds: [Number(staffId)] }
        );
        emitPortalEvent("shift_update", { action: "created", shiftId: Number(result.lastID), staffId: Number(staffId) }, { adminOnly: true });

        return res.json({ success: true, message: "Shift scheduled successfully.", shiftId: result.lastID });
    } catch (error) {
        console.error("Error creating shift:", error.message);
        return res.status(500).json({ success: false, message: "Unable to save shift." });
    }
});

app.patch("/api/shifts/:id", requirePortal, requireAdmin, async (req, res) => {
    const shiftId = Number(req.params.id);
    if (!Number.isInteger(shiftId) || shiftId <= 0) {
        return res.status(400).json({ success: false, message: "A valid shift id is required." });
    }

    const VALID_STATUSES = new Set(["scheduled", "clocked_in", "clocked_out", "completed", "cancelled", "no_show"]);
    const patientId = req.body.patient_id ? Number(req.body.patient_id) : undefined;
    const staffId = req.body.staff_id ? Number(req.body.staff_id) : undefined;
    const shiftDate = req.body.shift_date ? String(req.body.shift_date).trim() : undefined;
    const startTime = req.body.start_time ? String(req.body.start_time).trim() : undefined;
    const endTime = req.body.end_time ? String(req.body.end_time).trim() : undefined;
    const serviceType = req.body.service_type ? String(req.body.service_type).trim() : undefined;
    const serviceDivision = req.body.service_division ? String(req.body.service_division).trim().toLowerCase() : undefined;
    const status = req.body.status ? String(req.body.status).trim() : undefined;
    const notes = req.body.notes !== undefined ? String(req.body.notes).trim() : undefined;
    const careInstructions = req.body.care_instructions !== undefined ? String(req.body.care_instructions).trim() : undefined;

    if (status && !VALID_STATUSES.has(status)) {
        return res.status(400).json({ success: false, message: "Invalid status value." });
    }
    if (serviceDivision && !shiftDivisionOptions.includes(serviceDivision)) {
        return res.status(400).json({ success: false, message: "Invalid service division value." });
    }

    try {
        const shift = await getDb("SELECT id, patient_id FROM staff_shifts WHERE id = ?", [shiftId]);
        if (!shift) {
            return res.status(404).json({ success: false, message: "Shift not found." });
        }
        const assignedHourlyRate = staffId !== undefined ? await getValidStaffHourlyRate(staffId) : null;
        if (patientId !== undefined) {
            const patient = mapPatientRow(await getDb("SELECT * FROM patients WHERE id = ? AND COALESCE(is_archived, 0) = 0", [patientId]));
            if (!patient) {
                return res.status(404).json({ success: false, message: "Client not found." });
            }
            if (["In Hospital", "On Holiday", "Temporarily Suspended", "Discharged", "Deceased", "Archived"].includes(patient.status)) {
                return res.status(409).json({ success: false, message: `This client is currently marked as ${patient.status}, so new shift assignments are blocked.` });
            }
        }

        const updates = [];
        const params = [];

        if (patientId !== undefined) { updates.push("patient_id = ?"); params.push(patientId); }
        if (staffId !== undefined) { updates.push("staff_id = ?"); params.push(staffId); }
        if (status !== undefined) { updates.push("status = ?"); params.push(status); }
        if (serviceType !== undefined) { updates.push("service_type = ?"); params.push(serviceType); }
        if (serviceDivision !== undefined) { updates.push("service_division = ?"); params.push(serviceDivision); }
        if (notes !== undefined) { updates.push("notes = ?"); params.push(notes); }
        if (careInstructions !== undefined) { updates.push("care_instructions = ?"); params.push(careInstructions); }

        if (shiftDate && startTime) {
            updates.push("scheduled_start = ?");
            params.push(shiftDate + "T" + startTime + ":00");
            updates.push("shift_date = ?");
            params.push(shiftDate);
        }
        if (shiftDate && endTime) {
            updates.push("scheduled_end = ?");
            params.push(shiftDate + "T" + endTime + ":00");
        }

        if (updates.length === 0) {
            return res.status(400).json({ success: false, message: "No fields to update." });
        }

        params.push(shiftId);
        await runDb(`UPDATE staff_shifts SET ${updates.join(", ")} WHERE id = ?`, params);
        if (staffId !== undefined) {
            await snapshotShiftPayRate(shiftId, staffId, assignedHourlyRate);
        }
        if (serviceDivision !== undefined) {
            await runDb("UPDATE staff_shifts SET shift_code = ? WHERE id = ?", [buildShiftCode(serviceDivision, shiftId), shiftId]);
        }
        const updatedShift = await getDb("SELECT staff_id, shift_date, scheduled_start, scheduled_end, status FROM staff_shifts WHERE id = ?", [shiftId]);
        if (updatedShift && updatedShift.staff_id) {
            const assignedStaffMember = mapStaffRow(await getDb("SELECT * FROM staff WHERE id = ?", [Number(updatedShift.staff_id)]));
            if (assignedStaffMember && assignedStaffMember.notifyScheduleChanges) {
                await queueStaffNotification(
                    updatedShift.staff_id,
                    "Shift updated",
                    `Your shift on ${updatedShift.shift_date || toDateKey(updatedShift.scheduled_start)} was updated. Current status: ${updatedShift.status}.`,
                    "shift",
                    `/portal/shifts/${shiftId}`
                );
            }
            emitPortalEvent(
                "shift_update",
                { action: "updated", shiftId: Number(shiftId), staffId: Number(updatedShift.staff_id) },
                { staffIds: [Number(updatedShift.staff_id)] }
            );
        }
        if (status !== undefined) {
            await syncClientRequestStatusFromShift({
                shiftId,
                shiftStatus: status,
                notifyTitle: "Shift status update",
                notifyBody: `Your shift status is now ${status.replace(/_/g, " ")}.`,
            });
        } else if (staffId !== undefined && Number.isFinite(staffId) && staffId > 0) {
            await syncClientRequestStatusFromShift({
                shiftId,
                shiftStatus: "scheduled",
                notifyTitle: "Staff assigned",
                notifyBody: "A qualified staff member has been assigned to your request.",
            });
        }
        emitPortalEvent("shift_update", { action: "updated", shiftId: Number(shiftId) }, { adminOnly: true });
        return res.json({ success: true, message: "Shift updated successfully." });
    } catch (error) {
        console.error("Error updating shift:", error.message);
        return res.status(500).json({ success: false, message: "Unable to update shift." });
    }
});

app.delete("/api/shifts/:id", requirePortal, requireAdmin, async (req, res) => {
    const shiftId = Number(req.params.id);
    if (!Number.isInteger(shiftId) || shiftId <= 0) {
        return res.status(400).json({ success: false, message: "A valid shift id is required." });
    }

    try {
        const shift = await getDb("SELECT id, staff_id FROM staff_shifts WHERE id = ?", [shiftId]);
        if (!shift) {
            return res.status(404).json({ success: false, message: "Shift not found." });
        }

        await runDb("DELETE FROM staff_shifts WHERE id = ?", [shiftId]);
        if (shift.staff_id) {
            emitPortalEvent("shift_update", { action: "deleted", shiftId: Number(shiftId), staffId: Number(shift.staff_id) }, { staffIds: [Number(shift.staff_id)] });
        }
        emitPortalEvent("shift_update", { action: "deleted", shiftId: Number(shiftId) }, { adminOnly: true });
        return res.json({ success: true, message: "Shift removed." });
    } catch (error) {
        console.error("Error deleting shift:", error.message);
        return res.status(500).json({ success: false, message: "Unable to remove shift." });
    }
});

app.get("/api/health", async (req, res) => {
    try {
        const row = await getDb("SELECT status FROM app_status WHERE id = 1");
        return res.json({
            status: "ok",
            database: row ? row.status : "healthy",
            message: "JS is connected to the backend",
        });
    } catch (error) {
        return res.status(500).json({
                status: "error",
                database: "unavailable",
                message: error.message,
        });
    }
});

app.get("/api/dashboard", requirePortal, requireAdmin, async (req, res) => {
    try {
        const patientCount = await getDb("SELECT COUNT(*) AS count FROM patients");
        const staffCount = await getDb("SELECT COUNT(*) AS count FROM staff");
        const appointmentsToday = await allDb("SELECT * FROM staff_shifts WHERE date(scheduled_start) = date('now') ORDER BY scheduled_start");

        const tasks = appointmentsToday.map((shift) => ({
            client: shift.patient_id ? `Patient #${shift.patient_id}` : "Patient",
            time: shift.scheduled_start ? shift.scheduled_start.slice(11, 16) : "00:00",
            task: shift.status === "clocked_in" ? "Active care visit" : "Scheduled care visit",
            priority: shift.status === "clocked_in" ? "High" : "Medium",
        }));

        return res.json({
            summary: {
                activePatients: Number(patientCount.count),
                carersOnShift: Number(staffCount.count),
                tasksDueToday: tasks.length,
                urgentAlerts: tasks.filter((task) => task.priority === "High").length,
            },
            tasks,
            lastUpdated: new Date().toISOString(),
        });
    } catch (error) {
        console.error("Error loading dashboard:", error.message);
        return res.status(500).json({ status: "error", message: "Dashboard data could not be loaded." });
    }
});

app.get("/api/patients", requirePortal, requireAdmin, async (req, res) => {
    try {
        const patients = (await allDb("SELECT * FROM patients WHERE COALESCE(is_archived, 0) = 0 ORDER BY last_name, first_name, id")).map(mapPatientRow);
        return res.json({ patients });
    } catch (error) {
        console.error("Error loading patient API:", error.message);
        return res.status(500).json({ status: "error", message: "Unable to load patient records." });
    }
});

app.post("/api/patients/geocode", requirePortal, requireAdmin, async (req, res) => {
    try {
        const address = buildPatientAddressText([req.body.address, req.body.county, req.body.eircode]);
        if (!address) {
            return res.status(400).json({ success: false, message: "An address is required before locating GPS coordinates." });
        }
        const result = await geocodeAddress(address);
        return res.json({
            success: true,
            latitude: Number(result.lat),
            longitude: Number(result.lon),
            displayName: result.display_name || address,
        });
    } catch (error) {
        console.error("Error geocoding patient address:", error.message);
        return res.status(500).json({ success: false, message: error.message || "The address could not be geocoded." });
    }
});

app.get("/api/staff", requirePortal, requireAdmin, async (req, res) => {
    try {
        const staff = (await allDb("SELECT * FROM staff ORDER BY first_name")).map(mapStaffRow);
        return res.json({ staff });
    } catch (error) {
        console.error("Error loading staff API:", error.message);
        return res.status(500).json({ status: "error", message: "Unable to load staff records." });
    }
});

app.get("/api/compliance/requests", requirePortal, requireAdmin, async (req, res) => {
    try {
        const requests = await allDb(
            `SELECT id, request_type, patient_id, requested_by, status, details, processed_at, created_at
             FROM subject_requests
             ORDER BY created_at DESC
             LIMIT 50`
        );
        return res.json({ success: true, requests });
    } catch (error) {
        console.error("Error loading subject requests:", error.message);
        return res.status(500).json({ success: false, message: "Unable to load subject requests." });
    }
});

app.post("/api/compliance/patients/:id/legal", requirePortal, requireAdmin, async (req, res) => {
    const patientId = Number(req.params.id);
    const legalBasis = String(req.body.legalBasis || "").trim();
    const consentStatus = String(req.body.consentStatus || "").trim();
    const consentRecordedBy = String(req.body.consentRecordedBy || "").trim();
    const dataRetentionUntil = req.body.dataRetentionUntil ? String(req.body.dataRetentionUntil).trim() : "";

    if (!Number.isInteger(patientId) || patientId <= 0) {
        return res.status(400).json({ success: false, message: "A valid patient id is required." });
    }
    if (!legalBasisOptions.has(legalBasis)) {
        return res.status(400).json({ success: false, message: "Invalid legal basis supplied." });
    }
    if (!consentStatusOptions.has(consentStatus)) {
        return res.status(400).json({ success: false, message: "Invalid consent status supplied." });
    }
    if (!consentRecordedBy) {
        return res.status(400).json({ success: false, message: "consentRecordedBy is required." });
    }
    if (dataRetentionUntil && !/^\d{4}-\d{2}-\d{2}$/.test(dataRetentionUntil)) {
        return res.status(400).json({ success: false, message: "dataRetentionUntil must be in YYYY-MM-DD format." });
    }

    try {
        const patient = await getDb("SELECT id FROM patients WHERE id = ? AND COALESCE(is_archived, 0) = 0", [patientId]);
        if (!patient) {
            return res.status(404).json({ success: false, message: "Patient not found." });
        }

        await runDb(
            `UPDATE patients
             SET legal_basis = ?,
                 consent_status = ?,
                 consent_recorded_by = ?,
                 consent_recorded_at = datetime('now'),
                 data_retention_until = CASE WHEN ? = '' THEN data_retention_until ELSE ? END
             WHERE id = ?`,
            [legalBasis, consentStatus, consentRecordedBy, dataRetentionUntil, dataRetentionUntil, patientId]
        );

        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "compliance_legal_update",
            targetType: "patient",
            targetIdentifier: String(patientId),
            outcome: "success",
        });

        return res.json({ success: true, message: "Patient compliance details updated." });
    } catch (error) {
        console.error("Error updating patient compliance details:", error.message);
        return res.status(500).json({ success: false, message: "Unable to update compliance details." });
    }
});

app.get("/api/compliance/patients/:id/export", requirePortal, requireAdmin, async (req, res) => {
    const patientId = Number(req.params.id);
    if (!Number.isInteger(patientId) || patientId <= 0) {
        return res.status(400).json({ success: false, message: "A valid patient id is required." });
    }

    try {
        const exportPackage = await buildPatientExportPackage(patientId);
        if (!exportPackage) {
            return res.status(404).json({ success: false, message: "Patient not found." });
        }

        await runDb(
            `INSERT INTO subject_requests (request_type, patient_id, requested_by, status, details, processed_at)
             VALUES ('export', ?, ?, 'processed', 'Patient subject access export generated.', datetime('now'))`,
            [patientId, getActorContext(req).actorIdentifier || "system"]
        );

        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "subject_access_export",
            targetType: "patient",
            targetIdentifier: String(patientId),
            outcome: "success",
        });

        return res.json({ success: true, export: exportPackage });
    } catch (error) {
        console.error("Error exporting patient subject access package:", error.message);
        return res.status(500).json({ success: false, message: "Unable to generate export package." });
    }
});

app.post("/api/compliance/patients/:id/erase", requirePortal, requireAdmin, async (req, res) => {
    const patientId = Number(req.params.id);
    const reason = String(req.body.reason || "").trim();

    if (!Number.isInteger(patientId) || patientId <= 0) {
        return res.status(400).json({ success: false, message: "A valid patient id is required." });
    }
    if (!reason) {
        return res.status(400).json({ success: false, message: "A reason is required for the erasure workflow." });
    }

    try {
        const patient = await getDb("SELECT id FROM patients WHERE id = ? AND COALESCE(is_archived, 0) = 0", [patientId]);
        if (!patient) {
            return res.status(404).json({ success: false, message: "Patient not found or already archived." });
        }

        await runDb(
            `INSERT INTO subject_requests (request_type, patient_id, requested_by, status, details, processed_at)
             VALUES ('erasure', ?, ?, 'processed', ?, datetime('now'))`,
            [patientId, getActorContext(req).actorIdentifier || "system", reason]
        );

        await runDb(
            `UPDATE patients
             SET first_name = 'Archived',
                 last_name = 'Patient',
                 name = 'Archived Patient',
                 date_of_birth = NULL,
                 gender = NULL,
                 address = NULL,
                 phone = NULL,
                 email = NULL,
                 emergency_contact = NULL,
                 latitude = NULL,
                 longitude = NULL,
                 geofence_radius_meters = NULL,
                 consent_status = 'withdrawn',
                 consent_recorded_by = ?,
                 consent_recorded_at = datetime('now'),
                 is_archived = 1,
                 archived_at = datetime('now')
             WHERE id = ?`,
            [getActorContext(req).actorIdentifier || "system", patientId]
        );
        await runDb("UPDATE appointments SET patient_id = NULL WHERE patient_id = ?", [patientId]);
        await runDb("UPDATE staff_shifts SET patient_id = NULL WHERE patient_id = ?", [patientId]);
        const deletedNotes = await runDb("DELETE FROM care_notes WHERE patient_id = ?", [patientId]);

        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "subject_erasure_archive",
            targetType: "patient",
            targetIdentifier: String(patientId),
            outcome: "success",
            reason,
        });

        return res.json({
            success: true,
            message: "Patient record archived and identifying data removed.",
            removedNotes: Number(deletedNotes.changes || 0),
        });
    } catch (error) {
        console.error("Error processing patient erasure workflow:", error.message);
        return res.status(500).json({ success: false, message: "Unable to process erasure workflow." });
    }
});

app.post("/api/compliance/retention/run", requirePortal, requireAdmin, async (req, res) => {
    const retentionDays = parseRetentionDays(req.body.retentionDays);
    if (retentionDays === null) {
        return res.status(400).json({ success: false, message: "retentionDays must be an integer between 30 and 3650." });
    }

    try {
        const result = await runDb(
            `DELETE FROM care_notes
             WHERE id IN (
                 SELECT cn.id
                 FROM care_notes cn
                 INNER JOIN patients p ON p.id = cn.patient_id
                 WHERE COALESCE(p.is_archived, 0) = 1
                   AND datetime(cn.created_at) < datetime('now', ?)
             )`,
            [`-${retentionDays} days`]
        );

        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "retention_cleanup",
            targetType: "care_notes",
            targetIdentifier: "archived-patients",
            outcome: "success",
            reason: `${retentionDays}_days`,
        });

        return res.json({
            success: true,
            message: "Retention cleanup completed.",
            deletedNotes: Number(result.changes || 0),
            retentionDays,
        });
    } catch (error) {
        console.error("Error running retention cleanup:", error.message);
        return res.status(500).json({ success: false, message: "Unable to run retention cleanup." });
    }
});

app.get("/api/staff/shifts", requirePortal, async (req, res) => {
    try {
        const params = [];
        let whereClause = "";
        if (req.session.isStaff && !req.session.isAdmin) {
            whereClause = "WHERE ss.staff_id = ?";
            params.push(Number(req.session.staffId));
        }

        const shiftRows = await allDb(`
            SELECT ss.*, COALESCE(p.first_name || ' ' || p.last_name, ss.external_client_label, 'Client') AS patient_name, s.first_name || ' ' || s.last_name AS staff_name, s.status AS staff_status
            FROM staff_shifts ss
            LEFT JOIN patients p ON p.id = ss.patient_id
            LEFT JOIN staff s ON s.id = ss.staff_id
            ${whereClause}
            ORDER BY ss.scheduled_start ASC
        `, params);

        return res.json({ success: true, shifts: shiftRows.map(mapShiftRow) });
    } catch (error) {
        console.error("Error loading staff shifts API:", error.message);
        return res.status(500).json({ success: false, message: "Unable to load shift data." });
    }
});

const renderShiftDetailPage = async (req, res, isAdminView) => {
    try {
        const shiftId = Number(req.params.id);
        if (!Number.isInteger(shiftId) || shiftId <= 0) {
            return res.status(400).render("error", { title: "Invalid shift", message: "A valid shift id is required." });
        }

        const shift = mapShiftRow(await getDb(
            `SELECT ss.*,
                    p.home_care_client_id,
                    COALESCE(p.first_name || ' ' || p.last_name, ss.external_client_label, 'Home Care Client') AS home_care_client_name,
                    COALESCE(ss.external_client_label, ca.organization_name, p.first_name || ' ' || p.last_name, 'Client') AS patient_name,
                    COALESCE(p.address, ss.location_address) AS address,
                    COALESCE(p.eircode, ss.location_eircode) AS eircode,
                    p.status AS patient_status,
                    p.phone AS patient_phone,
                    COALESCE(p.latitude, ss.external_latitude) AS latitude,
                    COALESCE(p.longitude, ss.external_longitude) AS longitude,
                    p.photo_url,
                    COALESCE(p.geofence_radius_meters, ss.external_geofence_radius_meters) AS geofence_radius_meters,
                    p.diagnoses,
                    p.allergies,
                    p.current_medication,
                    p.shift_instructions,
                    p.carePlan,
                    p.emergency_contact,
                    p.emergency_contact_name,
                    p.emergency_contact_relationship,
                    p.emergency_contact_phone,
                    p.emergency_contact_alt_phone,
                    p.emergency_contact_email,
                    p.key_safe_code,
                    p.door_code,
                    p.alarm_code,
                    p.parking_instructions,
                    p.pets,
                    p.lift_available,
                    p.stairs,
                    p.access_notes,
                   ca.facility_id,
                   ca.organization_name AS facility_name,
                   COALESCE(ss.facility_type, csr.facility_type, ca.organization_type) AS facility_type,
                   csr.facility_address,
                   csr.facility_county,
                   csr.contact_person,
                   csr.contact_phone,
                   csr.staff_required,
                   csr.required_skills,
                   csr.required_training,
                   csr.special_instructions,
                   csr.break_duration_minutes,
                   csr.quantity_required,
                   s.first_name || ' ' || s.last_name AS staff_name,
                   s.status AS staff_status
             FROM staff_shifts ss
             LEFT JOIN patients p ON p.id = ss.patient_id
             LEFT JOIN client_accounts ca ON ca.id = ss.client_account_id
             LEFT JOIN client_service_requests csr ON csr.id = ss.client_request_id
             LEFT JOIN staff s ON s.id = ss.staff_id
             WHERE ss.id = ?`,
            [shiftId]
        ));
        if (!shift) {
            return res.status(404).render("error", { title: "Shift not found", message: "The requested shift could not be found." });
        }

        if (!isAdminView && Number(shift.staffId) !== Number(req.session.staffId)) {
            return res.status(403).render("error", { title: "Access denied", message: "You can only view your assigned shifts." });
        }

        const shiftStart = shift.scheduledStart ? new Date(normalizeDateTimeString(shift.scheduledStart)) : null;
        const shiftEnd = shift.scheduledEnd ? new Date(normalizeDateTimeString(shift.scheduledEnd)) : null;
        const durationMinutes = shiftStart && shiftEnd && !Number.isNaN(shiftStart.getTime()) && !Number.isNaN(shiftEnd.getTime())
            ? Math.max(0, Math.round((shiftEnd.getTime() - shiftStart.getTime()) / 60000))
            : 0;
        const actualHours = shift.actual_clock_in && shift.actual_clock_out
            ? calcShiftHours(shift.actual_clock_in, shift.actual_clock_out, shift.break_duration_minutes)
            : null;

        const visitNotes = await allDb(
            `SELECT svn.*, st.first_name || ' ' || st.last_name AS staff_name
             FROM staff_shift_visit_notes svn
             LEFT JOIN staff st ON st.id = svn.staff_id
             WHERE svn.shift_id = ?
             ORDER BY svn.created_at DESC`,
            [shiftId]
        );
        const attachments = await allDb(
            `SELECT * FROM shift_attachments
             WHERE shift_id = ?
             ORDER BY created_at DESC`,
            [shiftId]
        );
        const clientDocuments = shift.patientId
            ? await allDb(
                `SELECT * FROM patient_documents
                 WHERE patient_id = ? AND COALESCE(is_staff_visible, 1) = 1
                 ORDER BY category, title`,
                [shift.patientId]
            )
            : [];

        const patientAddress = String(shift.address || "").trim();
        const mapDestination = Number.isFinite(Number(shift.latitude)) && Number.isFinite(Number(shift.longitude))
            ? `${Number(shift.latitude)},${Number(shift.longitude)}`
            : patientAddress;
        const encodedDestination = encodeURIComponent(mapDestination || "");
        const clientName = shift.patientName || "Client";

        return res.render("portal-staff-shift-detail", {
            title: "Shift details",
            isLoggedIn: true,
            isAdmin: Boolean(isAdminView),
            currentStaffName: isAdminView
                ? (req.session.adminName || req.session.staffName || "Administrator")
                : (req.session.staffName || shift.staffName || "Staff member"),
            currentStaffEmail: isAdminView
                ? String((req.session.user && req.session.user.email) || req.session.staffEmail || "")
                : (req.session.staffEmail || ""),
            shift,
            clientName,
            durationMinutes,
            actualMinutes: actualHours === null ? null : Math.round(actualHours * 60),
            visitNotes,
            attachments,
            clientDocuments,
            backLink: isAdminView ? "/portal/schedule" : "/portal/my-schedule",
            attachmentDownloadBasePath: isAdminView ? "/admin/shifts" : "/portal/shifts",
            mapLinks: {
                google: `https://www.google.com/maps/search/?api=1&query=${encodedDestination}`,
                apple: `https://maps.apple.com/?q=${encodedDestination}`,
                directions: `https://www.google.com/maps/dir/?api=1&destination=${encodedDestination}`,
            },
        });
    } catch (error) {
        console.error("Error loading shift details:", error.message);
        return res.status(500).render("error", { title: "Shift details unavailable", message: "The shift details could not be loaded." });
    }
};

app.get("/admin/shifts/:id", requirePortal, requireAdmin, async (req, res) => renderShiftDetailPage(req, res, true));

app.get("/portal/shifts/:id", requireStaffOnly, async (req, res) => renderShiftDetailPage(req, res, false));

app.post("/api/staff/shifts/:id/visit-notes", requireStaffOnly, async (req, res) => {
    try {
        const shiftId = Number(req.params.id);
        const staffId = Number(req.session.staffId);
        const note = String(req.body.note || "").trim();

        if (!Number.isInteger(shiftId) || shiftId <= 0) {
            return res.status(400).json({ success: false, message: "A valid shift id is required." });
        }
        if (!note) {
            return res.status(400).json({ success: false, message: "Visit note cannot be empty." });
        }

        const shift = await getDb("SELECT id, staff_id FROM staff_shifts WHERE id = ?", [shiftId]);
        if (!shift) {
            return res.status(404).json({ success: false, message: "Shift not found." });
        }
        if (Number(shift.staff_id) !== staffId) {
            return res.status(403).json({ success: false, message: "You can only add notes to your assigned shifts." });
        }

        const result = await runDb(
            `INSERT INTO staff_shift_visit_notes (shift_id, staff_id, note)
             VALUES (?, ?, ?)`,
            [shiftId, staffId, note]
        );
        const inserted = await getDb(
            `SELECT svn.*, st.first_name || ' ' || st.last_name AS staff_name
             FROM staff_shift_visit_notes svn
             LEFT JOIN staff st ON st.id = svn.staff_id
             WHERE svn.id = ?`,
            [result.lastID]
        );
        emitPortalEvent("shift_update", { action: "visit_note_added", shiftId: Number(shiftId), staffId: Number(staffId) });
        return res.json({ success: true, note: inserted });
    } catch (error) {
        console.error("Error saving visit note:", error.message);
        return res.status(500).json({ success: false, message: "Could not save visit note." });
    }
});

app.post("/api/shifts/:id/attachments", requirePortal, requireAdmin, async (req, res) => {
    try {
        const shiftId = Number(req.params.id);
        const title = String(req.body.title || "").trim();
        const category = String(req.body.category || "Visit Document").trim();
        const fileName = String(req.body.file_name || "").trim();
        const documentText = String(req.body.download_text || "").trim();

        if (!Number.isInteger(shiftId) || shiftId <= 0) {
            return res.status(400).json({ success: false, message: "A valid shift id is required." });
        }
        if (!title || !documentText) {
            return res.status(400).json({ success: false, message: "Attachment title and content are required." });
        }

        const shift = await getDb("SELECT id FROM staff_shifts WHERE id = ?", [shiftId]);
        if (!shift) {
            return res.status(404).json({ success: false, message: "Shift not found." });
        }

        const result = await runDb(
            `INSERT INTO shift_attachments (shift_id, title, category, file_name, download_text)
             VALUES (?, ?, ?, ?, ?)`,
            [shiftId, title, category || "Visit Document", fileName || null, documentText]
        );
        const attachment = await getDb("SELECT * FROM shift_attachments WHERE id = ?", [result.lastID]);
        emitPortalEvent("shift_update", { action: "attachment_added", shiftId: Number(shiftId) });
        return res.json({ success: true, attachment });
    } catch (error) {
        console.error("Error saving shift attachment:", error.message);
        return res.status(500).json({ success: false, message: "Could not save attachment." });
    }
});

const downloadShiftAttachment = async (req, res, isAdminView) => {
    try {
        const shiftId = Number(req.params.shiftId);
        const attachmentId = Number(req.params.attachmentId);
        if (!Number.isInteger(shiftId) || !Number.isInteger(attachmentId) || shiftId <= 0 || attachmentId <= 0) {
            return res.status(400).render("error", { title: "Invalid attachment", message: "A valid attachment id is required." });
        }

        const attachment = await getDb("SELECT * FROM shift_attachments WHERE id = ? AND shift_id = ?", [attachmentId, shiftId]);
        if (!attachment) {
            return res.status(404).render("error", { title: "Attachment not found", message: "The requested attachment could not be found." });
        }

        if (!isAdminView) {
            const shift = await getDb("SELECT staff_id FROM staff_shifts WHERE id = ?", [shiftId]);
            if (!shift || Number(shift.staff_id) !== Number(req.session.staffId)) {
                return res.status(403).render("error", { title: "Access denied", message: "You are not allowed to access this attachment." });
            }
        }

        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="${attachment.file_name || "shift-document.txt"}"`);
        return res.send(attachment.download_text || attachment.title);
    } catch (error) {
        console.error("Error downloading shift attachment:", error.message);
        return res.status(500).render("error", { title: "Attachment unavailable", message: "The attachment could not be downloaded." });
    }
};

app.get("/admin/shifts/:shiftId/attachments/:attachmentId/download", requirePortal, requireAdmin, async (req, res) => downloadShiftAttachment(req, res, true));

app.get("/portal/shifts/:shiftId/attachments/:attachmentId/download", requireStaffOnly, async (req, res) => downloadShiftAttachment(req, res, false));

app.post("/api/staff/shifts/:id/travel-reminder-check", requireStaffOnly, async (req, res) => {
    try {
        const shiftId = Number(req.params.id);
        const latitude = Number(req.body.latitude);
        const longitude = Number(req.body.longitude);
        if (!Number.isInteger(shiftId) || shiftId <= 0) {
            return res.status(400).json({ success: false, message: "A valid shift id is required." });
        }
        if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
            return res.status(400).json({ success: false, message: "GPS coordinates are required." });
        }

        const shift = await getDb(
            `SELECT ss.*, p.latitude, p.longitude, p.geofence_radius_meters
             FROM staff_shifts ss
             LEFT JOIN patients p ON p.id = ss.patient_id
             WHERE ss.id = ?`,
            [shiftId]
        );
        if (!shift) {
            return res.status(404).json({ success: false, message: "Shift not found." });
        }
        if (Number(shift.staff_id) !== Number(req.session.staffId)) {
            return res.status(403).json({ success: false, message: "You can only check your own assigned shifts." });
        }

        const shiftStart = new Date(normalizeDateTimeString(shift.scheduled_start));
        const now = new Date();
        const minutesUntilStart = Math.floor((shiftStart.getTime() - now.getTime()) / 60000);
        if (Number.isNaN(shiftStart.getTime()) || minutesUntilStart > 30 || minutesUntilStart < 0) {
            return res.json({ success: true, reminderTriggered: false });
        }

        const patientLatitude = Number(shift.latitude);
        const patientLongitude = Number(shift.longitude);
        const geofenceRadius = Number(shift.geofence_radius_meters || 80);
        if (!Number.isFinite(patientLatitude) || !Number.isFinite(patientLongitude)) {
            return res.json({ success: true, reminderTriggered: false });
        }
        const distance = getDistanceInMeters(latitude, longitude, patientLatitude, patientLongitude);
        if (distance <= geofenceRadius) {
            return res.json({ success: true, reminderTriggered: false, distance: Math.round(distance) });
        }

        const existing = await getDb(
            `SELECT id FROM staff_shift_reminders
             WHERE shift_id = ? AND staff_id = ? AND reminder_type = 'travel'`,
            [shiftId, Number(req.session.staffId)]
        );
        if (!existing) {
            await queueStaffNotification(
                Number(req.session.staffId),
                "Travel reminder",
                "Your shift starts in 30 minutes. Please begin travelling to the client's address.",
                "shift",
                `/portal/shifts/${shiftId}`
            );
            await runDb(
                `INSERT INTO staff_shift_reminders (shift_id, staff_id, reminder_type, reminder_minutes)
                 VALUES (?, ?, 'travel', 30)`,
                [shiftId, Number(req.session.staffId)]
            );
        }

        return res.json({ success: true, reminderTriggered: true, distance: Math.round(distance) });
    } catch (error) {
        console.error("Error checking travel reminder:", error.message);
        return res.status(500).json({ success: false, message: "Could not check travel reminder." });
    }
});

app.post("/api/client/login", async (req, res) => {
    const { email, password } = req.body || {};

    if (!email || !password) {
        return res.status(400).json({ success: false, message: "Email and password are required." });
    }

    const throttleStatus = getLoginThrottleStatus(req, email);
    if (throttleStatus.throttled) {
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "client_login_throttled",
            targetType: "client_user",
            targetIdentifier: String(email).trim().toLowerCase(),
            outcome: "denied",
            reason: `too_many_attempts_retry_after_${throttleStatus.retryAfterSeconds}s`,
        });
        return res.status(429).json({
            success: false,
            message: `Too many failed attempts. Try again in ${throttleStatus.retryAfterSeconds} seconds.`,
        });
    }

    try {
        const normalizedEmail = String(email).trim().toLowerCase();
        const account = await getDb("SELECT * FROM client_accounts WHERE lower(email) = ?", [normalizedEmail]);
        const authState = getClientAuthState(account);
        if (!authState.allowed) {
            await writeAuditEvent(req, {
                ...getActorContext(req),
                action: "client_login",
                targetType: "client_user",
                targetIdentifier: normalizedEmail,
                outcome: "denied",
                reason: String((account && account.status) || "not_found"),
            });
            return res.status(403).json({ success: false, message: authState.message });
        }
        const passwordValid = Boolean(account && account.password_hash) && (await bcrypt.compare(String(password), account.password_hash));
        if (!passwordValid) {
            registerFailedLogin(req, normalizedEmail);
            await writeAuditEvent(req, {
                ...getActorContext(req),
                action: "client_login",
                targetType: "client_user",
                targetIdentifier: normalizedEmail,
                outcome: "denied",
                reason: "invalid_credentials",
            });
            return res.status(401).json({ success: false, message: "Invalid email or password." });
        }
        if (Boolean(Number(account.force_password_reset || 0))) {
            return res.status(403).json({
                success: false,
                message: "You must set a new password before accessing the Facility Portal.",
                redirect: `/facility-portal/reset-password?email=${encodeURIComponent(normalizedEmail)}`,
            });
        }
        clearFailedLogins(req, normalizedEmail);
        await regenerateSession(req);
        req.session.isClient = true;
        req.session.isAdmin = false;
        req.session.isStaff = false;
        req.session.clientAccountId = account.id;
        req.session.clientAccountName = account.organization_name || formatName(account.contact_first_name, account.contact_last_name);
        req.session.clientAccountEmail = normalizedEmail;
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "client_login",
            targetType: "client_user",
            targetIdentifier: normalizedEmail,
            outcome: "success",
        });
        
        // Redirect to onboarding if approved but not yet onboarded
        const redirectPath = (account.status === "approved" && !account.onboarded) 
            ? "/client-portal/onboarding" 
            : "/client-portal/dashboard";
        
        return res.json({ success: true, message: "Login successful", redirect: redirectPath });
    } catch (error) {
        console.error("Error processing client login:", error.stack || error.message || error);
        return res.status(500).json({ success: false, message: "Unable to sign in right now." });
    }
});

const getRoleRedirect = (role) => ({
    hr: "/admin/hr-dashboard",
    payroll: "/admin/payroll",
    manager: "/admin/dashboard",
    super_admin: "/portal/dashboard",
    staff: "/portal/home",
})[role] || "/portal/dashboard";

const startMfaLogin = async (req, res, account) => {
    if (!await isMfaRequiredForAccount(account)) return false;
    const methods = await getMfaMethods(account);
    if (!methods.length) {
        await writeAuditEvent(req, {
            action: "mfa_required",
            targetType: `${account.accountType}_user`,
            targetIdentifier: account.email,
            outcome: "denied",
            reason: "no_configured_mfa_method",
        });
        res.status(403).json({
            success: false,
            message: "MFA is required for this role, but no verified MFA method is configured. Contact a Super Admin.",
        });
        return true;
    }
    await regenerateSession(req);
    req.session.mfaPending = {
        accountType: account.accountType,
        accountId: account.id,
        role: account.role,
        redirect: getRoleRedirect(account.role),
        createdAt: Date.now(),
        attemptsRemaining: mfaChallengeAttemptLimit,
    };
    await writeAuditEvent(req, {
        action: "mfa_required",
        targetType: `${account.accountType}_user`,
        targetIdentifier: account.email,
        outcome: "success",
        metadata: { availableMethods: methods.map((method) => method.key) },
    });
    res.json({
        success: true,
        requiresMfa: true,
        message: "Choose a verification method.",
        methods,
    });
    return true;
};

const completePortalLogin = async (req, account) => {
    await regenerateSession(req);
    if (account.accountType === "staff") {
        req.session.isStaff = true;
        req.session.isAdmin = false;
        req.session.staffId = account.id;
        req.session.staffName = account.name || account.email;
        req.session.staffEmail = account.email;
        req.session.staffMfaVersion = Number(account.mfa_version || 1);
    } else {
        const adminUser = await getDb("SELECT * FROM admin_users WHERE id = ?", [account.id]);
        const access = await loadAdminAccessContext(adminUser);
        req.session.isAdmin = true;
        req.session.isStaff = false;
        req.session.adminUserId = account.id;
        req.session.adminAuthVersion = Number(adminUser.auth_version || 1);
        req.session.adminMfaVersion = Number(account.mfa_version || 1);
        req.session.adminRole = access.actualRole;
        req.session.adminPreviewRole = null;
        req.session.adminName = account.name || "Administrator";
        req.session.adminEmail = account.email;
        req.session.staffName = req.session.adminName;
        req.session.staffEmail = account.email;
        await runDb(
            "UPDATE admin_users SET last_login = CURRENT_TIMESTAMP, last_login_ip = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            [String(req.ip || ""), account.id]
        );
    }
};

app.post("/api/admin/login", async (req, res) => {
    const { email, password } = req.body || {};

    if (!email || !password) {
        return res.status(400).json({ success: false, message: "Email and password are required." });
    }

    const throttleStatus = getLoginThrottleStatus(req, email);
    if (throttleStatus.throttled) {
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "login_throttled",
            targetType: "user",
            targetIdentifier: String(email).trim().toLowerCase(),
            outcome: "denied",
            reason: `too_many_attempts_retry_after_${throttleStatus.retryAfterSeconds}s`,
        });
        return res.status(429).json({
            success: false,
            message: `Too many failed attempts. Try again in ${throttleStatus.retryAfterSeconds} seconds.`,
        });
    }

    try {
        const normalizedEmail = String(email).trim().toLowerCase();
        const existingAdminContext = {
            isAdmin: Boolean(req.session && req.session.isAdmin),
            adminName: String((req.session && req.session.adminName) || "Administrator"),
            adminEmail: String((req.session && req.session.adminEmail) || ""),
            adminUserId: Number(req.session && req.session.adminUserId) || null,
            adminRole: String((req.session && req.session.adminRole) || ""),
            adminAuthVersion: Number(req.session && req.session.adminAuthVersion) || null,
            adminPreviewRole: String((req.session && req.session.adminPreviewRole) || ""),
        };
        const existingStaffContext = {
            isStaff: Boolean(req.session && req.session.isStaff && req.session.staffId),
            staffId: Number(req.session && req.session.staffId) || null,
            staffName: String((req.session && req.session.staffName) || ""),
            staffEmail: String((req.session && req.session.staffEmail) || ""),
            staffMfaVersion: Number(req.session && req.session.staffMfaVersion) || null,
        };
        const staffMember = await getDb("SELECT * FROM staff WHERE lower(email) = ?", [normalizedEmail]);
        const staffPasswordValid = Boolean(staffMember && staffMember.password_hash) && (await bcrypt.compare(String(password), staffMember.password_hash));
        if (staffPasswordValid) {
            if (isStaffLoginBlocked(staffMember)) {
                await writeAuditEvent(req, {
                    ...getActorContext(req),
                    action: "login",
                    targetType: "user",
                    targetIdentifier: normalizedEmail,
                    outcome: "denied",
                    reason: "staff_account_blocked",
                });
                return res.status(403).json({ success: false, message: "This staff account is currently inactive. Please contact your manager." });
            }
            clearFailedLogins(req, normalizedEmail);
            const mfaAccount = await getMfaAccount("staff", staffMember.id);
            if (await startMfaLogin(req, res, mfaAccount)) return;
            await regenerateSession(req);
            req.session.isStaff = true;
            req.session.isAdmin = existingAdminContext.isAdmin;
            req.session.adminName = existingAdminContext.adminName;
            req.session.adminEmail = existingAdminContext.adminEmail;
            req.session.adminUserId = existingAdminContext.adminUserId;
            req.session.adminRole = existingAdminContext.adminRole;
            req.session.adminAuthVersion = existingAdminContext.adminAuthVersion;
            req.session.adminPreviewRole = existingAdminContext.adminPreviewRole;
            req.session.staffId = staffMember.id;
            req.session.staffMfaVersion = Number(staffMember.mfa_version || 1);
            req.session.staffName = formatName(staffMember.first_name, staffMember.last_name);
            req.session.staffEmail = normalizedEmail;
            await writeAuditEvent(req, {
                ...getActorContext(req),
                action: "login",
                targetType: "user",
                targetIdentifier: normalizedEmail,
                outcome: "success",
            });
            return res.json({ success: true, message: "Login successful", redirect: "/portal/home" });
        }

        const adminUser = await getDb("SELECT * FROM admin_users WHERE lower(username) = ?", [normalizedEmail]);
        if (adminUser && (await bcrypt.compare(String(password), adminUser.password_hash))) {
            if (Number(adminUser.is_active) !== 1) {
                await writeAuditEvent(req, {
                    action: "login",
                    targetType: "admin_user",
                    targetIdentifier: normalizedEmail,
                    outcome: "denied",
                    reason: "admin_account_disabled",
                });
                return res.status(403).json({
                    success: false,
                    message: "This administrator account is disabled. Contact a Super Admin.",
                });
            }
            clearFailedLogins(req, normalizedEmail);
            const mfaAccount = await getMfaAccount("admin", adminUser.id);
            if (await startMfaLogin(req, res, mfaAccount)) return;
            await regenerateSession(req);
            const access = await loadAdminAccessContext(adminUser);
            req.session.isAdmin = true;
            req.session.adminUserId = adminUser.id;
            req.session.adminAuthVersion = Number(adminUser.auth_version || 1);
            req.session.adminRole = access.actualRole;
            req.session.adminPreviewRole = null;
            req.session.adminName = adminUser.name || "Administrator";
            req.session.adminEmail = normalizedEmail;
            req.session.isStaff = existingStaffContext.isStaff;
            req.session.staffId = existingStaffContext.isStaff ? existingStaffContext.staffId : null;
            req.session.staffName = existingStaffContext.isStaff ? existingStaffContext.staffName : req.session.adminName;
            req.session.staffEmail = existingStaffContext.isStaff ? existingStaffContext.staffEmail : normalizedEmail;
            req.session.staffMfaVersion = existingStaffContext.isStaff ? existingStaffContext.staffMfaVersion : null;
            await runDb(
                "UPDATE admin_users SET last_login = CURRENT_TIMESTAMP, last_login_ip = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                [String(req.ip || ""), adminUser.id]
            );
            await writeAuditEvent(req, {
                ...getActorContext(req),
                action: "login",
                targetType: "admin_user",
                targetIdentifier: normalizedEmail,
                outcome: "success",
            });
            const redirectByRole = {
                hr: "/portal/applications",
                payroll: "/admin/payroll",
                manager: "/admin/dashboard",
                super_admin: "/portal/dashboard",
            };
            return res.json({
                success: true,
                message: "Login successful",
                redirect: redirectByRole[access.actualRole] || "/portal/dashboard",
                role: access.actualRole,
            });
        }

        registerFailedLogin(req, normalizedEmail);
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "login",
            targetType: "user",
            targetIdentifier: normalizedEmail,
            outcome: "denied",
            reason: "invalid_credentials",
        });
        return res.status(401).json({ success: false, message: "Invalid email or password." });
    } catch (error) {
        console.error("Error during login:", error.message);
        return res.status(500).json({ success: false, message: "Unable to sign in at this time." });
    }
});

const getPendingMfaAccount = async (req) => {
    const pending = req.session && req.session.mfaPending;
    if (!pending || Date.now() - Number(pending.createdAt || 0) > 15 * 60 * 1000) {
        const error = new Error("Your MFA sign-in session has expired. Sign in again.");
        error.code = "MFA_SESSION_EXPIRED";
        throw error;
    }
    const account = await getMfaAccount(pending.accountType, pending.accountId);
    if (!account
        || (account.accountType === "admin" && Number(account.is_active) !== 1)
        || (account.accountType === "staff" && isStaffLoginBlocked(account))) {
        const error = new Error("This account is no longer available.");
        error.code = "MFA_ACCOUNT_UNAVAILABLE";
        throw error;
    }
    return account;
};

app.post("/api/mfa/challenge", async (req, res) => {
    try {
        const account = await getPendingMfaAccount(req);
        const method = String(req.body && req.body.method || "").trim().toLowerCase();
        const methods = await getMfaMethods(account);
        if (!methods.some((item) => item.key === method)) {
            return res.status(400).json({ success: false, message: "That verification method is not available." });
        }
        if (method === "authenticator" || method === "recovery") {
            return res.json({ success: true, method, message: method === "authenticator"
                ? "Enter the 6-digit code from your authenticator app."
                : "Enter one of your unused recovery codes." });
        }
        const challenge = await createMfaChallenge({
            req,
            account,
            method,
            purpose: "login",
        });
        await writeAuditEvent(req, {
            action: "mfa_challenge_sent",
            targetType: `${account.accountType}_user`,
            targetIdentifier: account.email,
            outcome: "success",
            metadata: { method },
        });
        return res.json({
            success: true,
            method,
            expiresInSeconds: challenge.expiresInSeconds,
            message: `A verification code was sent to ${method === "email" ? maskEmail(account.email) : maskPhone(account.phone)}.`,
        });
    } catch (error) {
        const status = {
            MFA_SESSION_EXPIRED: 401,
            MFA_ACCOUNT_UNAVAILABLE: 403,
            MFA_RATE_LIMITED: 429,
            MFA_RESEND_DELAY: 429,
            MFA_EMAIL_NOT_CONFIGURED: 503,
            MFA_SMS_NOT_CONFIGURED: 503,
        }[error.code] || 500;
        if (status === 500) console.error("Error creating MFA challenge:", error.message);
        return res.status(status).json({ success: false, message: error.message || "Could not create the MFA challenge." });
    }
});

app.post("/api/mfa/verify", async (req, res) => {
    try {
        const account = await getPendingMfaAccount(req);
        const method = String(req.body && req.body.method || "").trim().toLowerCase();
        const code = String(req.body && req.body.code || "").trim();
        const methods = await getMfaMethods(account);
        if (!methods.some((item) => item.key === method) || !code) {
            return res.status(400).json({ success: false, message: "Choose an available method and enter its verification code." });
        }

        let verified = false;
        if (method === "email" || method === "sms") {
            const result = await verifyMfaChallenge({
                req,
                account,
                method,
                purpose: "login",
                code,
            });
            verified = result.verified;
        } else {
            const pending = req.session.mfaPending;
            if (Number(pending.attemptsRemaining || 0) <= 0) {
                const error = new Error("Too many failed attempts. Sign in again.");
                error.code = "MFA_ATTEMPTS_EXCEEDED";
                throw error;
            }
            pending.attemptsRemaining = Number(pending.attemptsRemaining || 0) - 1;
            if (method === "authenticator") {
                verified = mfaSecurity.verifyTotp(mfaSecurity.decryptSecret(account.totp_secret_encrypted), code);
            } else {
                const recoveryCodes = await allDb(
                    `SELECT id, code_hash FROM mfa_recovery_codes
                     WHERE account_type = ? AND account_id = ? AND used_at IS NULL`,
                    [account.accountType, account.id]
                );
                const matchingCode = recoveryCodes.find((item) => mfaSecurity.verifyRecoveryCode(code, item.code_hash));
                if (matchingCode) {
                    const consumed = await runDb(
                        "UPDATE mfa_recovery_codes SET used_at = CURRENT_TIMESTAMP WHERE id = ? AND used_at IS NULL",
                        [matchingCode.id]
                    );
                    verified = Number(consumed.changes || 0) === 1;
                }
            }
        }

        if (!verified) {
            await writeAuditEvent(req, {
                action: "mfa_failure",
                targetType: `${account.accountType}_user`,
                targetIdentifier: account.email,
                outcome: "denied",
                metadata: { method },
            });
            return res.status(401).json({ success: false, message: "The verification code is invalid or expired." });
        }

        const redirect = req.session.mfaPending.redirect || getRoleRedirect(account.role);
        await completePortalLogin(req, account);
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "mfa_success",
            targetType: `${account.accountType}_user`,
            targetIdentifier: account.email,
            outcome: "success",
            metadata: { method },
        });
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "login",
            targetType: `${account.accountType}_user`,
            targetIdentifier: account.email,
            outcome: "success",
            reason: "mfa_verified",
        });
        return res.json({ success: true, message: "Verification successful.", redirect, role: account.role });
    } catch (error) {
        const status = {
            MFA_SESSION_EXPIRED: 401,
            MFA_ACCOUNT_UNAVAILABLE: 403,
            MFA_CHALLENGE_MISSING: 400,
            MFA_CHALLENGE_EXPIRED: 401,
            MFA_ATTEMPTS_EXCEEDED: 429,
        }[error.code] || 500;
        if (status === 500) console.error("Error verifying MFA:", error.message);
        return res.status(status).json({ success: false, message: error.message || "Could not verify the MFA code." });
    }
});

app.post("/api/admin/logout", requirePortal, async (req, res) => {
    try {
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "logout",
            targetType: "session",
            targetIdentifier: "api",
            outcome: "success",
        });
        await destroySession(req);
        res.json({ success: true, message: "Logged out successfully." });
    } catch (error) {
        console.error("Error during API logout:", error.message);
        res.status(500).json({ success: false, message: "Unable to sign out at this time." });
    }
});

app.post("/api/staff/shifts/:id/clock-in", requirePortal, async (req, res) => {
    try {
        const shiftId = Number(req.params.id);
        const latitude = Number(req.body.latitude);
        const longitude = Number(req.body.longitude);
        const accuracy = req.body.accuracy !== undefined ? Number(req.body.accuracy) : null;
        const device = String(req.body.device || req.get("user-agent") || "").slice(0, 255);

        if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
            return res.status(400).json({ success: false, message: "GPS is unavailable. Enable location services to clock in." });
        }

        const shift = await getDb(`
            SELECT ss.*, COALESCE(p.latitude, ss.external_latitude) AS latitude, COALESCE(p.longitude, ss.external_longitude) AS longitude, COALESCE(p.geofence_radius_meters, ss.external_geofence_radius_meters) AS geofence_radius_meters, COALESCE(p.first_name || ' ' || p.last_name, ss.external_client_label, 'Client') AS patient_name
            FROM staff_shifts ss
            LEFT JOIN patients p ON p.id = ss.patient_id
            WHERE ss.id = ?
        `, [shiftId]);

        if (!shift) {
            return res.status(404).json({ success: false, message: "Shift not found." });
        }

        if (req.session.staffId && Number(shift.staff_id) !== Number(req.session.staffId) && !req.session.isAdmin) {
            return res.status(403).json({ success: false, message: "You can only clock in for your own assigned shift." });
        }

        if (shift.status === "clocked_in") {
            return res.status(400).json({ success: false, message: "This shift is already active." });
        }

        const patientLatitude = Number(shift.latitude);
        const patientLongitude = Number(shift.longitude);
        const geofenceRadius = Number(shift.geofence_radius_meters || 80);

        if (!Number.isFinite(patientLatitude) || !Number.isFinite(patientLongitude)) {
            return res.status(400).json({ success: false, message: "This client location is not configured yet." });
        }

        const distance = getDistanceInMeters(latitude, longitude, patientLatitude, patientLongitude);
        if (distance > geofenceRadius) {
            return res.status(403).json({
                success: false,
                message: "You are not within the client's location. Move closer to clock in.",
                distance: Math.round(distance),
            });
        }

        await runDb(
            `UPDATE staff_shifts
             SET status = 'clocked_in',
                 actual_clock_in = datetime('now'),
                 clock_in_latitude = ?,
                 clock_in_longitude = ?,
                 clock_in_accuracy = ?,
                 clock_in_device = ?
             WHERE id = ?`,
            [latitude, longitude, Number.isFinite(accuracy) ? accuracy : null, device || null, shiftId]
        );
        await syncClientRequestStatusFromShift({
            shiftId,
            shiftStatus: "clocked_in",
            notifyTitle: "Staff checked in",
            notifyBody: "The assigned staff member has checked in for the scheduled shift.",
        });
        emitPortalEvent("shift_update", { action: "clock_in", shiftId: Number(shiftId), staffId: Number(shift.staff_id) });

        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "clock_in",
            targetType: "shift",
            targetIdentifier: String(shiftId),
            outcome: "success",
        });
        return res.json({ success: true, message: "Clock-in recorded successfully.", distance: Math.round(distance), shiftId });
    } catch (error) {
        console.error("Error clocking in:", error.message);
        return res.status(500).json({ success: false, message: "Could not record clock-in." });
    }
});

app.post("/api/staff/shifts/:id/clock-out", requirePortal, async (req, res) => {
    try {
        const shiftId = Number(req.params.id);
        const latitude = Number(req.body.latitude);
        const longitude = Number(req.body.longitude);
        const accuracy = req.body.accuracy !== undefined ? Number(req.body.accuracy) : null;
        const device = String(req.body.device || req.get("user-agent") || "").slice(0, 255);

        if (!Number.isFinite(latitude) || !Number.isFinite(longitude)) {
            return res.status(400).json({ success: false, message: "GPS is unavailable. Enable location services to clock out." });
        }

        const shift = await getDb(`
            SELECT ss.*, COALESCE(p.latitude, ss.external_latitude) AS latitude, COALESCE(p.longitude, ss.external_longitude) AS longitude, COALESCE(p.geofence_radius_meters, ss.external_geofence_radius_meters) AS geofence_radius_meters, COALESCE(p.first_name || ' ' || p.last_name, ss.external_client_label, 'Client') AS patient_name
            FROM staff_shifts ss
            LEFT JOIN patients p ON p.id = ss.patient_id
            WHERE ss.id = ?
        `, [shiftId]);

        if (!shift) {
            return res.status(404).json({ success: false, message: "Shift not found." });
        }

        if (req.session.staffId && Number(shift.staff_id) !== Number(req.session.staffId) && !req.session.isAdmin) {
            return res.status(403).json({ success: false, message: "You can only clock out for your own assigned shift." });
        }

        if (shift.status !== "clocked_in") {
            return res.status(400).json({ success: false, message: "This shift is not currently active." });
        }

        const patientLatitude = Number(shift.latitude);
        const patientLongitude = Number(shift.longitude);
        const geofenceRadius = Number(shift.geofence_radius_meters || 80);
        if (!Number.isFinite(patientLatitude) || !Number.isFinite(patientLongitude)) {
            return res.status(400).json({ success: false, message: "This client location is not configured yet." });
        }
        const distance = getDistanceInMeters(latitude, longitude, patientLatitude, patientLongitude);

        if (distance > geofenceRadius) {
            return res.status(403).json({
                success: false,
               message: "You are not within the client's location. Move closer to clock out.",
                distance: Math.round(distance),
            });
        }

        await runDb(
            `UPDATE staff_shifts
             SET status = 'clocked_out',
                 actual_clock_out = datetime('now'),
                 clock_out_latitude = ?,
                 clock_out_longitude = ?,
                 clock_out_accuracy = ?,
                 clock_out_device = ?
             WHERE id = ?`,
            [latitude, longitude, Number.isFinite(accuracy) ? accuracy : null, device || null, shiftId]
        );
        await syncClientRequestStatusFromShift({
            shiftId,
            shiftStatus: "clocked_out",
            notifyTitle: "Staff checked out",
            notifyBody: "The assigned staff member has checked out from the shift.",
        });
        emitPortalEvent("shift_update", { action: "clock_out", shiftId: Number(shiftId), staffId: Number(shift.staff_id) });

        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "clock_out",
            targetType: "shift",
            targetIdentifier: String(shiftId),
            outcome: "success",
        });
        return res.json({ success: true, message: "Clock-out recorded successfully.", distance: Math.round(distance), shiftId });
    } catch (error) {
        console.error("Error clocking out:", error.message);
        return res.status(500).json({ success: false, message: "Could not record clock-out." });
    }
});

app.get("/portal/home", requireStaffOnly, async (req, res) => {
    try {
        const staffMember = mapStaffRow(await getDb("SELECT * FROM staff WHERE id = ?", [Number(req.session.staffId)]));
        if (!staffMember) {
            return res.redirect("/portal/login?error=Your staff account could not be found.");
        }
        await queueDueShiftReminders(staffMember);

        const today = new Date();
        const todayKey = getBusinessDateKey(today);
        const weekRange = getWeekRange(today);
        const assignedShifts = (await allDb(
            `SELECT ss.*, COALESCE(p.first_name || ' ' || p.last_name, ss.external_client_label, 'Client') AS patient_name, COALESCE(p.address, ss.location_address) AS address
             FROM staff_shifts ss
             LEFT JOIN patients p ON p.id = ss.patient_id
             WHERE ss.staff_id = ?
               AND COALESCE(ss.is_open, 0) = 0
             ORDER BY ss.scheduled_start ASC
             `,
            [staffMember.id]
        )).map(mapShiftRow);
        const visibleAssignedShifts = filterShiftsForStaffDivision(staffMember, assignedShifts);

        const currentShiftStatuses = new Set(["scheduled", "not_clocked_in", "running_late", "clocked_in", "break"]);
        const todayShift = visibleAssignedShifts.find((shift) => toDateKey(shift.scheduledStart) === todayKey && currentShiftStatuses.has(shift.status)) || null;
        const upcomingShifts = visibleAssignedShifts.filter((shift) => {
            const shiftDateKey = toDateKey(shift.scheduledStart);
            return shiftDateKey >= todayKey && currentShiftStatuses.has(shift.status);
        });
        const upcomingShiftCount = upcomingShifts.length;
        const upcomingShiftPreview = upcomingShifts.slice(0, 8);
        const weeklyRoster = (await allDb(
            `SELECT ss.*, COALESCE(p.first_name || ' ' || p.last_name, ss.external_client_label, 'Client') AS patient_name, COALESCE(p.address, ss.location_address) AS address
             FROM staff_shifts ss
             LEFT JOIN patients p ON p.id = ss.patient_id
             WHERE ss.staff_id = ?
               AND COALESCE(ss.is_open, 0) = 0
               AND date(ss.scheduled_start) BETWEEN date(?) AND date(?)
             ORDER BY ss.scheduled_start ASC`,
            [staffMember.id, toDateKey(weekRange.start), toDateKey(weekRange.end)]
        )).map(mapShiftRow);
        const visibleWeeklyRoster = filterShiftsForStaffDivision(staffMember, weeklyRoster);

        let totalWeekMinutes = 0;
        for (const shift of visibleWeeklyRoster) {
            if (shift.actual_clock_in && shift.actual_clock_out) {
                totalWeekMinutes += Math.max(0, Math.round((new Date(shift.actual_clock_out) - new Date(shift.actual_clock_in)) / 60000));
            }
        }

        const notifications = await allDb(
            `SELECT * FROM staff_notifications
             WHERE staff_id = ? AND deleted_at IS NULL
             ORDER BY is_read ASC, created_at DESC
             LIMIT 5`,
            [staffMember.id]
        );
        const assignedClients = await getAssignedPatientsForStaff(staffMember.id);

        const unreadCountRow = await getDb(
            "SELECT COUNT(*) AS count FROM staff_notifications WHERE staff_id = ? AND deleted_at IS NULL AND COALESCE(is_read, 0) = 0",
            [staffMember.id]
        );

        return res.render("portal-staff-dashboard", {
            title: "Staff Dashboard",
            isLoggedIn: true,
            isAdmin: false,
            currentStaffName: staffMember.name,
            currentStaffEmail: staffMember.email,
            staffMember,
            todayShift,
            upcomingShifts: upcomingShiftPreview,
            upcomingShiftCount,
            weeklyRoster: visibleWeeklyRoster,
            weeklyHours: (totalWeekMinutes / 60).toFixed(1),
            notifications,
            assignedClients,
            unreadCount: Number(unreadCountRow ? unreadCountRow.count : 0),
            weekLabel: formatWeekLabel(weekRange.start, weekRange.end),
        });
    } catch (error) {
        console.error("Error loading staff dashboard:", error.message);
        return res.status(500).render("error", { title: "Staff dashboard unavailable", message: "The staff dashboard could not be loaded." });
    }
});

app.get("/portal/my-schedule", requireStaffOnly, async (req, res) => {
    try {
        const staffMember = mapStaffRow(await getDb("SELECT * FROM staff WHERE id = ?", [Number(req.session.staffId)]));
        await queueDueShiftReminders(staffMember);
        const viewMode = ["today", "weekly", "monthly", "calendar", "list"].includes(String(req.query.view || "")) ? String(req.query.view) : "today";
        const allShifts = (await allDb(
            `SELECT ss.*, COALESCE(p.first_name || ' ' || p.last_name, ss.external_client_label, 'Client') AS patient_name, COALESCE(p.address, ss.location_address) AS address
             FROM staff_shifts ss
             LEFT JOIN patients p ON p.id = ss.patient_id
             WHERE ss.staff_id = ? AND COALESCE(ss.is_open, 0) = 0
             ORDER BY ss.scheduled_start ASC`,
            [staffMember.id]
        )).map(mapShiftRow);
        const visibleAllShifts = filterShiftsForStaffDivision(staffMember, allShifts);

        const todayKey = getBusinessDateKey();
        const weekRange = getWeekRange(new Date());
        const monthKey = todayKey.slice(0, 7);
        const filteredShifts = visibleAllShifts.filter((shift) => {
            const shiftDateKey = toDateKey(shift.scheduledStart);
            if (viewMode === "today") {
                return shiftDateKey === todayKey;
            }
            if (viewMode === "weekly") {
                return shiftDateKey >= toDateKey(weekRange.start) && shiftDateKey <= toDateKey(weekRange.end);
            }
            if (viewMode === "monthly" || viewMode === "calendar") {
                return shiftDateKey.startsWith(monthKey);
            }
            return shiftDateKey >= todayKey && ["scheduled", "not_clocked_in", "running_late", "clocked_in", "break"].includes(shift.status);
        });

        return res.render("portal-staff-schedule", {
            title: "My Schedule",
            isLoggedIn: true,
            isAdmin: false,
            currentStaffName: staffMember.name,
            currentStaffEmail: staffMember.email,
            viewMode,
            shifts: filteredShifts,
            allShifts: visibleAllShifts,
            todayKey,
        });
    } catch (error) {
        console.error("Error loading staff schedule:", error.message);
        return res.status(500).render("error", { title: "Schedule unavailable", message: "Your schedule could not be loaded." });
    }
});

app.get("/portal/weekly-roster", requireStaffOnly, async (req, res) => {
    try {
        const staffMember = mapStaffRow(await getDb("SELECT * FROM staff WHERE id = ?", [Number(req.session.staffId)]));
        const startParam = String(req.query.week || "").trim();
        const range = startParam ? getWeekRange(new Date(`${startParam}T12:00:00`)) : getWeekRange(new Date());
        const roster = (await allDb(
            `SELECT ss.*, COALESCE(p.first_name || ' ' || p.last_name, ss.external_client_label, 'Client') AS patient_name, COALESCE(p.address, ss.location_address) AS address
             FROM staff_shifts ss
             LEFT JOIN patients p ON p.id = ss.patient_id
             WHERE ss.staff_id = ? AND COALESCE(ss.is_open, 0) = 0
               AND date(ss.scheduled_start) BETWEEN date(?) AND date(?)
             ORDER BY ss.scheduled_start ASC`,
            [staffMember.id, toDateKey(range.start), toDateKey(range.end)]
        )).map(mapShiftRow);
        const visibleRoster = filterShiftsForStaffDivision(staffMember, roster);

        return res.render("portal-weekly-roster", {
            title: "Weekly Roster",
            isLoggedIn: true,
            isAdmin: false,
            currentStaffName: staffMember.name,
            currentStaffEmail: staffMember.email,
            roster: visibleRoster,
            weekStart: toDateKey(range.start),
            weekEnd: toDateKey(range.end),
            weekLabel: formatWeekLabel(range.start, range.end),
        });
    } catch (error) {
        console.error("Error loading weekly roster:", error.message);
        return res.status(500).render("error", { title: "Roster unavailable", message: "Your weekly roster could not be loaded." });
    }
});

app.get("/portal/staff-open-shifts", requireStaffOnly, async (req, res) => {
    try {
        const staffMember = mapStaffRow(await getDb("SELECT * FROM staff WHERE id = ?", [Number(req.session.staffId)]));
        const openShiftRows = (await allDb(
            `SELECT ss.*,
                    p.home_care_client_id,
                    COALESCE(p.first_name || ' ' || p.last_name, ss.external_client_label, 'Home Care Client') AS home_care_client_name,
                    COALESCE(ss.external_client_label, ca.organization_name, p.first_name || ' ' || p.last_name, 'Client') AS patient_name,
                    ca.organization_name AS facility_name,
                    ca.organization_type AS facility_type,
                    COALESCE(p.address, ss.location_address, ca.address_line_1) AS address,
                    COALESCE(p.latitude, ss.external_latitude) AS latitude,
                    COALESCE(p.longitude, ss.external_longitude) AS longitude
             FROM staff_shifts ss
             LEFT JOIN patients p ON p.id = ss.patient_id
             LEFT JOIN client_accounts ca ON ca.id = ss.client_account_id
             WHERE COALESCE(ss.is_open, 0) = 1 AND ss.staff_id IS NULL
             ORDER BY ss.scheduled_start ASC`,
            []
        )).map(mapShiftRow).filter((shift) => shift.operationalStatus === "open");
        const requestCache = new Map();
        const openShifts = [];
        for (const shift of openShiftRows) {
            if (!staffCanWorkDivision(staffMember, shift.serviceDivision)) {
                continue;
            }
            if (!shift.clientRequestId) {
                openShifts.push(shift);
                continue;
            }
            if (!requestCache.has(shift.clientRequestId)) {
               const requestRow = await getDb("SELECT * FROM client_service_requests WHERE id = ?", [Number(shift.clientRequestId)]);
               requestCache.set(shift.clientRequestId, requestRow ? mapClientRequestRow(requestRow) : null);
            }
            const request = requestCache.get(shift.clientRequestId);
            const eligibility = await staffMeetsRequestRequirements({
               staffMember,
               shift: {
                   id: shift.id,
                   scheduled_start: shift.scheduledStart,
                   scheduled_end: shift.scheduledEnd,
               },
               request,
            });
            if (eligibility.eligible) {
               openShifts.push({
                   ...shift,
                   request,
               });
            }
        }

        return res.render("portal-staff-open-shifts", {
            title: "Open Shifts",
            isLoggedIn: true,
            isAdmin: false,
            currentStaffName: staffMember.name,
            currentStaffEmail: staffMember.email,
            openShifts,
        });
    } catch (error) {
        console.error("Error loading staff open shifts:", error.message);
        return res.status(500).render("error", { title: "Open shifts unavailable", message: "Open shifts could not be loaded." });
    }
});

app.post("/api/staff/open-shifts/:id/accept", requireStaffOnly, async (req, res) => {
    try {
        const shiftId = Number(req.params.id);
        const staffId = Number(req.session.staffId);
        const staffMember = mapStaffRow(await getDb("SELECT * FROM staff WHERE id = ?", [staffId]));
        const shift = await getDb("SELECT * FROM staff_shifts WHERE id = ?", [shiftId]);
        if (!shift) {
            return res.status(404).json({ success: false, message: "Open shift not found." });
        }
        const shiftDivision = getShiftDivision(shift);
        if (!staffCanWorkDivision(staffMember, shiftDivision)) {
            return res.status(403).json({ success: false, message: `Your profile is not enabled for ${shiftDivision === "agency-staffing" ? "Agency Staffing" : "Home Care"} shifts.` });
        }
        if (Number(shift.is_open || 0) !== 1 || shift.staff_id) {
            return res.status(409).json({ success: false, message: "This open shift has already been taken." });
        }
        if (!isAvailableOpenShift(shift)) {
            return res.status(409).json({ success: false, message: "This shift is no longer available." });
        }
        const assignedHourlyRate = await getValidStaffHourlyRate(staffId);
        if (shift.client_request_id) {
            const request = mapClientRequestRow(await getDb("SELECT * FROM client_service_requests WHERE id = ?", [Number(shift.client_request_id)]));
            const eligibility = await staffMeetsRequestRequirements({
                staffMember,
                shift: {
                    id: shift.id,
                    scheduled_start: shift.scheduled_start,
                    scheduled_end: shift.scheduled_end,
                },
                request,
            });
            if (!eligibility.eligible) {
                return res.status(403).json({ success: false, message: eligibility.reasons[0] || "You are not eligible for this shift." });
            }
        }

        await runDb(
            "UPDATE staff_shifts SET staff_id = ?, is_open = 0, status = 'scheduled' WHERE id = ? AND COALESCE(is_open, 0) = 1 AND staff_id IS NULL",
            [staffId, shiftId]
        );
        await snapshotShiftPayRate(shiftId, staffId, assignedHourlyRate);
        if (shift.client_request_id) {
            await runDb(
                "UPDATE client_service_requests SET status = 'accepted', assigned_staff_id = ?, scheduled_shift_id = ?, accepted_by_staff_at = datetime('now'), updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                [staffId, shiftId, Number(shift.client_request_id)]
            );
            await queueClientNotification(
                Number(shift.client_account_id),
                "Shift accepted by staff",
                `${staffMember.name} has accepted your request and the shift is now confirmed.`,
                "request",
                "/facility-portal/requests"
            );
            emitPortalEvent("client_request", { requestId: Number(shift.client_request_id), status: "accepted" }, { adminOnly: true });
        }

        if (staffMember && staffMember.notifyOpenShift) {
            await queueStaffNotification(
                staffId,
                "Open shift accepted",
                "The shift has been added to your schedule.",
                "shift",
                `/portal/shifts/${shiftId}`
            );
        }
        emitPortalEvent("open_shift_update", { action: "accepted", shiftId: Number(shiftId), staffId: Number(staffId) });
        emitPortalEvent("shift_update", { action: "accepted_open_shift", shiftId: Number(shiftId), staffId: Number(staffId) }, { staffIds: [Number(staffId)] });
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "open_shift_accepted",
            targetType: "shift",
            targetIdentifier: String(shiftId),
            outcome: "success",
        });

        return res.json({ success: true, message: "Shift accepted successfully." });
    } catch (error) {
        console.error("Error accepting open shift:", error.message);
        return res.status(500).json({ success: false, message: "Unable to accept this shift." });
    }
});

app.get("/portal/notifications", requireStaffOnly, async (req, res) => {
    try {
        const staffMember = mapStaffRow(await getDb("SELECT * FROM staff WHERE id = ?", [Number(req.session.staffId)]));
        await queueDueShiftReminders(staffMember);
        const notifications = await allDb(
            `SELECT * FROM staff_notifications
             WHERE staff_id = ? AND deleted_at IS NULL
             ORDER BY is_read ASC, created_at DESC`,
            [staffMember.id]
        );
        res.render("portal-staff-notifications", {
            title: "Notifications",
            isLoggedIn: true,
            isAdmin: false,
            currentStaffName: staffMember.name,
            currentStaffEmail: staffMember.email,
            notifications,
        });
    } catch (error) {
        console.error("Error loading notifications:", error.message);
        return res.status(500).render("error", { title: "Notifications unavailable", message: "Notifications could not be loaded." });
    }
});

app.post("/api/staff/notifications/:id/read", requireStaffOnly, async (req, res) => {
    try {
        await runDb("UPDATE staff_notifications SET is_read = 1 WHERE id = ? AND staff_id = ?", [Number(req.params.id), Number(req.session.staffId)]);
        return res.json({ success: true });
    } catch (error) {
        return res.status(500).json({ success: false, message: "Unable to update notification." });
    }
});

app.post("/api/staff/notifications/:id/delete", requireStaffOnly, async (req, res) => {
    try {
        await runDb("UPDATE staff_notifications SET deleted_at = datetime('now') WHERE id = ? AND staff_id = ?", [Number(req.params.id), Number(req.session.staffId)]);
        return res.json({ success: true });
    } catch (error) {
        return res.status(500).json({ success: false, message: "Unable to delete notification." });
    }
});

const getPortalMfaAccount = async (req) => {
    if (req.session.isAdmin && req.session.adminUserId) {
        return getMfaAccount("admin", req.session.adminUserId);
    }
    return getMfaAccount("staff", req.session.staffId);
};

const replaceRecoveryCodes = async (account) => {
    const recoveryCodes = mfaSecurity.createRecoveryCodes(10);
    await runDb("DELETE FROM mfa_recovery_codes WHERE account_type = ? AND account_id = ?", [account.accountType, account.id]);
    for (const recoveryCode of recoveryCodes) {
        await runDb(
            `INSERT INTO mfa_recovery_codes (account_type, account_id, code_hash)
             VALUES (?, ?, ?)`,
            [account.accountType, account.id, mfaSecurity.hashRecoveryCode(recoveryCode)]
        );
    }
    return recoveryCodes;
};

const updatePortalMfaAccount = async (account, sql, params = []) => {
    const tableName = account.accountType === "admin" ? "admin_users" : "staff";
    await runDb(`UPDATE ${tableName} SET ${sql} WHERE id = ?`, [...params, account.id]);
};

app.get("/portal/security/mfa", requirePortal, async (req, res) => {
    try {
        const account = await getPortalMfaAccount(req);
        const methods = await getMfaMethods(account);
        const recoveryCount = await getDb(
            `SELECT COUNT(*) AS count FROM mfa_recovery_codes
             WHERE account_type = ? AND account_id = ? AND used_at IS NULL`,
            [account.accountType, account.id]
        );
        const securityPolicy = await getSecurityPolicy();
        const viewAccount = {
            ...account,
            maskedEmail: maskEmail(account.email),
            maskedPhone: maskPhone(account.phone),
            emailVerified: Number(account.email_verified) === 1,
            phoneVerified: Number(account.phone_verified) === 1,
        };
        return res.render("portal-mfa-security", {
            title: "Sign-in Security",
            isLoggedIn: true,
            isAdmin: account.accountType === "admin",
            currentStaffName: account.name,
            currentStaffEmail: account.email,
            account: viewAccount,
            methods,
            recoveryCodeCount: Number(recoveryCount && recoveryCount.count || 0),
            globalMfaEnabled: securityPolicy.mfaGlobalEnabled,
            roleMfaRequired: securityPolicy.mfaRoleRequirements[account.role] === true,
            providerStatus: {
                email: Boolean(smtpHost && smtpUser && smtpPass && smtpFrom),
                sms: Boolean(twilioAccountSid && twilioAuthToken && twilioFromNumber),
                authenticator: isAuthenticatorMfaConfigured(),
            },
            message: req.query.message || "",
            error: req.query.error || "",
        });
    } catch (error) {
        console.error("Error loading MFA security:", error.message);
        return res.status(500).render("error", { title: "Security unavailable", message: "Sign-in security could not be loaded." });
    }
});

app.post("/portal/security/mfa/contact-challenge", requirePortal, async (req, res) => {
    try {
        const account = await getPortalMfaAccount(req);
        const method = String(req.body && req.body.method || "").trim().toLowerCase();
        if (!["email", "sms"].includes(method)) {
            return res.status(400).json({ success: false, message: "Choose email or SMS verification." });
        }
        const challenge = await createMfaChallenge({ req, account, method, purpose: `setup_${method}` });
        return res.json({
            success: true,
            expiresInSeconds: challenge.expiresInSeconds,
            message: `A verification code was sent to ${method === "email" ? maskEmail(account.email) : maskPhone(account.phone)}.`,
        });
    } catch (error) {
        const status = ["MFA_RATE_LIMITED", "MFA_RESEND_DELAY"].includes(error.code)
            ? 429
            : ["MFA_EMAIL_NOT_CONFIGURED", "MFA_SMS_NOT_CONFIGURED"].includes(error.code)
                ? 503
                : 500;
        if (status === 500) console.error("Error creating contact verification:", error.message);
        return res.status(status).json({ success: false, message: error.message || "Could not send the verification code." });
    }
});

app.post("/portal/security/mfa/contact-verify", requirePortal, async (req, res) => {
    try {
        const account = await getPortalMfaAccount(req);
        const method = String(req.body && req.body.method || "").trim().toLowerCase();
        const code = String(req.body && req.body.code || "").trim();
        if (!["email", "sms"].includes(method) || !code) {
            return res.status(400).json({ success: false, message: "Enter the verification code." });
        }
        const result = await verifyMfaChallenge({ req, account, method, purpose: `setup_${method}`, code });
        if (!result.verified) {
            await writeAuditEvent(req, {
                ...getActorContext(req),
                action: "mfa_setup_failure",
                targetType: `${account.accountType}_user`,
                targetIdentifier: account.email,
                outcome: "denied",
                metadata: { method },
            });
            return res.status(401).json({ success: false, message: "The verification code is invalid or expired." });
        }
        const verifiedColumn = method === "email" ? "email_verified" : "phone_verified";
        await updatePortalMfaAccount(
            account,
            `${verifiedColumn} = 1, mfa_enabled = 1, mfa_reset_required = 0, mfa_version = COALESCE(mfa_version, 1) + 1, updated_at = CURRENT_TIMESTAMP`
        );
        if (account.accountType === "staff") {
            req.session.staffMfaVersion = Number(account.mfa_version || 1) + 1;
        }
        const recoveryCodes = await replaceRecoveryCodes(account);
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "mfa_setup",
            targetType: `${account.accountType}_user`,
            targetIdentifier: account.email,
            outcome: "success",
            metadata: { method },
        });
        return res.json({
            success: true,
            message: `${method === "email" ? "Email" : "SMS"} MFA is configured.`,
            recoveryCodes,
        });
    } catch (error) {
        const status = {
            MFA_CHALLENGE_MISSING: 400,
            MFA_CHALLENGE_EXPIRED: 401,
            MFA_ATTEMPTS_EXCEEDED: 429,
        }[error.code] || 500;
        if (status === 500) console.error("Error verifying MFA contact:", error.message);
        return res.status(status).json({ success: false, message: error.message || "Could not verify the code." });
    }
});

app.post("/portal/security/mfa/authenticator/start", requirePortal, async (req, res) => {
    try {
        const account = await getPortalMfaAccount(req);
        const setup = mfaSecurity.createTotpSetup(account.email);
        req.session.pendingTotpSetup = {
            accountType: account.accountType,
            accountId: account.id,
            encryptedSecret: mfaSecurity.encryptSecret(setup.secret),
            createdAt: Date.now(),
        };
        return res.json({
            success: true,
            qrCode: await QRCode.toDataURL(setup.uri, { width: 240, margin: 1 }),
            manualKey: setup.secret,
        });
    } catch (error) {
        const status = error.code === "MFA_ENCRYPTION_KEY_REQUIRED" ? 503 : 500;
        if (status === 500) console.error("Error starting authenticator setup:", error.message);
        return res.status(status).json({ success: false, message: error.message || "Could not start authenticator setup." });
    }
});

app.post("/portal/security/mfa/authenticator/verify", requirePortal, async (req, res) => {
    try {
        const account = await getPortalMfaAccount(req);
        const setup = req.session.pendingTotpSetup;
        if (!setup
            || setup.accountType !== account.accountType
            || Number(setup.accountId) !== account.id
            || Date.now() - Number(setup.createdAt || 0) > 10 * 60 * 1000) {
            return res.status(400).json({ success: false, message: "Authenticator setup expired. Start again." });
        }
        const secret = mfaSecurity.decryptSecret(setup.encryptedSecret);
        if (!mfaSecurity.verifyTotp(secret, String(req.body && req.body.code || ""))) {
            return res.status(401).json({ success: false, message: "The authenticator code is invalid." });
        }
        await updatePortalMfaAccount(
            account,
            "totp_secret_encrypted = ?, totp_verified_at = CURRENT_TIMESTAMP, mfa_enabled = 1, mfa_reset_required = 0, mfa_version = COALESCE(mfa_version, 1) + 1, updated_at = CURRENT_TIMESTAMP",
            [setup.encryptedSecret]
        );
        if (account.accountType === "staff") {
            req.session.staffMfaVersion = Number(account.mfa_version || 1) + 1;
        }
        delete req.session.pendingTotpSetup;
        const recoveryCodes = await replaceRecoveryCodes(account);
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "mfa_setup",
            targetType: `${account.accountType}_user`,
            targetIdentifier: account.email,
            outcome: "success",
            metadata: { method: "authenticator" },
        });
        return res.json({ success: true, message: "Authenticator MFA is configured.", recoveryCodes });
    } catch (error) {
        console.error("Error verifying authenticator setup:", error.message);
        return res.status(500).json({ success: false, message: "Could not complete authenticator setup." });
    }
});

app.post("/portal/security/mfa/recovery-codes", requirePortal, async (req, res) => {
    try {
        const account = await getPortalMfaAccount(req);
        const password = String(req.body && req.body.password || "");
        if (!password || !await bcrypt.compare(password, account.password_hash)) {
            return res.status(401).json({ success: false, message: "Your current password is incorrect." });
        }
        const recoveryCodes = await replaceRecoveryCodes(account);
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "mfa_recovery_codes_regenerated",
            targetType: `${account.accountType}_user`,
            targetIdentifier: account.email,
            outcome: "success",
        });
        return res.json({ success: true, recoveryCodes });
    } catch (error) {
        console.error("Error regenerating recovery codes:", error.message);
        return res.status(500).json({ success: false, message: "Could not regenerate recovery codes." });
    }
});

app.post("/portal/security/password", requirePortal, async (req, res) => {
    try {
        const account = await getPortalMfaAccount(req);
        const currentPassword = String(req.body && req.body.currentPassword || "");
        const newPassword = String(req.body && req.body.newPassword || "");
        const confirmPassword = String(req.body && req.body.confirmPassword || "");
        const securityPolicy = await getSecurityPolicy();
        if (!await bcrypt.compare(currentPassword, account.password_hash)) {
            return res.status(401).json({ success: false, message: "Your current password is incorrect." });
        }
        if (newPassword !== confirmPassword || newPassword.length < securityPolicy.passwordMinimumLength) {
            return res.status(400).json({
                success: false,
                message: `New passwords must match and be at least ${securityPolicy.passwordMinimumLength} characters.`,
            });
        }
        await assertPasswordNotReused({
            accountType: account.accountType,
            accountId: account.id,
            password: newPassword,
            currentPasswordHash: account.password_hash,
        });
        const passwordHash = await hashPassword(newPassword);
        await recordPasswordHistory(account.accountType, account.id, account.password_hash);
        if (account.accountType === "admin") {
            await runDb(
                `UPDATE admin_users
                 SET password_hash = ?, auth_version = COALESCE(auth_version, 1) + 1, updated_at = CURRENT_TIMESTAMP
                 WHERE id = ?`,
                [passwordHash, account.id]
            );
            const updatedAdmin = await getDb("SELECT auth_version FROM admin_users WHERE id = ?", [account.id]);
            req.session.adminAuthVersion = Number(updatedAdmin.auth_version);
        } else {
            await runDb("UPDATE staff SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", [passwordHash, account.id]);
        }
        await recordPasswordHistory(account.accountType, account.id, passwordHash);
        await writeAuditEvent(req, {
            ...getActorContext(req),
            action: "password_changed",
            targetType: `${account.accountType}_user`,
            targetIdentifier: account.email,
            outcome: "success",
        });
        return res.json({ success: true, message: "Password changed successfully." });
    } catch (error) {
        const status = error.code === "PASSWORD_REUSED" ? 400 : 500;
        if (status === 500) console.error("Error changing portal password:", error.message);
        return res.status(status).json({ success: false, message: error.message || "Could not change the password." });
    }
});

app.get("/portal/profile", requireStaffOnly, async (req, res) => {
    try {
        const staffMember = mapStaffRow(await getDb("SELECT * FROM staff WHERE id = ?", [Number(req.session.staffId)]));
        const assignedClients = await getAssignedPatientsForStaff(staffMember.id);
        return res.render("portal-staff-profile", {
            title: "My Profile",
            isLoggedIn: true,
            isAdmin: false,
            currentStaffName: staffMember.name,
            currentStaffEmail: staffMember.email,
            staffMember,
            assignedClients,
            message: req.query.message || "",
            error: req.query.error || "",
        });
    } catch (error) {
        console.error("Error loading staff profile:", error.message);
        return res.status(500).render("error", { title: "Profile unavailable", message: "Your profile could not be loaded." });
    }
});

app.post("/portal/profile", requireStaffOnly, async (req, res) => {
    try {
        const staffId = Number(req.session.staffId);
        const phone = String(req.body.phone || "").trim();
        const address = String(req.body.address || "").trim();
        const emergencyContact = String(req.body.emergency_contact || "").trim();
        const availability = String(req.body.availability || "").trim();
        const profilePhoto = String(req.body.profile_photo || "").trim();
        const appLockEnabled = req.body.app_lock_enabled ? 1 : 0;
        const appLockMethod = String(req.body.app_lock_method || "").trim();
        const reminderLeadMinutes = normalizeReminderLeadMinutes(req.body.reminder_lead_minutes);
        const notifyShiftReminders = req.body.notify_shift_reminders ? 1 : 0;
        const notifyNewShift = req.body.notify_new_shift ? 1 : 0;
        const notifyOpenShift = req.body.notify_open_shift ? 1 : 0;
        const notifyAnnouncements = req.body.notify_announcements ? 1 : 0;
        const notifyTrainingReminders = req.body.notify_training_reminders ? 1 : 0;
        const notifyComplianceAlerts = req.body.notify_compliance_alerts ? 1 : 0;
        const notifyScheduleChanges = req.body.notify_schedule_changes ? 1 : 0;
        const existingStaff = await getDb("SELECT email, phone_normalized FROM staff WHERE id = ?", [staffId]);
        const identity = await enforceApplicationUniqueness({
            email: existingStaff.email,
            phone,
            excludeStaffId: staffId,
        });

        await runDb(
            `UPDATE staff
             SET phone = ?,
                phone_normalized = ?,
                phone_verified = CASE WHEN COALESCE(phone_normalized, '') = COALESCE(?, '') THEN phone_verified ELSE 0 END,
                address = ?,
                emergency_contact = ?,
                availability = ?,
                profile_photo = ?,
                app_lock_enabled = ?,
                app_lock_method = ?,
                reminder_lead_minutes = ?,
                notify_shift_reminders = ?,
                notify_new_shift = ?,
                notify_open_shift = ?,
                notify_announcements = ?,
                notify_training_reminders = ?,
                notify_compliance_alerts = ?,
                notify_schedule_changes = ?
             WHERE id = ?`,
            [
               phone,
               identity.normalizedPhone || null,
               identity.normalizedPhone || null,
               address,
               emergencyContact,
               availability,
               profilePhoto,
               appLockEnabled,
               appLockMethod || null,
               reminderLeadMinutes,
               notifyShiftReminders,
               notifyNewShift,
               notifyOpenShift,
               notifyAnnouncements,
               notifyTrainingReminders,
               notifyComplianceAlerts,
               notifyScheduleChanges,
               staffId,
            ]
        );

        return res.redirect("/portal/profile?message=Profile updated successfully.");
    } catch (error) {
        await recordDuplicateIdentityAttempt(req, error, "staff");
        console.error("Error updating staff profile:", error.message);
        const message = ["APPLICATION_DUPLICATE_EMAIL", "APPLICATION_DUPLICATE_PHONE"].includes(error.code)
            ? error.message
            : "Profile could not be updated.";
        return res.redirect(`/portal/profile?error=${encodeURIComponent(message)}`);
    }
});

app.post("/portal/profile/password", requireStaffOnly, async (req, res) => {
    try {
        const staffId = Number(req.session.staffId);
        const currentPassword = String(req.body.current_password || "");
        const newPassword = String(req.body.new_password || "");
        const confirmPassword = String(req.body.confirm_password || "");
        const securityPolicy = await getSecurityPolicy();
        if (newPassword.length < securityPolicy.passwordMinimumLength || newPassword !== confirmPassword) {
            return res.redirect(`/portal/profile?error=${encodeURIComponent(`New passwords must match and be at least ${securityPolicy.passwordMinimumLength} characters.`)}`);
        }
        const staffMember = await getDb("SELECT * FROM staff WHERE id = ?", [staffId]);
        if (!staffMember || !(await bcrypt.compare(currentPassword, staffMember.password_hash || ""))) {
            return res.redirect("/portal/profile?error=Your current password is incorrect.");
        }
        await assertPasswordNotReused({
            accountType: "staff",
            accountId: staffId,
            password: newPassword,
            currentPasswordHash: staffMember.password_hash,
        });
        const passwordHash = await hashPassword(newPassword);
        await recordPasswordHistory("staff", staffId, staffMember.password_hash);
        await runDb("UPDATE staff SET password_hash = ? WHERE id = ?", [passwordHash, staffId]);
        await recordPasswordHistory("staff", staffId, passwordHash);
        return res.redirect("/portal/profile?message=Password changed successfully.");
    } catch (error) {
        if (error.code === "PASSWORD_REUSED") {
            return res.redirect(`/portal/profile?error=${encodeURIComponent(error.message)}`);
        }
        console.error("Error changing password:", error.message);
        return res.redirect("/portal/profile?error=Your password could not be changed.");
    }
});

app.get("/portal/documents", requireStaffOnly, async (req, res) => {
    try {
        const staffMember = mapStaffRow(await getDb("SELECT * FROM staff WHERE id = ?", [Number(req.session.staffId)]));
        const documents = await allDb(
            `SELECT * FROM staff_documents
             WHERE staff_id IS NULL OR staff_id = ?
             ORDER BY category, title`,
            [staffMember.id]
        );
        return res.render("portal-staff-documents", {
            title: "Documents",
            isLoggedIn: true,
            isAdmin: false,
            currentStaffName: staffMember.name,
            currentStaffEmail: staffMember.email,
            documents,
        });
    } catch (error) {
        console.error("Error loading staff documents:", error.message);
        return res.status(500).render("error", { title: "Documents unavailable", message: "Your documents could not be loaded." });
    }
});

app.get("/portal/documents/:id/download", requireStaffOnly, async (req, res) => {
    try {
        const document = await getDb("SELECT * FROM staff_documents WHERE id = ? AND (staff_id IS NULL OR staff_id = ?)", [Number(req.params.id), Number(req.session.staffId)]);
        if (!document) {
            return res.status(404).render("error", { title: "Document not found", message: "The requested document could not be found." });
        }
        res.setHeader("Content-Type", "text/plain; charset=utf-8");
        res.setHeader("Content-Disposition", `attachment; filename="${document.file_name || "document.txt"}"`);
        return res.send(document.download_text || document.title);
    } catch (error) {
        return res.status(500).render("error", { title: "Document unavailable", message: "The document could not be downloaded." });
    }
});

app.get("/portal/training", requireStaffOnly, async (req, res) => {
    try {
        const staffMember = mapStaffRow(await getDb("SELECT * FROM staff WHERE id = ?", [Number(req.session.staffId)]));
        const training = await allDb(
            `SELECT * FROM staff_training WHERE staff_id = ? ORDER BY COALESCE(expires_at, completed_at, created_at) ASC`,
            [staffMember.id]
        );
        return res.render("portal-staff-training", {
            title: "Training",
            isLoggedIn: true,
            isAdmin: false,
            currentStaffName: staffMember.name,
            currentStaffEmail: staffMember.email,
            training,
        });
    } catch (error) {
        console.error("Error loading staff training:", error.message);
        return res.status(500).render("error", { title: "Training unavailable", message: "Training records could not be loaded." });
    }
});

app.get("/portal/messages", requireStaffOnly, async (req, res) => {
    try {
        const staffMember = mapStaffRow(await getDb("SELECT * FROM staff WHERE id = ?", [Number(req.session.staffId)]));
        await runDb(
            "UPDATE staff_messages SET is_read = 1 WHERE staff_id = ? AND sender_type = 'admin' AND archived_at IS NULL",
            [staffMember.id]
        );
        const messages = await allDb(
            `SELECT * FROM staff_messages
             WHERE staff_id = ? AND archived_at IS NULL
             ORDER BY created_at DESC`,
            [staffMember.id]
        );
        return res.render("portal-staff-messages", {
            title: "Messages",
            isLoggedIn: true,
            isAdmin: false,
            currentStaffName: staffMember.name,
            currentStaffEmail: staffMember.email,
            messages,
        });
    } catch (error) {
        console.error("Error loading staff messages:", error.message);
        return res.status(500).render("error", { title: "Messages unavailable", message: "Messages could not be loaded." });
    }
});

app.post("/portal/messages", requireStaffOnly, async (req, res) => {
    try {
        await runDb(
            `INSERT INTO staff_messages (staff_id, sender_type, sender_name, subject, body, is_read)
             VALUES (?, 'staff', ?, ?, ?, 1)`,
            [Number(req.session.staffId), req.session.staffName || "Staff member", String(req.body.subject || "Reply"), String(req.body.body || "").trim()]
        );
        await queueStaffNotification(Number(req.session.staffId), "Message sent", "Your reply was added to the conversation thread.", "message", "/portal/messages");
        return res.redirect("/portal/messages");
    } catch (error) {
        console.error("Error sending staff message:", error.message);
        return res.redirect("/portal/messages");
    }
});

app.use((req, res) => {
    res.status(404).json({ status: "error", message: "Route not found" });
});

app.use((error, req, res, next) => {
    console.error("Unhandled application error:", error && (error.stack || error.message || error));
    res.status(500).json({ status: "error", message: "Internal server error" });
});

const startServer = (port = preferredPort) => {
    const server = app.listen(port, "0.0.0.0", () => {
        const actualPort = server.address() ? server.address().port : port;
        console.log(`Everkind Care System ready on http://localhost:${actualPort}`);
        console.log(`Database status: ${databaseLabel}`);
    });

    server.on("error", (error) => {
        if (error.code === "EADDRINUSE") {
            console.error(`Port ${port} is already in use. Stop the existing Everkind server before starting a new one.`);
            process.exit(1);
        }

        console.error("Unable to start server:", error.message);
        process.exit(1);
    });
};

initializeDatabase()
    .then(() => {
        ensureProductionSecurity();
    })
    .then(() => startServer())
    .then(() => {
        startPayslipEmailScheduler();
        if (!fs.existsSync(payslipsDir)) fs.mkdirSync(payslipsDir, { recursive: true });
    })
    .catch((error) => {
        console.error("Database initialization failed:", error.message);
        process.exit(1);
    });
