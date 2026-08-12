import { pgTable, text, serial, timestamp, boolean, pgEnum, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const staffRoleEnum = pgEnum("staff_role", [
  "care_assistant",
  "senior_carer",
  "care_coordinator",
  "nurse",
  "manager",
]);

export const staffStatusEnum = pgEnum("staff_status", [
  "active",
  "inactive",
  "on_leave",
]);

export const staffTable = pgTable("staff", {
  id: serial("id").primaryKey(),

  // Core identity
  firstName: text("first_name").notNull(),
  lastName: text("last_name").notNull(),
  email: text("email").notNull().default(""),
  phone: text("phone").notNull().default(""),
  role: staffRoleEnum("role").notNull().default("care_assistant"),
  employmentStatus: staffStatusEnum("employment_status").notNull().default("active"),
  hireDate: text("hire_date"),
  address: text("address"),
  dateOfBirth: text("date_of_birth"),
  nationality: text("nationality"),
  languages: text("languages"),

  // Contact
  emergencyContactName: text("emergency_contact_name"),
  emergencyContactPhone: text("emergency_contact_phone"),

  // Transport & availability
  ownTransport: boolean("own_transport").notNull().default(false),
  drivingLicence: boolean("driving_licence").notNull().default(false),
  availabilityDays: boolean("availability_days").notNull().default(false),
  availabilityNights: boolean("availability_nights").notNull().default(false),
  availabilityWeekends: boolean("availability_weekends").notNull().default(false),
  preferredLocations: text("preferred_locations"),

  // Compliance — all roles
  gardaVetted: boolean("garda_vetted").notNull().default(false),
  gardaVettingExpiry: text("garda_vetting_expiry"),
  manualHandlingCert: boolean("manual_handling_cert").notNull().default(false),
  manualHandlingExpiry: text("manual_handling_expiry"),
  infectionControlCert: boolean("infection_control_cert").notNull().default(false),
  infectionControlExpiry: text("infection_control_expiry"),
  blsCert: boolean("bls_cert").notNull().default(false),
  blsExpiry: text("bls_expiry"),
  patientMovingCert: boolean("patient_moving_cert").notNull().default(false),
  patientMovingExpiry: text("patient_moving_expiry"),
  trainingCompleted: boolean("training_completed").notNull().default(false),

  // Nurse-specific
  nmbiNumber: text("nmbi_number"),
  nmbiExpiryDate: text("nmbi_expiry_date"),
  nursingSpecialization: text("nursing_specialization"),
  nursingDivision: text("nursing_division"),

  // Carer-specific
  qqiLevel: text("qqi_level"),
  qqiQualification: text("qqi_qualification"),
  dementiaCare: boolean("dementia_care").notNull().default(false),
  palliativeCare: boolean("palliative_care").notNull().default(false),
  mentalHealthExperience: boolean("mental_health_experience").notNull().default(false),
  intellectualDisabilityExperience: boolean("intellectual_disability_experience").notNull().default(false),

  // HSE training records — array of { name, category, completed, completionDate, expiryDate }
  hcaTrainings: jsonb("hca_trainings").$type<Array<{
    name: string;
    category: string;
    completed: boolean;
    completionDate?: string;
    expiryDate?: string;
  }>>(),

  // General
  additionalQualifications: text("additional_qualifications"),
  notes: text("notes"),

  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const insertStaffSchema = createInsertSchema(staffTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertStaff = z.infer<typeof insertStaffSchema>;
export type Staff = typeof staffTable.$inferSelect;
