import { pgTable, text, serial, timestamp, boolean, pgEnum } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const applicationStatusEnum = pgEnum("application_status", [
  "new",
  "reviewing",
  "shortlisted",
  "interviewed",
  "hired",
  "rejected",
]);

export const applicationsTable = pgTable("applications", {
  id: serial("id").primaryKey(),
  firstName: text("first_name").notNull(),
  lastName: text("last_name").notNull(),
  email: text("email").notNull(),
  phone: text("phone").notNull(),
  location: text("location"),
  position: text("position").notNull(),
  experience: text("experience"),
  qualifications: text("qualifications"),
  ownTransport: boolean("own_transport").notNull().default(false),
  drivingLicence: boolean("driving_licence").notNull().default(false),
  gardaVetted: boolean("garda_vetted").notNull().default(false),
  rightToWork: boolean("right_to_work").notNull().default(false),
  availability: text("availability"),
  coverMessage: text("cover_message"),
  status: applicationStatusEnum("status").notNull().default("new"),
  notes: text("notes"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const insertApplicationSchema = createInsertSchema(applicationsTable, {
  firstName: (s) => s.trim().min(1, "First name is required").max(100),
  lastName: (s) => s.trim().min(1, "Last name is required").max(100),
  email: () => z.email("Please enter a valid email address").max(255),
  phone: (s) => s.trim().min(1, "Phone number is required").max(50),
  position: (s) => s.trim().min(1, "Position is required").max(120),
  location: (s) => s.max(200),
  experience: (s) => s.max(5000),
  qualifications: (s) => s.max(5000),
  availability: (s) => s.max(500),
  coverMessage: (s) => s.max(5000),
  notes: (s) => s.max(5000),
}).omit({ id: true, createdAt: true, updatedAt: true });

// Public-facing schema for candidate submissions: applicants must not be able to
// set their own pipeline status or internal recruiter notes.
export const publicApplicationSchema = insertApplicationSchema.omit({ status: true, notes: true });

export type InsertApplication = z.infer<typeof insertApplicationSchema>;
export type PublicApplication = z.infer<typeof publicApplicationSchema>;
export type Application = typeof applicationsTable.$inferSelect;
