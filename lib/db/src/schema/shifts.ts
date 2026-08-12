import { pgTable, text, serial, timestamp, integer, boolean, pgEnum, jsonb } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const shiftStatusEnum = pgEnum("shift_status", [
  "scheduled",
  "completed",
  "cancelled",
  "no_show",
]);

// How the assigned carer responded to the shift from the staff mobile app.
// Distinct from the operational `status` (owned by coordinators).
export const staffResponseEnum = pgEnum("staff_response", [
  "pending",
  "accepted",
  "declined",
  "cancelled",
]);

export const shiftsTable = pgTable("shifts", {
  id: serial("id").primaryKey(),
  // Nullable: an "open" shift sits in the pickup pool with no carer assigned
  // until an agency staff member claims it from the mobile app.
  staffId: integer("staff_id"),
  clientId: integer("client_id").notNull(),
  date: text("date").notNull(),
  startTime: text("start_time").notNull(),
  endTime: text("end_time").notNull(),
  serviceType: text("service_type").notNull(),
  status: shiftStatusEnum("status").notNull().default("scheduled"),
  // True while the shift is unassigned and offered to staff for pickup.
  // Set false the moment a carer claims it (or an admin assigns one directly).
  isOpen: boolean("is_open").notNull().default(false),
  notes: text("notes"),
  careInstructions: text("care_instructions"),
  visitNotes: text("visit_notes"),
  visitNotesUpdatedAt: timestamp("visit_notes_updated_at", { withTimezone: true }),
  visitNotesUpdatedBy: text("visit_notes_updated_by"),
  attachments: jsonb("attachments").$type<
    Array<{
      id: string;
      name: string;
      url: string;
      category?: "care_plan" | "risk_assessment" | "medication_chart" | "visit_document";
    }>
  >(),

  // Staff (mobile app) response tracking.
  staffResponse: staffResponseEnum("staff_response").notNull().default("pending"),
  staffResponseReason: text("staff_response_reason"),
  staffRespondedAt: timestamp("staff_responded_at", { withTimezone: true }),
  swapRequested: boolean("swap_requested").notNull().default(false),
  swapReason: text("swap_reason"),

  // Live shift tracking: when the carer clocked in on arrival and out when the
  // visit finished. Both null = not started; in set, out null = on duty; both
  // set = finished. Clocking out also flips `status` to "completed".
  clockInAt: timestamp("clock_in_at", { withTimezone: true }),
  clockOutAt: timestamp("clock_out_at", { withTimezone: true }),

  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const insertShiftSchema = createInsertSchema(shiftsTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertShift = z.infer<typeof insertShiftSchema>;
export type Shift = typeof shiftsTable.$inferSelect;
