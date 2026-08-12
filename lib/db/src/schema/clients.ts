import {
  pgTable,
  text,
  serial,
  timestamp,
  integer,
  doublePrecision,
  pgEnum,
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const clientStatusEnum = pgEnum("client_status", [
  "active",
  "inactive",
  "hospital",
  "discharged",
]);

export const clientsTable = pgTable("clients", {
  id: serial("id").primaryKey(),
  firstName: text("first_name").notNull(),
  lastName: text("last_name").notNull(),
  email: text("email"),
  phone: text("phone").notNull(),
  address: text("address").notNull(),
  eircode: text("eircode"),
  photoUrl: text("photo_url"),
  dateOfBirth: text("date_of_birth"),
  careNeeds: text("care_needs"),
  // Geofence anchor for GPS clock in/out. Null until a coordinator sets them
  // (manually or via geocode); a null anchor means clock-ins are allowed but
  // recorded with an unknown geofence result and flagged for review.
  latitude: doublePrecision("latitude"),
  longitude: doublePrecision("longitude"),
  geofenceRadiusM: integer("geofence_radius_m").notNull().default(100),
  emergencyContactName: text("emergency_contact_name"),
  emergencyContactRelationship: text("emergency_contact_relationship"),
  emergencyContactPhone: text("emergency_contact_phone"),
  assignedStaffId: text("assigned_staff_id"),
  status: clientStatusEnum("status").notNull().default("active"),
  notes: text("notes"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow().$onUpdate(() => new Date()),
});

export const insertClientSchema = createInsertSchema(clientsTable).omit({ id: true, createdAt: true, updatedAt: true });
export type InsertClient = z.infer<typeof insertClientSchema>;
export type Client = typeof clientsTable.$inferSelect;
