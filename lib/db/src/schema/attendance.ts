import { sql } from "drizzle-orm";
import {
  pgTable,
  text,
  serial,
  timestamp,
  integer,
  boolean,
  pgEnum,
  doublePrecision,
  jsonb,
  uniqueIndex,
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const clockEventTypeEnum = pgEnum("clock_event_type", [
  "clock_in",
  "clock_out",
]);

export const networkStatusEnum = pgEnum("network_status", [
  "online",
  "offline",
]);

// How much we trust a clock event. Auto-verified events pass every server check;
// flagged events are recorded but need a manager to review (implausible sync
// lag, missing geofence config, mock GPS, etc.); manager-resolved marks a
// flagged event a human has since accepted or corrected.
export const clockReviewStatusEnum = pgEnum("clock_review_status", [
  "auto_verified",
  "flagged",
  "manager_resolved",
]);

// One row per clock in / clock out. Kept separate from the shift so every
// attempt carries its own verifiable GPS + device fingerprint and audit trail;
// the shift only stores the denormalised clockInAt/clockOutAt for convenience.
export const clockEventsTable = pgTable(
  "clock_events",
  {
    id: serial("id").primaryKey(),
    shiftId: integer("shift_id").notNull(),
    staffId: integer("staff_id").notNull(),
    clientId: integer("client_id").notNull(),
    eventType: clockEventTypeEnum("event_type").notNull(),

    // Authoritative time the server accepted the event. Never derived from the
    // device; this is what gating and payroll trust when the event is online.
    serverAt: timestamp("server_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    // Device clock at the moment the carer tapped the button. Used only to
    // validate the shift time window for events captured while offline, and to
    // detect implausible clock skew. Never trusted for online events.
    capturedAt: timestamp("captured_at", { withTimezone: true }).notNull(),

    // GPS + device metadata captured at the action.
    latitude: doublePrecision("latitude"),
    longitude: doublePrecision("longitude"),
    accuracyM: doublePrecision("accuracy_m"),
    distanceM: doublePrecision("distance_m"),
    // Null when the client has no configured coordinates (geofence unknown).
    insideGeofence: boolean("inside_geofence"),
    deviceId: text("device_id"),
    // 0..1 fraction, or null on platforms that cannot report it (e.g. web).
    batteryLevel: doublePrecision("battery_level"),
    networkStatus: networkStatusEnum("network_status")
      .notNull()
      .default("online"),
    // Android-only best-effort mock-GPS flag; false elsewhere.
    isMockLocation: boolean("is_mock_location").notNull().default(false),

    // Client-generated idempotency key so a retried or offline-queued event can
    // never double-insert.
    idempotencyKey: text("idempotency_key").notNull(),

    reviewStatus: clockReviewStatusEnum("review_status")
      .notNull()
      .default("auto_verified"),
    reviewReason: text("review_reason"),

    // Set when a manager clears the shift's times (clear_times override). The row
    // is retained for the audit trail but no longer occupies the live
    // (shift, event_type) slot, so the carer can clock again.
    supersededAt: timestamp("superseded_at", { withTimezone: true }),

    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => [
    uniqueIndex("clock_events_idempotency_key_unique").on(t.idempotencyKey),
    // A shift can be clocked in once and out once; the unique pair makes retries
    // and races idempotent at the database level. Partial so superseded rows
    // (cleared by a manager) free the slot for a fresh clock event.
    uniqueIndex("clock_events_shift_event_unique")
      .on(t.shiftId, t.eventType)
      .where(sql`${t.supersededAt} IS NULL`),
  ],
);

// Append-only trail of manager overrides to attendance (clearing/setting a
// clock time, resolving a flag, marking no-show). Every override is recorded so
// the attendance record stays tamper-evident.
export const attendanceAuditTable = pgTable("attendance_audit", {
  id: serial("id").primaryKey(),
  shiftId: integer("shift_id").notNull(),
  staffId: integer("staff_id"),
  action: text("action").notNull(),
  performedByEmail: text("performed_by_email").notNull(),
  previousValue: jsonb("previous_value"),
  newValue: jsonb("new_value"),
  reason: text("reason"),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const insertClockEventSchema = createInsertSchema(clockEventsTable).omit({
  id: true,
  serverAt: true,
  createdAt: true,
});
export type InsertClockEvent = z.infer<typeof insertClockEventSchema>;
export type ClockEvent = typeof clockEventsTable.$inferSelect;

export const insertAttendanceAuditSchema = createInsertSchema(
  attendanceAuditTable,
).omit({ id: true, createdAt: true });
export type InsertAttendanceAudit = z.infer<typeof insertAttendanceAuditSchema>;
export type AttendanceAudit = typeof attendanceAuditTable.$inferSelect;
