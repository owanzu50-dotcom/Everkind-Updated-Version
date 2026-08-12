import { jsonb, pgTable, text, timestamp } from "drizzle-orm/pg-core";

export type SystemSettingsPayload = Record<string, string | boolean>;

export const systemSettingsTable = pgTable("system_settings", {
  id: text("id").primaryKey(),
  payload: jsonb("payload").$type<SystemSettingsPayload>().notNull(),
  updatedBy: text("updated_by").notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});
