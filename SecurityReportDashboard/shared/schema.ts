import { pgTable, text, serial, integer, timestamp, jsonb, real } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Updated schema to match your JSON format
export const devices = pgTable("devices", {
  id: serial("id").primaryKey(),
  agentId: text("agent_id").notNull(),
  deviceName: text("device_name").notNull(),
  ip: text("ip").notNull(),
  os: text("os").notNull(),
  lastSeen: timestamp("last_seen").notNull(),
  status: text("status").notNull().default("active"),
});

export const securityFindings = pgTable("security_findings", {
  id: serial("id").primaryKey(),
  deviceId: integer("device_id").references(() => devices.id).notNull(),
  timestamp: timestamp("timestamp").notNull(),
  software: text("software").notNull(),
  cveId: text("cve_id"),
  cvssScore: real("cvss_score"),
  description: text("description").notNull(),
  riskLevel: text("risk_level").notNull(), // Critical, High, Medium, Low
  url: text("url"),
  remediationSummary: text("remediation_summary"),
  remediationReferences: jsonb("remediation_references"), // array of URLs
});

export const securityReports = pgTable("security_reports", {
  id: serial("id").primaryKey(),
  deviceId: integer("device_id").references(() => devices.id).notNull(),
  generatedAt: timestamp("generated_at").notNull(),
  softwareAnalyzed: integer("software_analyzed").notNull(),
  alertsFound: integer("alerts_found").notNull(),
  syscheckEntries: integer("syscheck_entries").notNull(),
  totalCves: integer("total_cves").notNull(),
  severityBreakdown: jsonb("severity_breakdown").notNull(), // {Critical: 1, High: 4, Medium: 2, Low: 0}
});

export const insertDeviceSchema = createInsertSchema(devices).omit({
  id: true,
});

export const insertSecurityFindingSchema = createInsertSchema(securityFindings).omit({
  id: true,
});

export const insertSecurityReportSchema = createInsertSchema(securityReports).omit({
  id: true,
});

export type Device = typeof devices.$inferSelect;
export type InsertDevice = z.infer<typeof insertDeviceSchema>;
export type SecurityFinding = typeof securityFindings.$inferSelect;
export type InsertSecurityFinding = z.infer<typeof insertSecurityFindingSchema>;
export type SecurityReport = typeof securityReports.$inferSelect;
export type InsertSecurityReport = z.infer<typeof insertSecurityReportSchema>;

// Updated severity levels to match your format
export const severityLevels = ["Critical", "High", "Medium", "Low"] as const;
export type SeverityLevel = typeof severityLevels[number];

// Type definitions for your JSON structure
export interface CVEReportData {
  device_info: {
    agent_id: string;
    device_name: string;
    ip: string;
    os: string;
    last_seen: Date;
  };
  os_details: {
    build: string;
    display_version: string;
    major: string;
    minor: string;
    name: string;
    version: string;
  };
  summary: {
    software_analyzed: number;
    alerts_found: number;
    syscheck_entries: number;
    total_cves: number;
    severity_breakdown: {
      Critical: number;
      High: number;
      Medium: number;
      Low: number;
    };
  };
  findings: Array<{
    timestamp: string;
    software: string;
    cve_id: string;
    cvss_score: number;
    description: string;
    risk_level: SeverityLevel;
    url: string;
    remediation: {
      summary: string;
      references: string[];
    };
  }>;
}
