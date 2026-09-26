import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

export type AuditKind = "request" | "success" | "warning" | "error";

export type AuditEntry = {
  id: string;
  at: string;
  kind: AuditKind;
  message: string;
};

const MAX_AUDIT_ENTRIES = 500;
const auditPath = process.env.AUDIT_LOG_PATH
  ? resolve(process.env.AUDIT_LOG_PATH)
  : resolve(__dirname, "../data/activity-audit.json");

function readStoredEntries(): AuditEntry[] {
  if (!existsSync(auditPath)) return [];
  try {
    const stored = JSON.parse(readFileSync(auditPath, "utf8")) as AuditEntry[];
    return Array.isArray(stored) ? stored.slice(0, MAX_AUDIT_ENTRIES) : [];
  } catch (error) {
    console.error("Unable to read activity audit log:", error);
    return [];
  }
}

let entries = readStoredEntries();

function persistEntries(): void {
  const temporaryPath = `${auditPath}.${process.pid}.tmp`;
  try {
    mkdirSync(dirname(auditPath), { recursive: true });
    writeFileSync(temporaryPath, JSON.stringify(entries), "utf8");
    renameSync(temporaryPath, auditPath);
  } catch (error) {
    console.error("Unable to persist activity audit log:", error);
  }
}

export function recordAudit(kind: AuditKind, message: string): void {
  entries.unshift({
    id: randomUUID(),
    at: new Date().toISOString(),
    kind,
    message: message.slice(0, 300)
  });
  if (entries.length > MAX_AUDIT_ENTRIES) entries = entries.slice(0, MAX_AUDIT_ENTRIES);
  persistEntries();
}

export function getRecentAudit(limit = 40): AuditEntry[] {
  return entries.slice(0, Math.max(1, Math.min(limit, 100)));
}