/**
 * ClawGuard — Common Type Definitions
 */

import { homedir } from "node:os";

// ── Rule Types ───────────────────────────────────────────────

export type RuleAction = "deny" | "allow" | "approve";

export interface CommandRule {
  pattern: string;   // regex pattern string
  action: RuleAction;
  reason: string;
}

export interface RuleResult {
  action: RuleAction;
  reason: string;
  rule?: string;
}

// ── Extraction ───────────────────────────────────────────────

export interface ExtractionResult {
  command: string;
  isScript: boolean;
}

// ── Bypass Detection ─────────────────────────────────────────

export interface BypassCheck {
  detected: boolean;
  severity: "high" | "medium" | "low";
  reason: string;
}

// ── Audit ────────────────────────────────────────────────────

export interface AuditEntry {
  timestamp: string;
  toolName: string;
  params: string;
  result: string;
  durationMs: number;
  toolCallId?: string | null;
  error: string | null;
  decision?: string;
  rule?: string;
  session?: string;
  command?: string;
}

// ── Plugin Config ────────────────────────────────────────────

export type ClawGuardMode = "permissive" | "supervised" | "enforce";

export interface ClawGuardConfig {
  mode: ClawGuardMode;
  policyFile: string;
  auditDir: string;
  auditRetentionDays: number;
  allowCommands: string[];
  denyCommands: string[];
  allowDomains: string[];
}

export const DEFAULT_CONFIG: ClawGuardConfig = {
  mode: "supervised",
  policyFile: homedir() + "/.clawguard/policy.ini",
  auditDir: homedir() + "/.clawguard/audit",
  auditRetentionDays: 90,
  allowCommands: [],
  denyCommands: [],
  allowDomains: [],
};

// ── Before-Tool-Call Result ──────────────────────────────────

export type RequireApprovalOptions = {
  title: string;
  description: string;
  severity: "info" | "warning" | "critical";
  timeoutMs?: number;
  timeoutBehavior?: "deny" | "allow";
  sessionKey?: string | null;
  agentId?: string | null;
  onResolution?: (decision: string) => Promise<void> | void;
};

export type BeforeToolCallResult =
  | undefined
  | { block: true; blockReason: string }
  | { requireApproval: RequireApprovalOptions };

// ── Policy Engine Types ──────────────────────────────────────

export interface PolicyRule {
  type: "allow_cmd" | "allow_domain" | "allow_write";
  value: string;
}

export interface ParsedPolicy {
  mode: ClawGuardMode;
  rules: PolicyRule[];
}

// ── Network Check ────────────────────────────────────────────

export interface NetworkCheckResult extends RuleResult {
  domain: string;
}

// ── File Check ──────────────────────────────────────────────

export interface FileCheckResult extends RuleResult {
  path: string;
  normalizedPath: string;
}

// ── Session Context ─────────────────────────────────────────

export interface ClawGuardSession {
  commandCount: number;
  denyCount: number;
  approveCount: number;
  bypassDetections: number;
}
