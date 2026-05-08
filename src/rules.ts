/**
 * ClawGuard — Command Rule Engine
 *
 * Three-tier rules: DENY > ALLOW > APPROVE (priority descending).
 * Loads rules from JSON files in the rules/ directory.
 */
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { CommandRule, RuleResult } from "./types.js";

// Resolve rules directory relative to this source file
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const RULES_DIR = join(__dirname, "..", "rules");

// ── Load Rules ───────────────────────────────────────────────

function loadRules(filename: string): CommandRule[] {
  const path = join(RULES_DIR, filename);
  if (!existsSync(path)) {
    console.warn(`[ClawGuard] rules file not found: ${filename}`);
    return [];
  }
  try {
    const raw = readFileSync(path, "utf-8");
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      console.warn(`[ClawGuard] ${filename} is not an array, ignoring`);
      return [];
    }
    return parsed as CommandRule[];
  } catch (err) {
    console.warn(`[ClawGuard] failed to load ${filename}:`, err);
    return [];
  }
}

const DENY_RULES: CommandRule[] = loadRules("denylist.json");
const ALLOW_RULES: CommandRule[] = loadRules("allowlist.json");
const APPROVE_RULES: CommandRule[] = loadRules("approvelist.json");

// ── Matching Engine ─────────────────────────────────────────

/**
 * Match a command against a list of rules.
 * Returns the first matching rule, or null.
 */
function matchRule(command: string, rules: CommandRule[]): CommandRule | null {
  for (const rule of rules) {
    try {
      const regex = new RegExp(rule.pattern, "i");
      if (regex.test(command)) {
        return rule;
      }
    } catch {
      // Skip invalid regex patterns
      console.warn(`[ClawGuard] invalid regex pattern: ${rule.pattern}`);
    }
  }
  return null;
}

/**
 * Check a command against the three-tier rule engine.
 * Priority: DENY > ALLOW > APPROVE
 *
 * @param command - The command string to check
 * @returns RuleResult with action, reason, and optional matching rule
 */
export function checkCommand(command: string): RuleResult {
  const cmd = command.trim();

  if (!cmd) {
    return { action: "allow", reason: "空命令" };
  }

  // Tier 1: DENY list (highest priority)
  const denyMatch = matchRule(cmd, DENY_RULES);
  if (denyMatch) {
    return {
      action: "deny",
      reason: denyMatch.reason,
      rule: denyMatch.pattern,
    };
  }

  // Tier 2: ALLOW list (safe commands, fast-path)
  const allowMatch = matchRule(cmd, ALLOW_RULES);
  if (allowMatch) {
    return {
      action: "allow",
      reason: allowMatch.reason,
      rule: allowMatch.pattern,
    };
  }

  // Tier 3: APPROVE list (requires user confirmation)
  const approveMatch = matchRule(cmd, APPROVE_RULES);
  if (approveMatch) {
    return {
      action: "approve",
      reason: approveMatch.reason,
      rule: approveMatch.pattern,
    };
  }

  // Default: no rule matched — allow by default in permissive mode,
  // but the caller (index.ts) decides based on mode
  return {
    action: "allow",
    reason: "未匹配任何规则（默认放行）",
  };
}

/**
 * Reload rules from disk (for hot-reload scenarios).
 */
export function reloadRules(): void {
  DENY_RULES.length = 0;
  ALLOW_RULES.length = 0;
  APPROVE_RULES.length = 0;

  DENY_RULES.push(...loadRules("denylist.json"));
  ALLOW_RULES.push(...loadRules("allowlist.json"));
  APPROVE_RULES.push(...loadRules("approvelist.json"));
}

/**
 * Get current rule counts (for status/debugging).
 */
export function getRuleStats(): { deny: number; allow: number; approve: number } {
  return {
    deny: DENY_RULES.length,
    allow: ALLOW_RULES.length,
    approve: APPROVE_RULES.length,
  };
}
