/**
 * ClawGuard — Bypass Detection
 *
 * Detects encoding/obfuscation techniques that try to evade pattern-based rules.
 * Patterns are loaded from rules/bypass-patterns.json to keep detection logic
 * separate from code that could trigger security scanner false positives.
 */
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { BypassCheck } from "./types.js";

// ── Pattern Types ────────────────────────────────────────────

interface BypassPattern {
  id: string;
  pattern: string;
  flags?: string;
  severity: "high" | "medium" | "low";
  reason: string;
  chainPattern?: string;
  chainFlags?: string;
  excludeMatch?: string;
}

// ── Load Patterns ────────────────────────────────────────────

function loadBypassPatterns(): BypassPattern[] {
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const path = join(__dirname, "..", "rules", "bypass-patterns.json");

  if (!existsSync(path)) {
    console.warn("[ClawGuard] bypass-patterns.json not found, using fallback");
    return [];
  }

  try {
    const raw = readFileSync(path, "utf-8");
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      console.warn("[ClawGuard] bypass-patterns.json is not an array, ignoring");
      return [];
    }
    return parsed as BypassPattern[];
  } catch (err) {
    console.warn("[ClawGuard] failed to load bypass-patterns.json:", err);
    return [];
  }
}

const PATTERNS: BypassPattern[] = loadBypassPatterns();

// ── Detection Engine ─────────────────────────────────────────

export function checkBypass(command: string): BypassCheck | null {
  const cmd = command.trim();

  for (const rule of PATTERNS) {
    try {
      // Base64 decode chain detection (two-pattern match)
      if (rule.chainPattern) {
        const re1 = new RegExp(rule.pattern, rule.flags);
        const re2 = new RegExp(rule.chainPattern, rule.chainFlags);
        if (re1.test(cmd) && re2.test(cmd)) {
          return {
            detected: true,
            severity: rule.severity as BypassCheck["severity"],
            reason: rule.reason,
          };
        }
        continue;
      }

      // Standard single-pattern detection
      const re = new RegExp(rule.pattern, rule.flags);
      if (re.test(cmd)) {
        // Exclusion check (e.g., skip "export FOO=bar" for variable indirection)
        if (rule.excludeMatch) {
          const excludeRe = new RegExp(rule.excludeMatch, "i");
          if (excludeRe.test(cmd)) {
            continue;
          }
        }
        return {
          detected: true,
          severity: rule.severity as BypassCheck["severity"],
          reason: rule.reason,
        };
      }
    } catch {
      console.warn(`[ClawGuard] invalid bypass pattern: ${rule.id}`);
    }
  }

  return null;
}
