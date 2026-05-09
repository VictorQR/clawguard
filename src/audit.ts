/**
 * ClawGuard — Audit Logging
 *
 * Sanitized JSONL audit trail with automatic rotation (90-day retention).
 * All sensitive values (tokens, keys, passwords) are redacted before writing.
 */
import { appendFileSync, mkdirSync, existsSync, readdirSync, unlinkSync, statSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { AuditEntry } from "./types.js";

// ── Configuration ────────────────────────────────────────────

const HOME = homedir();
const DEFAULT_AUDIT_DIR = join(HOME, ".clawguard", "audit");
const DEFAULT_RETENTION_DAYS = 90;

// ── Sensitive Data Patterns ──────────────────────────────────

interface SensitivePattern {
  regex: RegExp;
  replace: string;
}

const SENSITIVE_PATTERNS: SensitivePattern[] = [
  // GitHub tokens: ghp_..., gho_..., ghu_..., ghr_..., ghs_...
  {
    regex: /gh[opurs]_[A-Za-z0-9]{36,}/g,
    replace: "[GITHUB_TOKEN_REDACTED]",
  },
  // Bearer tokens
  {
    regex: /bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
    replace: "[BEARER_REDACTED]",
  },
  // JWTs (three base64url segments)
  {
    regex: /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*/g,
    replace: "[JWT_REDACTED]",
  },
  // API keys, secrets, passwords in key=value or key:value format
  {
    regex: /(api[_-]?key|apikey|secret|password|token)\s*[:=]\s*['"]?\S+['"]?/gi,
    replace: "$1: [REDACTED]",
  },
  // SSH private keys
  {
    regex: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END .*KEY-----/g,
    replace: "[SSH_KEY_REDACTED]",
  },
  // AWS access keys (AKIA...)
  {
    regex: /AKIA[0-9A-Z]{16}/g,
    replace: "[AWS_ACCESS_KEY_REDACTED]",
  },
  // Generic hex tokens (32+ hex chars)
  {
    regex: /\b[a-f0-9]{64,}\b/gi,
    replace: "[HEX_TOKEN_REDACTED]",
  },
];

// ── Log Rotation ─────────────────────────────────────────────

function cleanupOldLogs(auditDir: string, retentionDays: number): void {
  if (!existsSync(auditDir)) return;

  const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;

  try {
    const files = readdirSync(auditDir);
    for (const file of files) {
      if (!file.endsWith(".jsonl")) continue;

      const fullPath = join(auditDir, file);
      try {
        const stats = statSync(fullPath);
        if (stats.mtimeMs < cutoff) {
          unlinkSync(fullPath);
          console.log(`[ClawGuard] Audit log expired: ${file}`);
        }
      } catch {
        // Skip files we can't stat
      }
    }
  } catch (err) {
    console.warn("[ClawGuard] Failed to cleanup audit logs:", err);
  }
}

// ── Audit Logger ─────────────────────────────────────────────

export class AuditLogger {
  private auditDir: string;
  private retentionDays: number;
  private lastCleanupDate: string = "";

  constructor(auditDir?: string, retentionDays?: number) {
    this.auditDir = auditDir || DEFAULT_AUDIT_DIR;
    this.retentionDays = retentionDays || DEFAULT_RETENTION_DAYS;

    // Ensure audit directory exists
    if (!existsSync(this.auditDir)) {
      mkdirSync(this.auditDir, { recursive: true });
    }
  }

  /**
   * Append a sanitized audit entry to today's JSONL file.
   */
  append(entry: AuditEntry): void {
    this.tryCleanup();

    // Sanitize sensitive data
    const sanitized: AuditEntry = {
      ...entry,
      params: this.sanitize(this.truncate(entry.params, 1000)),
      result: this.sanitize(this.truncate(entry.result, 500)),
      error: entry.error ? this.sanitize(this.truncate(entry.error, 500)) : null,
    };

    // Build file path: ~/.clawguard/audit/YYYY-MM-DD.jsonl
    const today = new Date().toISOString().slice(0, 10);
    const logFile = join(this.auditDir, `${today}.jsonl`);

    try {
      appendFileSync(logFile, JSON.stringify(sanitized) + "\n");
    } catch (err) {
      console.error("[ClawGuard] Failed to write audit log:", err);
    }
  }

  /**
   * Sanitize text by replacing sensitive patterns.
   */
  sanitize(text: string): string {
    let safe = text;
    for (const { regex, replace } of SENSITIVE_PATTERNS) {
      safe = safe.replace(regex, replace);
    }
    return safe;
  }

  /**
   * Truncate text to maxChars.
   */
  private truncate(text: string, maxChars: number): string {
    if (text.length <= maxChars) return text;
    return text.slice(0, maxChars) + `... [truncated ${text.length - maxChars} chars]`;
  }

  /**
   * Remove audit logs older than retentionDays.
   * Only runs once per day to avoid excessive filesystem scans.
   */
  private tryCleanup(): void {
    const today = new Date().toISOString().slice(0, 10);
    if (this.lastCleanupDate === today) return;
    this.lastCleanupDate = today;

    cleanupOldLogs(this.auditDir, this.retentionDays);
  }

  /**
   * Force a cleanup of old logs now.
   */
  forceCleanup(): void {
    cleanupOldLogs(this.auditDir, this.retentionDays);
    this.lastCleanupDate = new Date().toISOString().slice(0, 10);
  }

  /**
   * Get audit directory path.
   */
  get dir(): string {
    return this.auditDir;
  }
}
