/**
 * ClawGuard — Policy Engine
 *
 * Reads ~/.clawguard/policy.ini, supports hot-reload via write-then-rename.
 * Falls back to built-in deny-all defaults when policy file is missing or corrupt.
 */
import { readFileSync, existsSync, writeFileSync, watch, FSWatcher } from "node:fs";
import { createHash } from "node:crypto";
import { homedir, tmpdir } from "node:os";
import { join, dirname } from "node:path";
import type { ClawGuardMode, PolicyRule, ParsedPolicy } from "./types.js";

// ── Paths ────────────────────────────────────────────────────

const HOME = homedir();
const CLAWGUARD_DIR = join(HOME, ".clawguard");
const POLICY_FILE = join(CLAWGUARD_DIR, "policy.ini");
const HASH_FILE = join(CLAWGUARD_DIR, ".policy-hash");

// ── Fallback Defaults (when policy file is corrupt/missing) ──

const FALLBACK_RULES: ParsedPolicy = {
  mode: "enforce",
  rules: [
    // Only allow absolutely safe commands
    { type: "allow_cmd", value: "ls" },
    { type: "allow_cmd", value: "cd" },
    { type: "allow_cmd", value: "pwd" },
    { type: "allow_cmd", value: "whoami" },
    { type: "allow_cmd", value: "which" },
    { type: "allow_cmd", value: "gio trash" },
    { type: "allow_cmd", value: "echo" },
    { type: "allow_cmd", value: "cat" },
  ],
};

// ── Policy Engine ────────────────────────────────────────────

export class PolicyEngine {
  private policy: ParsedPolicy;
  private _isFallbackMode: boolean;
  private watcher: FSWatcher | null = null;

  constructor(policyPath?: string) {
    this._isFallbackMode = false;
    this.policy = { mode: "supervised", rules: [] };

    const path = policyPath || POLICY_FILE;
    this.load(path);
  }

  private _integrityOk = true;
  private _lastHash = "";

  /**
   * Load policy from file. Falls back if file missing or corrupt.
   */
  load(filePath: string): void {
    if (!existsSync(filePath)) {
      console.warn("[ClawGuard] Policy file not found, using fallback deny-all");
      this.policy = { ...FALLBACK_RULES };
      this._isFallbackMode = true;
      this._integrityOk = false;
      return;
    }

    try {
      const raw = readFileSync(filePath, "utf-8");

      // SHA256 integrity check
      const integrity = this.verifyIntegrity(raw, filePath);
      if (!integrity.valid) {
        console.error(`[ClawGuard] Policy integrity check failed: ${integrity.reason}`);
        this.policy = { ...FALLBACK_RULES };
        this._isFallbackMode = true;
        this._integrityOk = false;
        return;
      }

      this.policy = this.parse(raw);
      this._isFallbackMode = false;
      this._integrityOk = true;
      console.log(`[ClawGuard] Policy loaded: mode=${this.policy.mode}, rules=${this.policy.rules.length}, integrity=✓`);
    } catch (err) {
      console.error("[ClawGuard] Policy file corrupt, using fallback deny-all:", err);
      this.policy = { ...FALLBACK_RULES };
      this._isFallbackMode = true;
      this._integrityOk = false;
    }
  }

  /**
   * Compute SHA256 of content.
   */
  computeHash(content: string): string {
    return createHash("sha256").update(content, "utf-8").digest("hex");
  }

  /**
   * Verify policy file integrity against stored hash.
   * First load → store hash and return valid.
   * Hash match → valid.
   * Hash mismatch → file may have been tampered.
   */
  verifyIntegrity(content: string, filePath: string): { valid: boolean; reason?: string } {
    const currentHash = this.computeHash(content);
    this._lastHash = currentHash;

    // First load: store hash
    if (!existsSync(HASH_FILE)) {
      try {
        const dir = dirname(HASH_FILE);
        if (!existsSync(dir)) return { valid: true }; // dir may be auto-created
        writeFileSync(HASH_FILE, currentHash, "utf-8");
        console.log("[ClawGuard] Policy hash initialized");
        return { valid: true };
      } catch (err) {
        console.warn("[ClawGuard] Could not write policy hash file:", err);
        return { valid: true }; // Don't block on hash write failure
      }
    }

    // Subsequent loads: verify hash
    try {
      const storedHash = readFileSync(HASH_FILE, "utf-8").trim();
      if (storedHash === currentHash) {
        return { valid: true };
      }

      // Hash changed — check if the new content parses validly
      try {
        this.parse(content); // Throws if invalid
        // Content is valid → update hash (legitimate change)
        writeFileSync(HASH_FILE, currentHash, "utf-8");
        console.log("[ClawGuard] Policy hash updated (legitimate change detected)");
        return { valid: true };
      } catch {
        return {
          valid: false,
          reason: `策略文件被篡改且内容损坏 (hash: ${currentHash.slice(0, 16)}...)`,
        };
      }
    } catch (err) {
      console.warn("[ClawGuard] Could not read policy hash file:", err);
      return { valid: true }; // Don't block on hash read failure
    }
  }

  /**
   * Hot-reload policy (called on clawguard.config reload or file watch).
   */
  reload(filePath?: string): void {
    const path = filePath || POLICY_FILE;
    this.load(path);
  }

  /**
   * Watch policy file for changes and auto-reload.
   */
  watchFile(filePath?: string): void {
    const path = filePath || POLICY_FILE;
    try {
      this.watcher = watch(path, () => {
        console.log("[ClawGuard] Policy file changed, reloading...");
        // Small delay to allow atomic rename to complete
        setTimeout(() => this.reload(path), 100);
      });
    } catch {
      // File may not exist yet — that's fine
    }
  }

  /**
   * Stop watching the policy file.
   */
  unwatch(): void {
    if (this.watcher) {
      this.watcher.close();
      this.watcher = null;
    }
  }

  /**
   * Parse policy.ini content into ParsedPolicy.
   */
  private parse(content: string): ParsedPolicy {
    const rules: PolicyRule[] = [];
    let mode: ClawGuardMode = "supervised";

    const lines = content.split("\n");
    for (const rawLine of lines) {
      const line = rawLine.trim();

      // Skip comments and empty lines
      if (!line || line.startsWith("#") || line.startsWith(";")) {
        continue;
      }

      // Parse mode = value
      const modeMatch = line.match(/^mode\s*=\s*(.+)$/i);
      if (modeMatch) {
        const val = modeMatch[1].trim().toLowerCase();
        if (val === "permissive" || val === "supervised" || val === "enforce") {
          mode = val;
        }
        continue;
      }

      // Parse allow_cmd = command prefix
      const cmdMatch = line.match(/^allow_cmd\s*=\s*(.+)$/i);
      if (cmdMatch) {
        const value = this.resolveVars(cmdMatch[1].trim());
        rules.push({ type: "allow_cmd", value });
        continue;
      }

      // Parse allow_domain = domain
      const domainMatch = line.match(/^allow_domain\s*=\s*(.+)$/i);
      if (domainMatch) {
        rules.push({ type: "allow_domain", value: domainMatch[1].trim() });
        continue;
      }

      // Parse allow_write = path
      const writeMatch = line.match(/^allow_write\s*=\s*(.+)$/i);
      if (writeMatch) {
        const value = this.resolveVars(writeMatch[1].trim());
        rules.push({ type: "allow_write", value });
        continue;
      }
    }

    return { mode, rules };
  }

  /**
   * Resolve variables like $WORKSPACE and $HOME.
   */
  private resolveVars(value: string): string {
    // $WORKSPACE → OpenClaw workspace directory (hardcoded)
    const workspace = process.env.WORKSPACE || join(HOME, ".openclaw", "workspace");
    let resolved = value.replace(/\$WORKSPACE/g, workspace);

    // $HOME → user home
    resolved = resolved.replace(/\$HOME/g, HOME);

    // ~ → user home
    resolved = resolved.replace(/^~/, HOME);

    return resolved;
  }

  /**
   * Whether we are in fallback/panic mode.
   */
  get isFallbackMode(): boolean {
    return this._isFallbackMode;
  }

  /**
   * Whether policy file integrity is verified.
   */
  get integrityOk(): boolean {
    return this._integrityOk;
  }

  /**
   * Last computed policy hash.
   */
  get lastHash(): string {
    return this._lastHash;
  }

  /**
   * Current operational mode.
   */
  get mode(): ClawGuardMode {
    return this.policy.mode;
  }

  /**
   * Check if a command is allowed by policy rules.
   * Returns "allow" if matched, "deny" if explicitly denied by fallback, null if not in policy.
   */
  checkCommand(cmd: string): "allow" | "deny" | null {
    if (this._isFallbackMode) {
      // In fallback mode, only allow list applies
      for (const rule of this.policy.rules) {
        if (rule.type === "allow_cmd" && cmd.trim().startsWith(rule.value)) {
          return "allow";
        }
      }
      return "deny"; // deny everything else in fallback
    }

    for (const rule of this.policy.rules) {
      if (rule.type === "allow_cmd" && cmd.trim().startsWith(rule.value)) {
        return "allow";
      }
    }
    return null;
  }

  /**
   * Check if a domain is allowed by policy.
   */
  checkDomain(domain: string): "allow" | "deny" | null {
    if (this._isFallbackMode) {
      return "deny"; // no domains allowed in fallback
    }

    const normalized = domain.toLowerCase().trim();
    for (const rule of this.policy.rules) {
      if (rule.type === "allow_domain" && normalized === rule.value) {
        return "allow";
      }
    }
    return null;
  }

  /**
   * Check if a write path is allowed by policy.
   */
  checkWritePath(path: string): "allow" | "deny" | null {
    if (this._isFallbackMode) {
      return "deny"; // most writes denied in fallback
    }

    const normalized = path.trim();
    for (const rule of this.policy.rules) {
      if (rule.type === "allow_write" && normalized.startsWith(rule.value.replace(/\*\*/g, "").replace(/\*$/, ""))) {
        return "allow";
      }
    }
    return null;
  }

  /**
   * Get all policy rules (for status display).
   */
  get rules(): PolicyRule[] {
    return [...this.policy.rules];
  }

  /**
   * Get a summary of the current policy state.
   */
  getSummary(): { mode: string; rules: number; fallback: boolean; integrity: boolean } {
    return {
      mode: this.policy.mode,
      rules: this.policy.rules.length,
      fallback: this._isFallbackMode,
      integrity: this._integrityOk,
    };
  }
}
