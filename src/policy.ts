/**
 * ClawGuard — Policy Engine
 *
 * Reads ~/.clawguard/policy.ini, supports hot-reload via write-then-rename.
 * Falls back to built-in deny-all defaults when policy file is missing or corrupt.
 */
import { readFileSync, existsSync, watch, FSWatcher } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import type { ClawGuardMode, PolicyRule, ParsedPolicy } from "./types.js";

// ── Paths ────────────────────────────────────────────────────

const HOME = homedir();
const POLICY_FILE = join(HOME, ".clawguard", "policy.ini");

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

  /**
   * Load policy from file. Falls back if file missing or corrupt.
   */
  load(filePath: string): void {
    if (!existsSync(filePath)) {
      console.warn("[ClawGuard] Policy file not found, using fallback deny-all");
      this.policy = { ...FALLBACK_RULES };
      this._isFallbackMode = true;
      return;
    }

    try {
      const raw = readFileSync(filePath, "utf-8");
      this.policy = this.parse(raw);
      this._isFallbackMode = false;
      console.log(`[ClawGuard] Policy loaded: mode=${this.policy.mode}, rules=${this.policy.rules.length}`);
    } catch (err) {
      console.error("[ClawGuard] Policy file corrupt, using fallback deny-all:", err);
      this.policy = { ...FALLBACK_RULES };
      this._isFallbackMode = true;
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
  getSummary(): { mode: string; rules: number; fallback: boolean } {
    return {
      mode: this.policy.mode,
      rules: this.policy.rules.length,
      fallback: this._isFallbackMode,
    };
  }
}
