/**
 * ClawGuard — File Path Rules
 *
 * Read/write rules with separate evaluation. Uses minimatch for glob matching
 * and realpath for symlink resolution.
 */
import { realpathSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { minimatch } from "minimatch";
import type { FileCheckResult } from "./types.js";

// ── Path Normalization ───────────────────────────────────────

const HOME = homedir();

/**
 * Normalize a file path:
 *   - Expand ~ → /home/victor
 *   - Expand $HOME → /home/victor
 *   - Resolve relative paths
 *   - Resolve symlinks to real path
 */
export function normalizePath(rawPath: string): string {
  let p = rawPath.trim();

  // Expand tilde
  if (p.startsWith("~/")) {
    p = HOME + "/" + p.slice(2);
  } else if (p === "~") {
    p = HOME;
  }

  // Expand $HOME
  if (p.startsWith("$HOME/")) {
    p = HOME + "/" + p.slice(6);
  } else if (p === "$HOME") {
    p = HOME;
  }

  // Resolve realpath if file exists (handles symlinks)
  try {
    if (existsSync(p)) {
      p = realpathSync(p);
    }
  } catch {
    // If realpath fails (e.g., file doesn't exist yet for writes),
    // use the normalized path as-is
  }

  // Remove trailing slash
  p = p.replace(/\/+$/, "") || "/";

  return p;
}

// ── Path Lists ───────────────────────────────────────────────

const WRITE_ALLOWED: string[] = [
  HOME + "/.openclaw/workspace/**",
  "/tmp/**",
];

const WRITE_DENIED: string[] = [
  HOME + "/.ssh/**",
  HOME + "/.gnupg/**",
  HOME + "/.aws/**",
  HOME + "/.config/**/credentials",
  HOME + "/.kube/config",
  HOME + "/.docker/config.json",
  "/etc/shadow",
  "/etc/passwd",
  "/etc/sudoers",
  "/boot/**",
  "**/.env",
  "**/.env.*",
  "**/*.pem",
  "**/*.key",
];

const READ_DENIED: string[] = [
  HOME + "/.ssh/**",
  HOME + "/.gnupg/**",
  HOME + "/.aws/**",
  HOME + "/.kube/config",
  "/etc/shadow",
  "**/.env",
  "**/.env.*",
];

const READ_ALLOWED: string[] = [
  HOME + "/.openclaw/**",
  "/tmp/**",
  HOME + "/Documents/**",
  "/etc/hostname",
  "/etc/os-release",
];

// ── Matching ─────────────────────────────────────────────────

function matchesAny(path: string, patterns: string[]): string | null {
  for (const pattern of patterns) {
    if (minimatch(path, pattern, { dot: true, matchBase: false })) {
      return pattern;
    }
  }
  return null;
}

// ── Public API ───────────────────────────────────────────────

/**
 * Check if a file write operation is allowed.
 * Deny list takes priority over allow list.
 */
export function checkFileWrite(rawPath: string): FileCheckResult {
  const normalized = normalizePath(rawPath);

  // Check deny list first
  const deniedBy = matchesAny(normalized, WRITE_DENIED);
  if (deniedBy) {
    return {
      action: "deny",
      reason: `🚫 敏感路径禁止写入: ${deniedBy}`,
      rule: deniedBy,
      path: rawPath,
      normalizedPath: normalized,
    };
  }

  // Check allow list
  const allowedBy = matchesAny(normalized, WRITE_ALLOWED);
  if (allowedBy) {
    return {
      action: "allow",
      reason: `✅ 路径在白名单内: ${allowedBy}`,
      rule: allowedBy,
      path: rawPath,
      normalizedPath: normalized,
    };
  }

  // Not in allow list, not denied — approve (requires user confirmation)
  return {
    action: "approve",
    reason: "🔶 写入路径不在白名单内，需审批",
    path: rawPath,
    normalizedPath: normalized,
  };
}

/**
 * Check if a file read operation is allowed.
 * Deny list takes priority (more permissive than write).
 */
export function checkFileRead(rawPath: string): FileCheckResult {
  const normalized = normalizePath(rawPath);

  // Check deny list
  const deniedBy = matchesAny(normalized, READ_DENIED);
  if (deniedBy) {
    return {
      action: "deny",
      reason: `🚫 敏感路径禁止读取: ${deniedBy}`,
      rule: deniedBy,
      path: rawPath,
      normalizedPath: normalized,
    };
  }

  // Check allow list
  const allowedBy = matchesAny(normalized, READ_ALLOWED);
  if (allowedBy) {
    return {
      action: "allow",
      reason: `✅ 读取路径在白名单内: ${allowedBy}`,
      rule: allowedBy,
      path: rawPath,
      normalizedPath: normalized,
    };
  }

  // Not in allow list, not denied — approve
  return {
    action: "approve",
    reason: "🔶 读取路径不在白名单内，需审批",
    path: rawPath,
    normalizedPath: normalized,
  };
}
