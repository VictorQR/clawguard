/**
 * ClawGuard — File Path Rules
 *
 * Read/write rules with separate evaluation. Uses minimatch for glob matching
 * and realpath for symlink resolution.
 */
import { realpathSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { resolve, join } from "node:path";
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

  // Collapse ../ and ./ components (pure string operation, no I/O)
  p = resolve(p);

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
  // ClawGuard self-protection
  HOME + "/.clawguard/**",
  HOME + "/.openclaw/openclaw.json",
  HOME + "/.openclaw/.policy-hash",
  HOME + "/.openclaw/npm/node_modules/**/clawguard/**",
  HOME + "/.openclaw/node_modules/**/clawguard/**",
  // System credentials
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

// ── Boundary Check ───────────────────────────────────────────

/**
 * Check whether a normalized path falls within any of the allowed root directories.
 * Prevents path traversal attacks and accidental writes outside safe boundaries.
 */
const ALLOWED_ROOTS: string[] = [
  join(HOME, ".openclaw", "workspace"),
  "/tmp",
  HOME,
];

function isWithinAllowedTree(candidate: string, allowedRoots: string[]): boolean {
  const normalizedCandidate = candidate.replace(/\/+$/, "") || "/";
  for (const root of allowedRoots) {
    const normalizedRoot = root.replace(/\/+$/, "") || "/";
    // Candidate must either equal the root, or start with root + "/"
    if (
      normalizedCandidate === normalizedRoot ||
      normalizedCandidate.startsWith(normalizedRoot + "/")
    ) {
      return true;
    }
  }
  return false;
}

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

  // Boundary check: deny writes outside allowed root trees
  if (!isWithinAllowedTree(normalized, ALLOWED_ROOTS)) {
    return {
      action: "deny",
      reason: `🚫 路径越界，不在允许的根目录范围内: ${normalized}`,
      path: rawPath,
      normalizedPath: normalized,
    };
  }

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

  // Boundary check: deny reads outside allowed root trees
  if (!isWithinAllowedTree(normalized, ALLOWED_ROOTS)) {
    return {
      action: "deny",
      reason: `🚫 读取路径越界，不在允许的根目录范围内: ${normalized}`,
      path: rawPath,
      normalizedPath: normalized,
    };
  }

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
