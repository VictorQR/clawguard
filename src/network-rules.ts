/**
 * ClawGuard — Network Domain Rules
 *
 * Domain allowlist with default-deny for unrecognized domains.
 * Also intercepts web_search tool calls.
 */
import type { NetworkCheckResult } from "./types.js";

// ── Domain Lists ─────────────────────────────────────────────

const ALLOWED_DOMAINS: string[] = [
  // Code repositories
  "api.github.com",
  "github.com",
  "raw.githubusercontent.com",

  // Package registries
  "registry.npmjs.org",
  "pypi.org",
  "files.pythonhosted.org",

  // AI APIs
  "api.deepseek.com",
  "api.openai.com",

  // Search APIs
  "api.tavily.ai",

  // OpenClaw
  "docs.openclaw.ai",
  "openclaw.ai",

  // Localhost (always allowed)
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
];

const DENIED_DOMAINS_BY_DEFAULT = true;

// ── URL Parsing ──────────────────────────────────────────────

function extractDomain(urlStr: string): string | null {
  try {
    // Try as full URL
    const url = new URL(urlStr);
    return url.hostname.toLowerCase();
  } catch {
    // Try as hostname:port
    const match = urlStr.match(/^([a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9])(?::\d+)?$/);
    if (match) {
      return match[1].toLowerCase();
    }
    return null;
  }
}

// ── Domain Matching ──────────────────────────────────────────

function matchesDomain(domain: string, patterns: string[]): string | null {
  for (const pattern of patterns) {
    // Exact match
    if (domain === pattern.toLowerCase()) {
      return pattern;
    }
    // Subdomain match: *.example.com matches sub.example.com
    if (pattern.startsWith("*.")) {
      const suffix = pattern.slice(1); // .example.com
      if (domain.endsWith(suffix)) {
        return pattern;
      }
    }
  }
  return null;
}

// ── Public API ───────────────────────────────────────────────

/**
 * Check if a URL/domain is allowed for network access.
 *
 * @param urlOrDomain - A full URL or bare domain string
 * @returns NetworkCheckResult
 */
export function checkDomain(urlOrDomain: string): NetworkCheckResult {
  // Empty/blank URLs are not actual network requests — allow
  if (!urlOrDomain || urlOrDomain.trim() === "") {
    return {
      action: "allow",
      reason: "✅ 空白 URL —— 放行",
      domain: "",
    };
  }

  const domain = extractDomain(urlOrDomain);

  if (!domain) {
    return {
      action: "deny",
      reason: "🚫 无法解析域名",
      domain: urlOrDomain,
    };
  }

  // Check localhost / private IPs — always allow (RFC 1918 + RFC 5735)
  if (
    domain === "localhost" ||
    domain === "127.0.0.1" ||
    domain === "0.0.0.0" ||
    domain.startsWith("192.168.") ||
    domain.startsWith("10.") ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(domain)  // RFC 1918: 172.16.0.0/12
  ) {
    return {
      action: "allow",
      reason: "✅ 本地/私有网络地址",
      domain,
    };
  }

  // Explicitly deny cloud metadata endpoints (IMDS)
  if (
    domain === "169.254.169.254" ||
    domain === "metadata.google.internal"
  ) {
    return {
      action: "deny",
      reason: "🚫 禁止访问云元数据服务",
      domain,
    };
  }

  // Check allowlist
  const allowedBy = matchesDomain(domain, ALLOWED_DOMAINS);
  if (allowedBy) {
    return {
      action: "allow",
      reason: `✅ 域名在白名单内: ${allowedBy}`,
      domain,
    };
  }

  // Default: require approval for unknown domains
  if (DENIED_DOMAINS_BY_DEFAULT) {
    return {
      action: "approve",
      reason: `🔶 域名不在白名单内: ${domain}`,
      domain,
    };
  }

  // If default not denied, approve
  return {
    action: "approve",
    reason: `🔶 域名不在白名单内，需审批: ${domain}`,
    domain,
  };
}

/**
 * Add a runtime-allowlisted domain (from policy or config).
 */
export function addAllowedDomain(domain: string): void {
  const normalized = domain.toLowerCase().trim();
  if (normalized && !ALLOWED_DOMAINS.includes(normalized)) {
    ALLOWED_DOMAINS.push(normalized);
  }
}

/**
 * Get current domain allowlist (for status).
 */
export function getAllowedDomains(): string[] {
  return [...ALLOWED_DOMAINS];
}
