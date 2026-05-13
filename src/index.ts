/**
 * ClawGuard Plugin — Main Entry Point
 *
 * A lightweight OpenClaw security plugin providing:
 *   - Runtime tool call interception (before_tool_call hook)
 *   - Three-tier command rules: DENY > ALLOW > APPROVE
 *   - Encoding bypass detection (base64, eval, obfuscation)
 *   - File path rules (read/write separate) with symlink resolution
 *   - Network domain allowlist with default-deny
 *   - Policy file with hot-reload and fallback defaults
 *   - Sanitized JSONL audit logging with 90-day rotation
 */
import { homedir } from "node:os";
import { extractCommand } from "./extractor.js";
import { checkCommand, reloadRules, getRuleStats, isRuleIntegrityOK } from "./rules.js";
import { checkBypass } from "./bypass.js";
import { checkFileWrite, checkFileRead } from "./file-rules.js";
import { checkDomain } from "./network-rules.js";
import { PolicyEngine } from "./policy.js";
import { AuditLogger } from "./audit.js";
import { RateLimiter } from "./rateLimiter.js";
import { StatsCollector } from "./session-stats.js";
import type {
  BeforeToolCallResult,
  ClawGuardSession,
  AuditEntry,
} from "./types.js";

// ── Global State ─────────────────────────────────────────────

const policyEngine = new PolicyEngine();
const auditLog = new AuditLogger();

// Session tracking (maps sessionId → stats)
const sessionCache = new Map<string, ClawGuardSession>();
let currentSessionId = "unknown";

// Per-session approval memory: sessionKey → Set<"category:value">
// e.g. "exec:git push", "file:/tmp/test.txt", "net:api.github.com"
const sessionApprovals = new Map<string, Set<string>>();

// Rate limiter for burst protection and escalation
const rateLimiter = new RateLimiter();

// Stats collector for session reports
const stats = new StatsCollector();

// ── Approval Memory Limit ───────────────────────────────────
const MAX_APPROVALS_PER_SESSION = 200;

/** Add an approval entry with FIFO eviction when at capacity */
function addApproval(sessionKey: string, key: string): void {
  if (!sessionApprovals.has(sessionKey)) {
    sessionApprovals.set(sessionKey, new Set());
  }
  const set = sessionApprovals.get(sessionKey)!;
  if (set.size >= MAX_APPROVALS_PER_SESSION) {
    // FIFO: remove the earliest entry (Set preserves insertion order)
    const firstKey = set.values().next().value;
    if (firstKey) set.delete(firstKey);
  }
  set.add(key);
}

// ── Channel Detection ────────────────────────────────────────

type ChannelType = "direct" | "group" | "cron" | "terminal" | "unknown";

/** Parse channel type from ctx.sessionKey */
function parseChannelType(sessionKey: string): ChannelType {
  // Format: agent:main:<provider>:<chatType>:<id>
  // e.g.   agent:main:qqbot:direct:0a39...
  const parts = sessionKey.split(":");
  if (parts.length >= 4) {
    const chatType = parts[3];
    if (chatType === "direct" || chatType === "group" || chatType === "cron") {
      return chatType as ChannelType;
    }
  }
  if (sessionKey.includes("terminal")) return "terminal";
  if (sessionKey.includes("cron")) return "cron";
  return "unknown";
}

/** Channel-based default mode (overrides policy.ini mode) */
const CHANNEL_MODE_OVERRIDE: Record<ChannelType, string | null> = {
  direct: null,       // Use policy.ini mode
  group: "enforce",   // Strict in groups
  cron: "permissive", // Auto-allow for cron (full audit)
  terminal: null,     // Use policy.ini mode
  unknown: "enforce", // Strict for unknown channels
};

// ── Tool Dispatch Tables ─────────────────────────────────────

const EXEC_TOOLS = new Set([
  "exec",
  "bash",
  "run_command",
  "shell",
  "terminal",
  "cmd",
  "powershell",
]);

const WRITE_TOOLS = new Set([
  "write",
  "edit",
  "apply_patch",
]);

const READ_TOOLS = new Set([
  "read",
  "read_file",
  "cat",
]);

const NETWORK_TOOLS = new Set([
  "web_fetch",
  "http_request",
  "fetch",
]);

// Read-only tools: auto-allow (no exec, no write, no side effects)
// ⚠️ web_search was originally handled by handleNetwork with a special case.
// If removed from this set, restore the handleNetwork special case for audit coverage.
const READONLY_TOOLS = new Set([
  "web_fetch",
  "web_search",
  "memory_search",
  "memory_get",
  "memory_recall",
  "image",
  "session_status",
  "weather",
  "sessions_list",
  "sessions_history",
]);

const DANGEROUS_TOOLS = new Set([
  "process",
  "sessions_spawn",
]);

// ── Plugin Entry Point ───────────────────────────────────────

// In ESM we use createRequire to dynamically import SDK modules
import { createRequire } from "node:module";
const _require = createRequire(import.meta.url);

// Shared init function for both paths
function initPlugin(api: any): void {
  console.log("[ClawGuard] Plugin initializing...");

  // Watch policy file for changes
  policyEngine.watchFile();
  console.log(`[ClawGuard] Mode: ${policyEngine.mode}, Fallback: ${policyEngine.isFallbackMode}`);

  // ── session_start hook ───────────────────────────────────

  api.on("session_start", async (_event: any, ctx: any) => {
    const sessionKey = ctx?.sessionKey || "unknown";
    currentSessionId = sessionKey;

    // Initialize session tracking
    if (!sessionCache.has(sessionKey)) {
      sessionCache.set(sessionKey, {
        commandCount: 0,
        denyCount: 0,
        approveCount: 0,
        bypassDetections: 0,
      });
    }

    // Pre-load policy strategy
    const channelType = parseChannelType(sessionKey);
    const effectiveMode = CHANNEL_MODE_OVERRIDE[channelType] || policyEngine.mode;

    console.log(`[ClawGuard] 🚀 会话开始: ${sessionKey} | 通道: ${channelType} | 模式: ${effectiveMode}`);
  });

  // ── before_tool_call hook (priority=100) ──────────────────

  api.on(
    "before_tool_call",
    async (event: any, ctx: any) => {
      // Update session tracking from hook context
      if (ctx?.sessionKey) {
        currentSessionId = ctx.sessionKey;
      }

      // ── Channel-aware policy ──────────────────────────
      const channelType = parseChannelType(currentSessionId);
      const effectiveMode = CHANNEL_MODE_OVERRIDE[channelType] || policyEngine.mode;

      // Group channels: enforce mode (only allowlist)
      if (channelType === "group") {
        if (EXEC_TOOLS.has(event.toolName)) {
          const { command } = extractCommand(event.params);
          if (command) {
            const ruleResult = checkCommand(command);
            if (ruleResult.action !== "allow") {
              logDecision("DENY", command, "群聊通道仅允许白名单命令");
              return { block: true, blockReason: "🔒 群聊通道安全策略：仅允许白名单命令" };
            }
          }
        }
        if (WRITE_TOOLS.has(event.toolName)) {
          const filePath = event.params?.path || event.params?.file || event.params?.filePath || "";
          if (filePath) {
            const writeResult = checkFileWrite(filePath);
            if (writeResult.action !== "allow") {
              logDecision("DENY", filePath, "群聊通道仅允许白名单路径写入");
              return { block: true, blockReason: "🔒 群聊通道安全策略：仅允许白名单文件写入" };
            }
          }
        }
        if (NETWORK_TOOLS.has(event.toolName)) {
          const url = event.params?.url || event.params?.uri || "";
          if (url) {
            const netResult = checkDomain(url);
            if (netResult.action !== "allow") {
              logDecision("DENY", url, "群聊通道仅允许白名单域名");
              return { block: true, blockReason: "🔒 群聊通道安全策略：仅允许白名单域名访问" };
            }
          }
        }
        // For exec/write/network handled above, prevent fallthrough to normal handlers
        if (EXEC_TOOLS.has(event.toolName) || WRITE_TOOLS.has(event.toolName) || NETWORK_TOOLS.has(event.toolName)) {
          return;
        }
        // Allow other tool types (read, etc.) in groups
      }

      // Cron channels: permissive mode (auto-allow, full audit)
      if (channelType === "cron") {
        if (EXEC_TOOLS.has(event.toolName)) {
          const { command } = extractCommand(event.params);
          if (command) {
            logDecision("ALLOW", command, `cron 通道自动放行 (模式:${effectiveMode})`);
          }
          rateLimiter.recordExec(currentSessionId);
        }
        return; // Auto-allow all in cron
      }

      // ── Rate limiting & escalation (exec tools only) ────
      if (EXEC_TOOLS.has(event.toolName)) {
        // Escalated session → enforce mode override
        if (rateLimiter.isEscalated(currentSessionId)) {
          logDecision("DENY", "[escalated]", "会话已升级为 enforce 模式");
          rateLimiter.recordDeny(currentSessionId);
          return { block: true, blockReason: "🔴 该会话已因连续拒绝操作自动升级为 enforce 模式。如需重置，请开启新会话。" };
        }

        // Rate limit check (burst / global cap)
        const rateCheck = rateLimiter.checkExecRate(currentSessionId);
        if (!rateCheck.allowed) {
          console.warn(`[ClawGuard] ⚡ ${rateCheck.reason}`);
          if (rateCheck.escalated) {
            auditLog.append({
              timestamp: new Date().toISOString(),
              toolName: event.toolName,
              params: JSON.stringify(event.params),
              result: "BLOCKED (global cap)",
              durationMs: 0,
              error: null,
              decision: "DENY",
              rule: "rate_limit_global_cap",
              session: currentSessionId,
            });
          }
          return {
            block: true,
            blockReason: rateCheck.reason!,
          };
        }
      }

      // Read operations: auto-allow even in fallback (zero side effects, self-healing)
      // Design: deny-all-for-exec, allow-all-for-read
      if (READONLY_TOOLS.has(event.toolName)) {
        stats.recordCall(currentSessionId, event.toolName);
        console.log(`[ClawGuard] ✅ ALLOW | 只读工具自动放行 | tool="${event.toolName}"`);
        return;
      }
      if (READ_TOOLS.has(event.toolName)) {
        return handleFileRead(event, ctx); // Already permissive: only blocks denied_paths
      }

      // Fallback mode — deny write/exec operations
      if (policyEngine.isFallbackMode) {
        auditLog.append({
          timestamp: new Date().toISOString(),
          toolName: event.toolName,
          params: JSON.stringify(event.params),
          result: "BLOCKED (fallback)",
          durationMs: 0,
          error: null,
          decision: "DENY",
          rule: "fallback_deny_all",
          session: currentSessionId,
        });
        return {
          block: true,
          blockReason: "⚠️ Policy 文件损坏，已拒绝写/执行操作。只读操作仍可用。",
        };
      }

      // Permissive mode — log only, never block
      if (policyEngine.mode === "permissive") {
        // Still run bypass detection for logging
        if (EXEC_TOOLS.has(event.toolName)) {
          const { command } = extractCommand(event.params);
          if (command) {
            const bypassCheck = checkBypass(command);
            if (bypassCheck) {
              console.warn(`[ClawGuard] ${bypassCheck.reason}`);
            }
          }
          rateLimiter.recordExec(currentSessionId);
        }
        return;
      }

      // Check session-level approval cache (from previous "always allow")
      const approvedSet = sessionApprovals.get(currentSessionId);
      if (approvedSet && approvedSet.size > 0) {
        if (EXEC_TOOLS.has(event.toolName)) {
          const { command } = extractCommand(event.params);
          if (command && approvedSet.has(`exec:${command}`)) {
            logDecision("ALLOW", command, "会话内已审批 (always-allow)");
            return;
          }
        }
        if (WRITE_TOOLS.has(event.toolName)) {
          const fp = event.params?.path || event.params?.file || event.params?.filePath || "";
          if (fp && approvedSet.has(`file:${fp}`)) {
            return;
          }
        }
        if (NETWORK_TOOLS.has(event.toolName)) {
          const url = event.params?.url || event.params?.uri || "";
          if (url && approvedSet.has(`net:${url}`)) {
            return;
          }
        }
      }

      // Route dangerous tools through exec pipeline (process, sessions_spawn)
      if (DANGEROUS_TOOLS.has(event.toolName)) {
        return handleExec(event, ctx);
      }

      // Route to appropriate handler
      try {
        if (EXEC_TOOLS.has(event.toolName)) {
          return handleExec(event, ctx);
        }
        if (WRITE_TOOLS.has(event.toolName)) {
          return handleFileWrite(event, ctx);
        }
        if (READ_TOOLS.has(event.toolName)) {
          return handleFileRead(event, ctx);
        }
        if (NETWORK_TOOLS.has(event.toolName)) {
          return handleNetwork(event, ctx);
        }
        return;
      } catch (err) {
        console.error("[ClawGuard] before_tool_call handler error:", err);
        return { block: true, blockReason: "🔴 ClawGuard 内部异常——操作已安全拦截" };
      }
    },
    { priority: 100 }
  );

  // ── after_tool_call hook (priority=50) ────────────────────

  api.on(
    "after_tool_call",
    async (event: any, ctx: any) => {
      // Update session tracking from hook context
      if (ctx?.sessionKey) {
        currentSessionId = ctx.sessionKey;
      }

      let resultStr: string;
      if (event.result === undefined || event.result === null) {
        resultStr = "";
      } else if (typeof event.result === "string") {
        resultStr = event.result;
      } else if (Buffer.isBuffer(event.result)) {
        resultStr = `[Buffer: ${(event.result as Buffer).length} bytes]`;
      } else {
        try { resultStr = JSON.stringify(event.result); }
        catch { resultStr = String(event.result); }
      }

      const entry: AuditEntry = {
        timestamp: new Date().toISOString(),
        toolName: event.toolName,
        params: JSON.stringify(event.params),
        result: resultStr,
        toolCallId: event.toolCallId || null,
        durationMs: event.durationMs ?? 0,
        error: event.error ? String(event.error) : null,
        session: currentSessionId,
      };

      if (EXEC_TOOLS.has(event.toolName)) {
        const { command } = extractCommand(event.params);
        if (command) entry.command = command;
      }

      // Record stats for non-exec tools too
      if (!EXEC_TOOLS.has(event.toolName)) {
        stats.recordCall(currentSessionId, event.toolName);
      }
      if (event.durationMs) {
        stats.recordDuration(currentSessionId, event.durationMs);
      }

      auditLog.append(entry);
    },
    { priority: 50 }
  );

  // ── session_end hook ───────────────────────────────────────
  api.on("session_end", async (_event: any, ctx: any) => {
    const sessionKey = ctx?.sessionKey || currentSessionId;
    const approvalCount = sessionApprovals.get(sessionKey)?.size || 0;
    const rateStats = rateLimiter.getStats(sessionKey);
    const sessionStats = stats.getSession(sessionKey);
    sessionCache.delete(sessionKey);
    sessionApprovals.delete(sessionKey);
    rateLimiter.reset(sessionKey);
    stats.reset(sessionKey);
    console.log(`[ClawGuard] 🧹 会话结束: ${sessionKey}`);
    console.log(`  审批记忆:${approvalCount} | execs:${rateStats?.recentExecs ?? 0} | denies:${sessionStats?.denyCount ?? 0} | commands:${sessionStats?.commandCount ?? 0}`);
  });

  // ── Health check service ───────────────────────────────────
  if (typeof api.registerService === "function") {
    api.registerService({ id: "clawguard-health", start: async () => {
      return {
        status: "ok",
        mode: policyEngine.mode,
        fallback: policyEngine.isFallbackMode,
        integrity: policyEngine.integrityOk,
        rules: getRuleStats(),
        sessions: sessionCache.size,
        rateLimit: {
          trackedSessions: rateLimiter.sessionCount,
          currentSession: rateLimiter.getStats(currentSessionId),
        },
      };
    }});
  }

  // ── Gateway methods ────────────────────────────────────────
  async function statusRpc() {
    const sessionStats = stats.getSession(currentSessionId);
    return {
      plugin: "ClawGuard",
      version: "0.1.0",
      mode: policyEngine.mode,
      fallbackMode: policyEngine.isFallbackMode,
      integrity: policyEngine.integrityOk,
      rules: getRuleStats(),
      auditDir: auditLog.dir,
      policySummary: policyEngine.getSummary(),
      activeSessions: sessionCache.size,
      rateLimit: rateLimiter.getStats(currentSessionId),
      currentSession: sessionStats,
    };
  }

  async function configRpc(params: { action: string }) {
    if (params?.action === "reload") {
      policyEngine.reload();
      reloadRules();
      return { success: true, mode: policyEngine.mode, fallback: policyEngine.isFallbackMode, rules: getRuleStats() };
    }
    return {
      mode: policyEngine.mode,
      fallbackMode: policyEngine.isFallbackMode,
      rules: getRuleStats(),
      policyFile: policyEngine.getSummary(),
      auditDir: auditLog.dir,
    };
  }

  if (typeof api.registerGatewayMethod === "function") {
    api.registerGatewayMethod("clawguard.status", statusRpc);
    api.registerGatewayMethod("clawguard.config", configRpc);
    api.registerGatewayMethod("clawguard.report", async (params?: { type?: string }) => {
      if (params?.type === "weekly") {
        return await stats.generateReport();
      }
      return {
        sessions: stats.allSessions,
        totalSessions: stats.sessionCount,
        heatmap: await stats.generateHeatmap(),
      };
    });
  }

  console.log("[ClawGuard] Plugin ready ✓");
}

// Gateway expects a { id, name, description, register } object.
// wrap initPlugin as the register callback.
export default {
  id: "clawguard",
  name: "ClawGuard",
  description: "OpenClaw security plugin — runtime tool call interception, command-level allow/deny/approve, bypass detection, file/network path rules, and audit logging",
  register(api: any) {
    initPlugin(api);
  },
};

// ── Tool Handlers ────────────────────────────────────────────

function handleExec(event: any, ctx: any): BeforeToolCallResult {
  const { command, isScript } = extractCommand(event.params);

  if (!command) {
    return; // No command to check — allow
  }

  // Step 1: Bypass detection (HIGH severity → DENY immediately)
  const bypassCheck = checkBypass(command);
  if (bypassCheck && bypassCheck.severity === "high") {
    logDecision("DENY", command, bypassCheck.reason);
    if (policyEngine.mode === "supervised") {
      return {
        requireApproval: {
          title: "🚫 编码绕过检测",
          description: `📂 ${process.cwd()} | ⏱️ 30秒\n\`${command.slice(0, 200)}\`\n📌 ${bypassCheck.reason}`,
          sessionKey: currentSessionId,
          agentId: ctx?.agentId ?? null,
          severity: "critical",
          timeoutMs: 30000,
          timeoutBehavior: "deny",
        },
      };
    }
    return { block: true, blockReason: bypassCheck.reason };
  }

  // Medium/low bypass → log warning but continue to rule check
  if (bypassCheck) {
    console.warn(`[ClawGuard] ${bypassCheck.reason} (command: "${command.slice(0, 80)}")`);
  }

  // Step 2: Rule integrity check — block all if denylist is missing
  if (!isRuleIntegrityOK()) {
    logDecision("DENY", command, "规则文件缺失");
    return { block: true, blockReason: "🔴 安全规则缺失——denylist.json 为空或损坏，所有 exec 命令已拦截" };
  }

  // Step 3: Policy engine check
  const policyResult = policyEngine.checkCommand(command);
  if (policyResult === "allow") {
    logDecision("ALLOW", command, "policy allow");
    return; // Allow
  }
  if (policyResult === "deny") {
    logDecision("DENY", command, "Policy 拒绝");
    return { block: true, blockReason: "🚫 安全策略拒绝——命令不在允许列表中" };
  }

  // Step 3: Three-tier rule engine
  const result = checkCommand(command);

  switch (result.action) {
    case "deny": {
      logDecision("DENY", command, result.reason);
      return { block: true, blockReason: result.reason };
    }

    case "allow": {
      // In enforce mode, unknown commands are denied by default
      if (policyEngine.mode === "enforce" && result.reason === "未匹配任何规则（默认放行）") {
        logDecision("DENY", command, "enforce 模式——未在白名单");
        return { block: true, blockReason: "🔴 enforce 模式——命令未在白名单中，已拦截" };
      }
      logDecision("ALLOW", command, result.reason);
      return; // Allow
    }

    case "approve": {
      logDecision("APPROVE", command, result.reason);

      if (policyEngine.mode === "enforce") {
        // In enforce mode, approve becomes deny
        return {
          block: true,
          blockReason: `🔶 ${result.reason}（enforce 模式——操作被拦截。如需执行，请切换为 supervised 模式并手动审批）`,
        };
      }

      // Supervised mode: require approval
      // Fallback: if SDK doesn't support requireApproval, block with message
      return {
        requireApproval: {
          title: "🖥 执行命令",
          description: `📂 ${process.cwd()} | ⏱️ 3分钟\n\`${command.slice(0, 300)}\`\n📌 ${result.reason}`,
          sessionKey: currentSessionId,
          agentId: ctx?.agentId ?? null,
          severity: "warning",
          timeoutMs: 180000,
          timeoutBehavior: "deny",
          onResolution: async (decision: string) => {
            if (decision === "allow-always") {
              const { command: cmd } = extractCommand(event.params);
              if (cmd) {
                addApproval(currentSessionId, `exec:${cmd}`);
                console.log(`[ClawGuard] 🔖 会话内记住审批: exec:${cmd.slice(0, 60)}`);
              }
            }
          },
        },
      };
    }

    default:
      return; // Unknown action — allow
  }
}

function handleFileWrite(event: any, ctx: any): BeforeToolCallResult {
  const filePath = event.params?.path || event.params?.file || event.params?.filePath || "";
  if (typeof filePath !== "string" || !filePath) {
    return; // No path — allow
  }

  // Step 1: Policy engine check (policy.ini allow_write / deny_write rules)
  const policyResult = policyEngine.checkWritePath(filePath);
  if (policyResult === "allow") return;
  if (policyResult === "deny") return { block: true, blockReason: "🚫 策略拒绝——写入路径不在允许列表中" };

  // Step 2: File rules check
  const result = checkFileWrite(filePath);

  switch (result.action) {
    case "deny":
      return { block: true, blockReason: result.reason };
    case "approve":
      if (policyEngine.mode === "enforce") {
        return { block: true, blockReason: `🔶 写入路径需审批: ${result.path}` };
      }
      return {
        requireApproval: {
          title: "🔶 文件写入需审批",
          description: `📂 ${process.cwd()} | ⏱️ 3分钟\n📁 ${result.normalizedPath}\n📌 ${result.reason}`,
          sessionKey: currentSessionId,
          agentId: ctx?.agentId ?? null,
          severity: "warning",
          timeoutMs: 180000,
          timeoutBehavior: "deny",
          onResolution: async (decision: string) => {
            if (decision === "allow-always") {
              addApproval(currentSessionId, `file:${filePath}`);
              console.log(`[ClawGuard] 🔖 会话内记住审批: file:${filePath}`);
            }
          },
        },
      };
    default:
      return; // allow
  }
}

function handleFileRead(event: any, ctx: any): BeforeToolCallResult {
  const filePath = event.params?.path || event.params?.file || event.params?.filePath || "";
  if (typeof filePath !== "string" || !filePath) {
    return; // No path — allow
  }

  const result = checkFileRead(filePath);

  switch (result.action) {
    case "deny":
      return { block: true, blockReason: result.reason };
    case "approve":
      if (policyEngine.mode === "enforce") {
        return { block: true, blockReason: `🔶 读取敏感路径需审批: ${result.path}` };
      }
      // For reads, approve is less strict — just log a warning
      console.warn(`[ClawGuard] Reading sensitive path: ${result.normalizedPath}`);
      return; // Allow reads by default, log for audit
    default:
      return; // allow
  }
}

function handleNetwork(event: any, ctx: any): BeforeToolCallResult {
  // Handle web_fetch / http_request / fetch
  const url = event.params?.url || event.params?.uri || "";
  if (typeof url !== "string" || !url) {
    // No URL — allow (might be a low-level tool)
    return;
  }

  // Step 1: Policy engine check (policy.ini allow_domain rules)
  const policyResult = policyEngine.checkDomain(url);
  if (policyResult === "allow") return;
  if (policyResult === "deny") return { block: true, blockReason: "🚫 策略拒绝——域名不在允许列表中" };

  // Step 2: Network rules check
  const result = checkDomain(url);

  switch (result.action) {
    case "deny":
      return { block: true, blockReason: result.reason };
    case "approve":
      if (policyEngine.mode === "enforce") {
        return { block: true, blockReason: `🔶 域名需审批: ${result.domain}` };
      }
      return {
        requireApproval: {
          title: "🔶 网络请求需审批",
          description: `📂 ${process.cwd()} | ⏱️ 3分钟\n🌐 ${result.domain}\n📌 ${result.reason}`,
          sessionKey: currentSessionId,
          agentId: ctx?.agentId ?? null,
          severity: "warning",
          timeoutMs: 180000,
          timeoutBehavior: "deny",
          onResolution: async (decision: string) => {
            if (decision === "allow-always") {
              addApproval(currentSessionId, `net:${url}`);
              console.log(`[ClawGuard] 🔖 会话内记住审批: net:${url}`);
            }
          },
        },
      };
    default:
      return; // allow
  }
}

// ── Decision Logging Helper ──────────────────────────────────
// ⚠️ 仅用于 exec 路径的决策日志——内部调用 rateLimiter.recordExec() 和
// stats.recordCall("exec", ...)。README等只读工具不应通过此处，应直接 console.log。

function logDecision(decision: string, command: string, reason: string): void {
  const emoji = decision === "DENY" ? "🚫" : decision === "APPROVE" ? "🔶" : "✅";
  const safeCmd = auditLog.sanitize(command.slice(0, 80));
  console.log(`[ClawGuard] ${emoji} ${decision} | ${reason} | cmd="${safeCmd}"`);

  // Update rate limiter
  if (decision === "DENY") {
    rateLimiter.recordDeny(currentSessionId);
    stats.recordDeny(currentSessionId, command);
  } else if (decision === "ALLOW") {
    rateLimiter.recordAllow(currentSessionId);
    rateLimiter.recordExec(currentSessionId);
    stats.recordCall(currentSessionId, "exec", command);
  } else if (decision === "APPROVE") {
    stats.recordApprove(currentSessionId);
    stats.recordCall(currentSessionId, "exec", command);
  }
}
