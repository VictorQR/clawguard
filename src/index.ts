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
import { checkCommand, reloadRules, getRuleStats } from "./rules.js";
import { checkBypass } from "./bypass.js";
import { checkFileWrite, checkFileRead } from "./file-rules.js";
import { checkDomain, addAllowedDomain } from "./network-rules.js";
import { PolicyEngine } from "./policy.js";
import { AuditLogger } from "./audit.js";
import type {
  BeforeToolCallResult,
  ClawGuardMode,
  ClawGuardSession,
  AuditEntry,
} from "./types.js";

// ── Global State ─────────────────────────────────────────────

const policyEngine = new PolicyEngine();
const auditLog = new AuditLogger();

// Session tracking (maps sessionId → stats)
const sessionCache = new Map<string, ClawGuardSession>();
let currentSessionId = "unknown";

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

// ── Start Time Tracker ───────────────────────────────────────

const callStartTimes = new Map<string, number>();

// ── Plugin Entry Point ───────────────────────────────────────

export default function clawguardPlugin(api: any): void {
  console.log("[ClawGuard] Plugin initializing...");

  // Watch policy file for changes
  policyEngine.watchFile();
  console.log(`[ClawGuard] Mode: ${policyEngine.mode}, Fallback: ${policyEngine.isFallbackMode}`);

  // ── before_tool_call hook (priority=100) ──────────────────

  api.on(
    "before_tool_call",
    async (event: any, _ctx: any) => {
      // Track start time for duration calculation
      const callId = `${event.toolName}:${Date.now()}:${Math.random().toString(36).slice(2, 6)}`;
      callStartTimes.set(callId, Date.now());

      // Store callId on event for after_tool_call
      (event as any).__clawguard_callId = callId;

      // Fallback mode — deny all
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
          blockReason: "⚠️ Policy 文件损坏，已启用 deny-all 安全模式",
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
        }
        return; // allow everything in permissive mode
      }

      // Route to appropriate handler
      try {
        if (EXEC_TOOLS.has(event.toolName)) {
          return handleExec(event, callId);
        }

        if (WRITE_TOOLS.has(event.toolName)) {
          return handleFileWrite(event);
        }

        if (READ_TOOLS.has(event.toolName)) {
          return handleFileRead(event);
        }

        if (NETWORK_TOOLS.has(event.toolName) || event.toolName === "web_search") {
          return handleNetwork(event);
        }

        // Tool not in our scope — allow
        return;
      } catch (err) {
        // Fail-open: if our handler crashes, allow the tool call
        console.error("[ClawGuard] before_tool_call handler error:", err);
        return;
      }
    },
    { priority: 100 }
  );

  // ── after_tool_call hook (priority=50) ────────────────────

  api.on(
    "after_tool_call",
    async (event: any) => {
      const callId = (event as any).__clawguard_callId;
      const startTime = callId ? callStartTimes.get(callId) : undefined;
      const durationMs = startTime ? Date.now() - startTime : 0;

      if (callId) {
        callStartTimes.delete(callId);
      }

      // Format result
      let resultStr: string;
      if (event.result === undefined || event.result === null) {
        resultStr = "";
      } else if (typeof event.result === "string") {
        resultStr = event.result;
      } else if (Buffer.isBuffer(event.result)) {
        resultStr = `[Buffer: ${(event.result as Buffer).length} bytes]`;
      } else {
        try {
          resultStr = JSON.stringify(event.result);
        } catch {
          resultStr = String(event.result);
        }
      }

      const entry: AuditEntry = {
        timestamp: new Date().toISOString(),
        toolName: event.toolName,
        params: JSON.stringify(event.params),
        result: resultStr,
        durationMs,
        error: event.error ? String(event.error) : null,
        session: currentSessionId,
      };

      // Add command if exec tool
      if (EXEC_TOOLS.has(event.toolName)) {
        const { command } = extractCommand(event.params);
        if (command) {
          entry.command = command;
        }
      }

      auditLog.append(entry);
    },
    { priority: 50 }
  );

  // ── session_end hook ───────────────────────────────────────

  api.on("session_end", async () => {
    sessionCache.delete(currentSessionId);
    console.log("[ClawGuard] Session ended, cache cleaned");
  });

  // ── Health check service ───────────────────────────────────

  api.registerService("clawguard-health", async () => {
    return {
      status: "ok",
      mode: policyEngine.mode,
      fallback: policyEngine.isFallbackMode,
      rules: getRuleStats(),
      sessions: sessionCache.size,
    };
  });

  // ── Gateway methods ────────────────────────────────────────

  api.registerGatewayMethod("clawguard.status", async () => {
    return {
      plugin: "ClawGuard",
      version: "0.1.0",
      mode: policyEngine.mode,
      fallbackMode: policyEngine.isFallbackMode,
      rules: getRuleStats(),
      auditDir: auditLog.dir,
      policySummary: policyEngine.getSummary(),
      activeSessions: sessionCache.size,
    };
  });

  api.registerGatewayMethod("clawguard.config", async (params: { action: string }) => {
    if (params.action === "reload") {
      policyEngine.reload();
      reloadRules();
      return {
        success: true,
        mode: policyEngine.mode,
        fallback: policyEngine.isFallbackMode,
        rules: getRuleStats(),
      };
    }

    // Default: view config
    return {
      mode: policyEngine.mode,
      fallbackMode: policyEngine.isFallbackMode,
      rules: getRuleStats(),
      policyFile: policyEngine.getSummary(),
      auditDir: auditLog.dir,
    };
  });

  console.log("[ClawGuard] Plugin ready ✓");
}

// ── Tool Handlers ────────────────────────────────────────────

function handleExec(event: any, callId: string): BeforeToolCallResult {
  const { command, isScript } = extractCommand(event.params);

  if (!command) {
    return; // No command to check — allow
  }

  // Step 1: Bypass detection (HIGH severity → DENY immediately)
  const bypassCheck = checkBypass(command);
  if (bypassCheck && bypassCheck.severity === "high") {
    logDecision("DENY", callId, command, bypassCheck.reason, "bypass_detection", event);
    if (policyEngine.mode === "supervised") {
      return {
        requireApproval: {
          title: "🚫 编码绕过检测",
          description: bypassCheck.reason,
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

  // Step 2: Policy engine check
  const policyResult = policyEngine.checkCommand(command);
  if (policyResult === "allow") {
    logDecision("ALLOW", callId, command, "policy allow", "policy_allow", event);
    return; // Allow
  }
  if (policyResult === "deny") {
    logDecision("DENY", callId, command, "Policy 文件回退模式——拒绝", "policy_fallback_deny", event);
    return { block: true, blockReason: "⚠️ Policy 回退模式——命令被拒绝" };
  }

  // Step 3: Three-tier rule engine
  const result = checkCommand(command);

  switch (result.action) {
    case "deny": {
      logDecision("DENY", callId, command, result.reason, result.rule, event);
      return { block: true, blockReason: result.reason };
    }

    case "allow": {
      logDecision("ALLOW", callId, command, result.reason, result.rule, event);
      return; // Allow
    }

    case "approve": {
      logDecision("APPROVE", callId, command, result.reason, result.rule, event);

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
          title: "🔶 操作需审批",
          description: result.reason,
          severity: "warning",
          timeoutMs: 60000,
          timeoutBehavior: "deny",
        },
      };
    }

    default:
      return; // Unknown action — allow
  }
}

function handleFileWrite(event: any): BeforeToolCallResult {
  const filePath = event.params?.path || event.params?.file || event.params?.filePath || "";
  if (typeof filePath !== "string" || !filePath) {
    return; // No path — allow
  }

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
          description: `写入路径: ${result.normalizedPath}\n${result.reason}`,
          severity: "warning",
          timeoutMs: 60000,
          timeoutBehavior: "deny",
        },
      };
    default:
      return; // allow
  }
}

function handleFileRead(event: any): BeforeToolCallResult {
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

function handleNetwork(event: any): BeforeToolCallResult {
  // Handle web_search (domain-based check from params)
  if (event.toolName === "web_search") {
    // web_search uses an internal provider; intercept based on allowed search providers
    return; // Allow web_search — search providers are controlled by the gateway
  }

  // Handle web_fetch / http_request / fetch
  const url = event.params?.url || event.params?.uri || "";
  if (typeof url !== "string" || !url) {
    // No URL — allow (might be a low-level tool)
    return;
  }

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
          description: `域名: ${result.domain}\n${result.reason}`,
          severity: "warning",
          timeoutMs: 60000,
          timeoutBehavior: "deny",
        },
      };
    default:
      return; // allow
  }
}

// ── Decision Logging Helper ──────────────────────────────────

function logDecision(
  decision: string,
  callId: string,
  command: string,
  reason: string,
  rule: string | undefined,
  event: any
): void {
  const emoji = decision === "DENY" ? "🚫" : decision === "APPROVE" ? "🔶" : "✅";
  console.log(`[ClawGuard] ${emoji} ${decision} | ${reason} | cmd="${command.slice(0, 80)}"`);
}
