/**
 * ClawGuard — Rate Limiter
 *
 * Provides burst protection and consecutive-deny escalation
 * to defend against tool call cascades and recursive loops.
 */

// ── Thresholds ───────────────────────────────────────────────

/** 30s sliding window for exec burst detection */
const EXEC_WINDOW_MS = 30_000;

/** Max exec calls per 30s window before burst trigger */
const EXEC_BURST_THRESHOLD = 10;

/** 5 min window for global rate cap (suspected infinite loop) */
const GLOBAL_WINDOW_MS = 5 * 60_000;

/** Max exec calls per 5 min before global block */
const GLOBAL_CAP_THRESHOLD = 50;

/** Consecutive denies before auto-escalation to enforce mode */
const CONSECUTIVE_DENY_THRESHOLD = 3;

/** Pause duration when burst is detected */
const BURST_PAUSE_MS = 30_000;

// ── Types ────────────────────────────────────────────────────

export interface RateCheckResult {
  allowed: boolean;
  reason?: string;
  escalated?: boolean;    // enforce mode auto-triggered
  paused?: boolean;        // burst pause active
}

interface SessionRateState {
  execTimestamps: number[];       // recent exec call timestamps (ms)
  denyCount: number;               // consecutive denies
  burstUntil: number;              // timestamp until burst pause expires (0 = not paused)
  escalated: boolean;              // enforce mode auto-triggered
  lastExecTime: number;            // last exec timestamp
}

// ── Rate Limiter ─────────────────────────────────────────────

export class RateLimiter {
  private sessions = new Map<string, SessionRateState>();

  /** Check if an exec call is allowed under current rate limits */
  checkExecRate(sessionKey: string): RateCheckResult {
    const now = Date.now();
    const state = this.getOrCreate(sessionKey);

    // 1. Global cap check (5 min window)
    const globalCutoff = now - GLOBAL_WINDOW_MS;
    const globalCount = state.execTimestamps.filter(t => t >= globalCutoff).length;
    if (globalCount >= GLOBAL_CAP_THRESHOLD) {
      return {
        allowed: false,
        reason: `🚫 全局速率上限: 5分钟内 ${globalCount} 次 exec 调用，疑似递归死循环，已阻断`,
        escalated: true,
      };
    }

    // 2. Burst check (30s window)
    if (state.burstUntil > now) {
      const remaining = Math.ceil((state.burstUntil - now) / 1000);
      return {
        allowed: false,
        reason: `⏳ 调用过于频繁，请等待 ${remaining}s`,
        paused: true,
      };
    }

    // Count recent execs
    const windowCutoff = now - EXEC_WINDOW_MS;
    const recentCount = state.execTimestamps.filter(t => t >= windowCutoff).length;

    if (recentCount >= EXEC_BURST_THRESHOLD) {
      state.burstUntil = now + BURST_PAUSE_MS;
      return {
        allowed: false,
        reason: `⚠️ 30s 内 ${recentCount} 次 exec 调用，速率限制触发，暂停 ${BURST_PAUSE_MS / 1000}s`,
        paused: true,
      };
    }

    return { allowed: true };
  }

  /** Record a successful exec call */
  recordExec(sessionKey: string): void {
    const now = Date.now();
    const state = this.getOrCreate(sessionKey);
    state.execTimestamps.push(now);
    state.lastExecTime = now;
    // Trim old timestamps (keep last GLOBAL_WINDOW_MS)
    const cutoff = now - GLOBAL_WINDOW_MS;
    state.execTimestamps = state.execTimestamps.filter(t => t >= cutoff);
  }

  /** Record a deny decision, check for consecutive deny escalation */
  recordDeny(sessionKey: string): RateCheckResult {
    const state = this.getOrCreate(sessionKey);
    state.denyCount += 1;

    if (state.denyCount >= CONSECUTIVE_DENY_THRESHOLD && !state.escalated) {
      state.escalated = true;
      return {
        allowed: false,
        reason: `🔴 连续 ${state.denyCount} 次操作被拒绝，已自动切换 enforce 模式`,
        escalated: true,
      };
    }

    return { allowed: true };
  }

  /** Reset deny counter (on successful allow) */
  recordAllow(sessionKey: string): void {
    const state = this.sessions.get(sessionKey);
    if (state) {
      state.denyCount = 0;
    }
  }

  /** Check if session is in escalated (enforce) mode */
  isEscalated(sessionKey: string): boolean {
    return this.sessions.get(sessionKey)?.escalated ?? false;
  }

  /** Get stats for a session */
  getStats(sessionKey: string) {
    const state = this.sessions.get(sessionKey);
    if (!state) return null;
    const now = Date.now();
    const windowCutoff = now - EXEC_WINDOW_MS;
    const recentCount = state.execTimestamps.filter(t => t >= windowCutoff).length;
    return {
      recentExecs: recentCount,
      denyCount: state.denyCount,
      escalated: state.escalated,
      paused: state.burstUntil > now,
      pauseRemaining: Math.max(0, state.burstUntil - now),
    };
  }

  /** Reset all state for a session */
  reset(sessionKey: string): void {
    this.sessions.delete(sessionKey);
  }

  /** Get total tracked sessions */
  get sessionCount(): number {
    return this.sessions.size;
  }

  private getOrCreate(sessionKey: string): SessionRateState {
    if (!this.sessions.has(sessionKey)) {
      this.sessions.set(sessionKey, {
        execTimestamps: [],
        denyCount: 0,
        burstUntil: 0,
        escalated: false,
        lastExecTime: 0,
      });
    }
    return this.sessions.get(sessionKey)!;
  }
}
