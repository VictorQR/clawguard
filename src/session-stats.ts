/**
 * ClawGuard — Session Statistics
 *
 * Per-session counters, hourly heatmap, and report generation.
 */
import {
  readFileSync,
  existsSync,
  renameSync,
  mkdirSync,
  createReadStream,
} from "node:fs";
import { join, dirname } from "node:path";
import { createInterface } from "node:readline";
import { homedir } from "node:os";

// ── Paths ────────────────────────────────────────────────────

const HOME = homedir();
const AUDIT_DIR = join(HOME, ".clawguard", "audit");

// ── Types ────────────────────────────────────────────────────

export interface SessionStats {
  sessionKey: string;
  channel: string;
  commandCount: number;
  denyCount: number;
  approveCount: number;
  bypassDetections: number;
  totalDurationMs: number;
  firstSeen: string;
  lastSeen: string;
  topDenied: Array<{ command: string; count: number }>;
  toolCalls: Record<string, number>; // toolName → count
}

export interface HourlyHeatmap {
  hour: string;   // "HH:00"
  total: number;
  denied: number;
  approved: number;
}

export interface WeeklyReport {
  generated: string;
  period: { from: string; to: string };
  summary: {
    totalCommands: number;
    totalDenied: number;
    totalApproved: number;
    denyRate: string;
    activeSessions: number;
    topDeniedCommands: Array<{ command: string; count: number }>;
    heatmap: HourlyHeatmap[];
  };
  sessions: SessionStats[];
}

// ── Stats Collector ──────────────────────────────────────────

export class StatsCollector {
  private sessions = new Map<string, SessionStats>();

  /** Get or create session stats */
  private getOrCreate(sessionKey: string): SessionStats {
    if (!this.sessions.has(sessionKey)) {
      const channel = this.extractChannel(sessionKey);
      this.sessions.set(sessionKey, {
        sessionKey,
        channel,
        commandCount: 0,
        denyCount: 0,
        approveCount: 0,
        bypassDetections: 0,
        totalDurationMs: 0,
        firstSeen: new Date().toISOString(),
        lastSeen: new Date().toISOString(),
        topDenied: [],
        toolCalls: {},
      });
    }
    return this.sessions.get(sessionKey)!;
  }

  /** Record a tool call */
  recordCall(sessionKey: string, toolName: string, command?: string): void {
    const s = this.getOrCreate(sessionKey);
    s.commandCount += 1;
    s.lastSeen = new Date().toISOString();
    s.toolCalls[toolName] = (s.toolCalls[toolName] || 0) + 1;

    if (command) {
      this.recordCommand(s, command);
    }
  }

  /** Record a deny decision */
  recordDeny(sessionKey: string, command?: string): void {
    const s = this.getOrCreate(sessionKey);
    s.denyCount += 1;
    s.lastSeen = new Date().toISOString();

    if (command) {
      // Track top denied commands
      const existing = s.topDenied.find(d => d.command === command);
      if (existing) {
        existing.count += 1;
      } else {
        s.topDenied.push({ command, count: 1 });
      }
      // Keep top 10
      s.topDenied.sort((a, b) => b.count - a.count);
      if (s.topDenied.length > 10) s.topDenied.length = 10;
    }
  }

  /** Record an approval request */
  recordApprove(sessionKey: string): void {
    const s = this.getOrCreate(sessionKey);
    s.approveCount += 1;
    s.lastSeen = new Date().toISOString();
  }

  /** Record bypass detection */
  recordBypass(sessionKey: string): void {
    const s = this.getOrCreate(sessionKey);
    s.bypassDetections += 1;
    s.lastSeen = new Date().toISOString();
  }

  /** Record tool call duration */
  recordDuration(sessionKey: string, durationMs: number): void {
    const s = this.getOrCreate(sessionKey);
    s.totalDurationMs += durationMs;
  }

  /** Reset a session */
  reset(sessionKey: string): void {
    this.sessions.delete(sessionKey);
  }

  /** Get stats for a session */
  getSession(sessionKey: string): SessionStats | null {
    return this.sessions.get(sessionKey) || null;
  }

  /** Get all active sessions */
  get allSessions(): SessionStats[] {
    return Array.from(this.sessions.values());
  }

  /** Get session count */
  get sessionCount(): number {
    return this.sessions.size;
  }

  /** Generate an hourly heatmap from audit log (streaming) */
  async generateHeatmap(date?: string): Promise<HourlyHeatmap[]> {
    const target = date || new Date().toISOString().slice(0, 10);
    const file = join(AUDIT_DIR, `${target}.jsonl`);

    if (!existsSync(file)) return [];

    const heatmap: Record<string, { total: number; denied: number; approved: number }> = {};
    for (let h = 0; h < 24; h++) {
      const key = `${String(h).padStart(2, "0")}:00`;
      heatmap[key] = { total: 0, denied: 0, approved: 0 };
    }

    try {
      const rl = createInterface({
        input: createReadStream(file, { encoding: "utf-8" }),
        crlfDelay: Infinity,
      });
      for await (const line of rl) {
        if (!line.trim()) continue;
        try {
          const entry = JSON.parse(line);
          const hour = entry.timestamp?.slice(11, 13) || "00";
          const key = `${hour}:00`;
          if (heatmap[key]) {
            heatmap[key].total += 1;
            if (entry.decision === "DENY") heatmap[key].denied += 1;
            if (entry.decision === "APPROVE") heatmap[key].approved += 1;
          }
        } catch { /* skip malformed lines */ }
      }
    } catch { /* file read error */ }

    return Object.entries(heatmap).map(([hour, data]) => ({
      hour,
      ...data,
    }));
  }

  /** Synchronous heatmap (non-streaming, for backward compat) */
  generateHeatmapSync(date?: string): HourlyHeatmap[] {
    const target = date || new Date().toISOString().slice(0, 10);
    const file = join(AUDIT_DIR, `${target}.jsonl`);

    if (!existsSync(file)) return [];

    const heatmap: Record<string, { total: number; denied: number; approved: number }> = {};
    for (let h = 0; h < 24; h++) {
      const key = `${String(h).padStart(2, "0")}:00`;
      heatmap[key] = { total: 0, denied: 0, approved: 0 };
    }

    try {
      const content = readFileSync(file, "utf-8");
      const lines = content.trim().split("\n");
      for (const line of lines) {
        try {
          const entry = JSON.parse(line);
          const hour = entry.timestamp?.slice(11, 13) || "00";
          const key = `${hour}:00`;
          if (heatmap[key]) {
            heatmap[key].total += 1;
            if (entry.decision === "DENY") heatmap[key].denied += 1;
            if (entry.decision === "APPROVE") heatmap[key].approved += 1;
          }
        } catch { /* skip malformed lines */ }
      }
    } catch { /* file read error */ }

    return Object.entries(heatmap).map(([hour, data]) => ({
      hour,
      ...data,
    }));
  }

  /**
   * Generate a weekly report using streaming reads.
   * Reads 7 days of JSONL audit logs line-by-line without loading all entries into memory.
   */
  async generateReport(): Promise<WeeklyReport> {
    const now = new Date();
    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

    // Aggregators (incremental, not array-backed)
    let totalCommands = 0;
    let totalDenied = 0;
    let totalApproved = 0;
    const sessions = new Set<string>();
    const denyMap = new Map<string, number>();

    for (let d = 0; d < 7; d++) {
      const date = new Date(weekAgo.getTime() + d * 24 * 60 * 60 * 1000);
      const dateStr = date.toISOString().slice(0, 10);
      const file = join(AUDIT_DIR, `${dateStr}.jsonl`);
      if (!existsSync(file)) continue;

      try {
        const rl = createInterface({
          input: createReadStream(file, { encoding: "utf-8" }),
          crlfDelay: Infinity,
        });
        for await (const line of rl) {
          if (!line.trim()) continue;
          try {
            const e = JSON.parse(line);
            totalCommands += 1;
            if (e.decision === "DENY") totalDenied += 1;
            if (e.decision === "APPROVE") totalApproved += 1;
            if (e.session) sessions.add(e.session);
            if (e.decision === "DENY" && e.command) {
              denyMap.set(e.command, (denyMap.get(e.command) || 0) + 1);
            }
          } catch { /* skip malformed line */ }
        }
      } catch { /* skip unreadable file */ }
    }

    const topDenied = Array.from(denyMap.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([command, count]) => ({ command: command.slice(0, 80), count }));

    const heatmap = await this.generateHeatmap(now.toISOString().slice(0, 10));

    return {
      generated: now.toISOString(),
      period: {
        from: weekAgo.toISOString().slice(0, 10),
        to: now.toISOString().slice(0, 10),
      },
      summary: {
        totalCommands,
        totalDenied,
        totalApproved,
        denyRate: totalCommands > 0
          ? `${((totalDenied / totalCommands) * 100).toFixed(1)}%`
          : "0%",
        activeSessions: sessions.size,
        topDeniedCommands: topDenied,
        heatmap,
      },
      sessions: this.allSessions,
    };
  }

  /** Extract channel type from sessionKey */
  private extractChannel(sessionKey: string): string {
    const parts = sessionKey.split(":");
    if (parts.length >= 4) return parts[3];
    if (sessionKey.includes("terminal")) return "terminal";
    if (sessionKey.includes("cron")) return "cron";
    return "unknown";
  }

  /** Track a command string in the session (helper for top denied) */
  private recordCommand(s: SessionStats, command: string): void {
    // Only track for deny recording later; this is a no-op for now
  }
}
