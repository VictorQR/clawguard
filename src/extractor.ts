/**
 * ClawGuard — Command Extractor
 *
 * Unifies four param formats used across OpenClaw versions/channels:
 *   command, cmd, script, args
 */
import type { ExtractionResult } from "./types.js";

export function extractCommand(params: Record<string, unknown>): ExtractionResult {
  // Format 1: command (string) — most common
  if (params.command && typeof params.command === "string") {
    return { command: params.command.trim(), isScript: false };
  }

  // Format 2: cmd (string)
  if (params.cmd && typeof params.cmd === "string") {
    return { command: params.cmd.trim(), isScript: false };
  }

  // Format 3: script (string) — exec(script="...")
  if (params.script && typeof params.script === "string") {
    return { command: params.script.trim(), isScript: true };
  }

  // Format 4: args (string[]) — argv-like
  if (Array.isArray(params.args)) {
    const args = params.args.map((a) => String(a));
    return { command: args.join(" "), isScript: false };
  }

  return { command: "", isScript: false };
}

/**
 * Split a command string into individual pipeline segments.
 * Respects quoted strings to avoid splitting inside quotes.
 */
export function splitPipeline(command: string): string[] {
  const segments: string[] = [];
  let current = "";
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    const prev = i > 0 ? command[i - 1] : "";

    if (ch === "'" && !inDouble && prev !== "\\") {
      inSingle = !inSingle;
      current += ch;
    } else if (ch === '"' && !inSingle && prev !== "\\") {
      inDouble = !inDouble;
      current += ch;
    } else if (ch === "|" && !inSingle && !inDouble) {
      // Check for || (OR operator) — not a pipeline
      if (i + 1 < command.length && command[i + 1] === "|") {
        current += "||";
        i++;
      } else {
        segments.push(current.trim());
        current = "";
      }
    } else {
      current += ch;
    }
  }

  if (current.trim()) {
    segments.push(current.trim());
  }

  return segments;
}
