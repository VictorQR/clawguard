/**
 * ClawGuard — Bypass Detection
 *
 * Detects encoding/obfuscation techniques that try to evade pattern-based rules.
 */
import type { BypassCheck } from "./types.js";

export function checkBypass(command: string): BypassCheck | null {
  const cmd = command.trim();

  // base64 → sh pipeline chain (highest severity)
  if (/base64\s+-d\s*\|.*(?:bash|sh|python|perl)/.test(cmd)) {
    return {
      detected: true,
      severity: "high",
      reason: "🚫 base64 decode 管道到 shell——编码绕过",
    };
  }

  // base64 decode followed by execution (any form)
  if (/base64\s+(-d|--decode)/.test(cmd) && /(?:bash|sh|python|perl|node)\b/.test(cmd)) {
    return {
      detected: true,
      severity: "high",
      reason: "🚫 base64 解码后执行——编码绕过",
    };
  }

  // eval execution — dynamic code execution
  // Covers: eval(...), eval "$(...)", eval '$(...)', eval `...`
  if (/\beval\s*(?:\(|\s*['"`]?(?:\$|\(|"|'))/.test(cmd)) {
    return {
      detected: true,
      severity: "high",
      reason: "🚫 eval 动态代码执行——编码绕过",
    };
  }

  // Single-quote / double-quote injection (disrupt pattern matching)
  if (/ba'sh'|ba"sh"|b\\ash/.test(cmd)) {
    return {
      detected: true,
      severity: "medium",
      reason: "⚠️ 命令混淆绕过尝试（引号分隔）",
    };
  }

  // Backslash continuation — splits command across lines
  if (/\\$/.test(cmd) || /\\\n/.test(cmd)) {
    return {
      detected: true,
      severity: "medium",
      reason: "⚠️ 反斜杠续行——可能用于绕过模式匹配",
    };
  }

  // Process substitution — indirect file read
  if (/<\(.*\)/.test(cmd)) {
    return {
      detected: true,
      severity: "medium",
      reason: "⚠️ 进程替换——可能用于间接文件读取",
    };
  }

  // Hexadecimal / octal escape in command names
  if (/\$\\(?:x[0-9a-fA-F]{2}|[0-7]{3})/i.test(cmd)) {
    return {
      detected: true,
      severity: "medium",
      reason: "⚠️ 十六进制/八进制转义——命令混淆",
    };
  }

  // Variable-based command execution (indirection)
  if (/\$\{[A-Za-z_][A-Za-z0-9_]*\[@\]?\}/.test(cmd) && !/^(export|echo|env)\s/.test(cmd)) {
    return {
      detected: true,
      severity: "low",
      reason: "⚠️ 变量间接引用——可能的命令混淆",
    };
  }

  return null;
}
