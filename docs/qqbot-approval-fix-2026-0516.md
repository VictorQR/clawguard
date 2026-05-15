# QQBot 审批格式回退 Bug 修复记录

## 概述

| 字段 | 值 |
|------|------|
| **Bug ID** | BUG-2026-0516-01 |
| **影响版本** | ClawGuard ≥ v0.3.3 |
| **影响组件** | QQBot approval renderer (`handler-runtime-ZgvjnyoH.js`) |
| **严重程度** | Medium |
| **修复状态** | ✅ 已修复（本地临时补丁） |

---

## 问题描述

ClawGuard 发起的插件审批请求，在 QQ 中渲染时格式回退为旧的 `🔐 命令执行审批` 样式，而不是预期的 `🟡 审批请求` + `title` + `description` 格式。

**错误样式示例：**
```
🔐 命令执行审批
🤖 Agent: main
⏱️ 超时: 180 秒
```

**预期样式（修复后）：**
```
🟡 审批请求

📋 执行命令
📝 📂 /home/victor | ⏱️ 3分钟
`whoami`
📌 系统命令执行
🔌 插件: clawguard
🤖 Agent: main

⏱️ 超时: 180 秒
```

---

## 根因分析

### 路由判断逻辑错误

QQBot 审批处理器使用 `isExecRequest()` 函数决定使用哪个渲染器：

```javascript
// 修复前（错误）
function isExecRequest(request) {
    return "expiresAtMs" in request;  // ❌ 不可靠
}
```

当返回 `true` 时调用 `buildExecApprovalText()`（exec 审批样式），返回 `false` 时调用 `buildPluginApprovalText()`（插件审批样式）。

### 问题链路

1. ClawGuard 通过 `before_tool_call` hook 返回 `requireApproval` 对象：
   ```javascript
   {
     title: "🖥 执行命令",
     description: "📂 ${process.cwd()} | ⏱️ 3分钟\n`${command}`\n📌 ...",
     severity: "warning",
     timeoutMs: 180000,
     pluginId: "clawguard",
     sessionKey: currentSessionId,
     agentId: ctx?.agentId ?? null,
     onResolution: async (decision) => { ... }
   }
   ```

2. `requestPluginToolApproval()` 调用 `plugin.approval.request` 时，会生成审批 ID 为 `plugin:${randomUUID()}` 格式。

3. SDK 层创建 `PluginApprovalRequest`，**可能未设置 `expiresAtMs` 字段**（或未传递给下游）。

4. QQBot 的 `isExecRequest()` 检查 `"expiresAtMs" in request`：
   - 如果 `expiresAtMs` 未被正确传递 → 检查失败 → 判定为 `false`
   - 但 `request.id` 实际为 `plugin:xxx` → 应该走插件审批路径

5. 最终错误路由到 `buildExecApprovalText()` → 显示旧格式。

### 核心原因

`"expiresAtMs" in request` 这个检查不可靠——`expiresAtMs` 是 SDK 在创建审批记录时自动计算的值，但如果底层数据流中该字段未正确传递，判断就会失败。

**正确的判断方式：直接检查审批 ID 前缀**

```javascript
// ✅ 正确（修复后）
function isExecRequest(request) {
    return !request.id.startsWith("plugin:");
}
```

---

## 修复方案

### 修改文件

**路径：** `/home/victor/.openclaw/npm/node_modules/@openclaw/qqbot/dist/handler-runtime-ZgvjnyoH.js`

**位置：** 第 9-11 行，`isExecRequest()` 函数

```javascript
// 修复前
function isExecRequest(request) {
    return "expiresAtMs" in request;
}

// 修复后
function isExecRequest(request) {
    return !request.id.startsWith("plugin:");
}
```

### 验证

修改后，ClawGuard 发起的审批（ID 格式 `plugin:xxx`）将正确路由到 `buildPluginApprovalText()`，显示：
- `🟡` / `🔴` / `🔵` severity 图标
- `📋 title` 标题行
- `📝 description` 描述行
- `🔌 插件:` / `🤖 Agent:` 元数据
- `⏱️ 超时:` 超时提示

---

## 持久化方案（建议）

由于 QQBot 是 `@openclaw/qqbot` 包的一部分（非 ClawGuard 维护范围），此修复应通过以下方式持久化：

1. **向 OpenClaw 官方提交 PR**：将 `isExecRequest()` 的判断逻辑从检查 `expiresAtMs` 改为检查 `request.id.startsWith("plugin:")`
2. **记录此修复**：在 ClawGuard 文档中记录此问题的根因和临时修复方法
3. **监控 QQBot 更新**：若 OpenClaw 后续更新 `handler-runtime-ZgvjnyoH.js`，需重新验证 `isExecRequest()` 是否已修复

---

## 相关文件

| 文件 | 用途 |
|------|------|
| `handler-runtime-ZgvjnyoH.js` | QQBot 审批处理器（问题文件） |
| `approval-cg0SVahb.js` | QQBot 审批渲染器（`buildExecApprovalText` / `buildPluginApprovalText`） |
| `approval-handler-runtime-BgxeRD2b.js` | OpenClaw 审批视图构建器 |
| `plugin-approvals-BiH4NDIm.d.ts` | 插件审批类型定义 |
| `pi-tools.before-tool-call-BmZM4hyt.js` | before_tool_call hook 调度器 |

---

## 时间线

| 时间 | 事件 |
|------|------|
| 2026-05-15 16:24 | 用户首次报告审批格式回退 |
| 2026-05-16 00:30 | 开始根因分析 |
| 2026-05-16 00:34 | 定位到 `isExecRequest()` 判断错误 |
| 2026-05-16 00:34 | 应用本地修复（`request.id.startsWith("plugin:")`） |

---

*文档创建：2026-05-16 | 最后更新：2026-05-16*