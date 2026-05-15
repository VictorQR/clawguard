# 🛡️ ClawGuard — OpenClaw Runtime Security Plugin

> 轻量级 OpenClaw 安全插件，基于 `before_tool_call` 钩子实现运行时工具调用拦截。
> 零外部依赖（仅 minimatch 用于路径匹配）、全本地决策、进程内运行。
>
> 📦 **ClawHub**: [`clawhub:@victorqr/clawguard`](https://clawhub.com/@victorqr/clawguard)

---

## 📋 目录

- [功能矩阵](#-功能矩阵)
- [快速开始](#-快速开始)
- [规则引擎](#-规则引擎)
- [速率限制](#-速率限制--级联防护)
- [Guardrail 自防护](#-guardrail-自防护)
- [通道感知](#-通道感知策略)
- [会话管理](#-会话管理)
- [审计日志](#-审计日志)
- [统计与周报](#-统计与周报)
- [配置详解](#-配置详解)
- [架构](#-架构)
- [API 参考](#-api-参考)
- [测试](#-测试)
- [许可证](#-许可证)

---

## 🎯 功能矩阵

| 模块 | 说明 | 版本 |
|:-----|:-----|:--:|
| **三段式规则引擎** | DENY > ALLOW > APPROVE 三级优先级 | v0.1.0 |
| **编码绕过检测** | base64 管道、eval 动态执行、反弹 Shell | v0.1.0 |
| **文件路径规则** | 读/写分开评估，glob 通配符，symlink 解析 | v0.1.0 |
| **网络域名白名单** | 内网自动放行，未知域名默认拒绝 | v0.1.0 |
| **Policy 热加载** | INI 格式，写时复制+原子 rename，损坏兜底 | v0.1.0 |
| **审计日志** | 脱敏 JSONL，90 天自动轮转 | v0.1.0 |
| **会话审批记忆** | `allow-always` 会话内记住，`session_end` 清除 | v0.1.1 |
| **会话追踪** | `ctx.sessionKey` 替代硬编码 `"unknown"` | v0.1.1 |
| **速率限制** | 30s burst / 5min global cap / 连续拒绝升级 | v0.2.0 |
| **Guardrail 自防护** | 进程保护、policy.ini SHA256 完整性校验 | v0.2.0 |
| **通道感知策略** | 群聊/私聊/Cron 按通道分级 | v0.2.0 |
| **统计与周报** | 每会话统计、热力图、`clawguard.report` | v0.2.0 |
| 🔴 **崩溃修复** | ESM compat、异常兜底、敏感信息脱敏 | v0.3.0 |
| 🔴 **安全加固** | 路径遍历防护、死代码激活、JSON 完整性校验 | v0.3.0 |
| 🔴 **enforce 默认拒绝** | 未知命令在 enforce 模式下直接拦截 | v0.3.0 |
| 🔴 **路径写保护** | `.clawguard/` `openclaw.json` 防覆写 | v0.3.0 |
| 🟡 **纵深防御** | Session TTL、escalate 可逆、审批上限 FIFO | v0.3.0 |
| 🟡 **工具扩展** | process/sessions_spawn 纳入拦截 | v0.3.0 |
| 🟡 **流式报告** | Report 流式读取避免 OOM | v0.3.0 |
| 🟡 **网络审批** | 未知域名弹窗审批 + 云元数据拦截 | v0.3.1 |
| 🟡 **绕过外置** | 检测模式迁至 JSON，消除安全扫描误判 | v0.3.1 |
| 🟢 **QQ审批详细化** | title/description/agentId/sessionKey 全字段推送，description 显示工作目录/原因 | v0.3.3 |
| 🟢 **cwd 回退修复** | process.cwd() 直读系统目录，解决 qqbot hook cwd 缺失问题 | v0.3.3 |
| 🟢 **只读工具放行** | web_fetch/search/memory 等 10 个工具免审批 | v0.3.2 |
| 🟢 **Fallback 分级** | Policy 损坏时拒绝写/执行，允许只读自愈诊断 | v0.3.2 |
| 🟢 **工具扩展** | sessions_list / sessions_history 加入只读白名单 | v0.3.2 |

---

## 🚀 快速开始

### 安装

```bash
# 方式一：ClawHub（推荐）
openclaw plugins install clawhub:@victorqr/clawguard

# 更新
openclaw plugins update clawguard
```

### 验证安装

```bash
# 查看插件状态
openclaw plugins list | grep clawguard

# 完整状态（含速率限制、完整性、会话统计）
curl -s http://127.0.0.1:18789/gateway/clawguard.status | jq
```

### 输出示例

```json
{
  "plugin": "ClawGuard",
  "version": "0.3.2",
  "mode": "supervised",
  "fallbackMode": false,
  "integrity": true,
  "rules": { "deny": 33, "allow": 45, "approve": 31 },
  "auditDir": "/home/victor/.clawguard/audit",
  "activeSessions": 1,
  "rateLimit": {
    "recentExecs": 3,
    "denyCount": 0,
    "escalated": false,
    "paused": false
  },
  "currentSession": {
    "channel": "direct",
    "commandCount": 15,
    "denyCount": 0,
    "approveCount": 0
  }
}
```

---

## 🔐 规则引擎

### 三张规则表

#### 🚫 DENY — 彻底拦截（33 条）

拒绝优先级最高，命中后立即阻断，不可审批绕过。

| 类别 | 示例 | 数量 |
|:-----|:-----|:--:|
| 递归删除 | `rm -rf /`, `rm -rf ~`, `rm -rf *` | 5 |
| 磁盘操作 | `mkfs`, `fdisk`, `dd if=/dev/sda` | 3 |
| Fork Bomb | `:(){ :\|:& };:` | 1 |
| 远程代码执行 | `curl ... \| bash`, `wget ... \| sh` | 3 |
| 反弹 Shell | `bash -i >& /dev/tcp`, `nc -e /bin/bash` | 4 |
| 凭据窃取 | `cat /etc/shadow`, `grep -r password` | 3 |
| 编码绕过 | `base64 -d \| sh`, `eval $(...)`, `eval \`` | 3 |
| 环境注入 | `PATH=`, `LD_PRELOAD=`, `PYTHONPATH=` | 1 |
| 容器逃逸 | `docker run --privileged`, `-v /:/host` | 2 |
| 持久化后门 | `echo >> /etc/crontab` | 2 |
| 🆕 Guardrail 防护 | `kill ... openclaw`, 篡改 `~/.clawguard/` | 4 |
| 权限提升 | `chmod 777 /`, `chown -R /` | 2 |

#### ✅ ALLOW — 直接放行（45 条）

安全命令白名单，跳过所有后续检查，无延时。

| 类别 | 示例 |
|:-----|:-----|
| 只读文件 | `ls`, `cat`, `head`, `tail`, `file`, `stat` |
| 文件导航 | `cd`, `pwd`, `which`, `whoami`, `realpath` |
| Git 只读 | `git status`, `git log`, `git diff`, `git branch` |
| 包查看 | `pip list`, `pip show`, `npm list` |
| 系统回收站 | `gio trash` (rm 唯一安全替代) |
| 文本处理 | `grep`, `sed`, `awk`, `sort`, `wc`, `cut`, `tr` |
| 进程查看 | `ps`, `top`, `free`, `df`, `du` |
| 脚本运行 | `python3 *.py`, `node *.js`, `npx tsx` |
| 条件创建 | `mkdir -p`, `echo`, `date`, `env` |

#### 🔶 APPROVE — 需审批（32 条）

触发审批弹窗，用户可选择：**仅此次** / **始终允许** / **拒绝**。

| 类别 | 审批超时 | 示例 |
|:-----|:--:|:-----|
| 文件删除 | 180s | `rm` (非 gio trash) |
| 提权操作 | 180s | `sudo` |
| 权限修改 | 180s | `chmod`, `chown` |
| 软件安装 | 180s | `pip install`, `npm install`, `apt install` |
| Git 写入 | 180s | `git push`, `git commit`, `git reset --hard` |
| 容器操作 | 180s | `docker run`, `docker build` |
| SSH/远程 | 180s | `ssh user@host`, `scp`, `rsync` |
| 归档解压 | 180s | `tar -xzf`, `unzip` |
| 服务管理 | 180s | `systemctl start/stop/restart` |
| 🆕 系统控制 | 180s | `reboot`, `shutdown`, `halt`, `poweroff` |

### 规则优先级

```
DENY list (最高)
   ↓ 未命中
ALLOW list
   ↓ 未命中
APPROVE list
   ↓ 未命中
Policy 文件 (allow_cmd prefix match)
   ↓ 未命中
默认放行（按模式决定：permissive=放行, supervised=审批, enforce=拒绝）
```

---

## ⚡ 速率限制 & 级联防护

> **威胁背景**：AI Agent 单次提示可触发数百次工具调用，递归 bug 几分钟耗尽 API 预算。
> 攻击者可利用 prompt injection 放大单次恶意输入为洪水式攻击。

### 三层限速

| 层级 | 窗口 | 阈值 | 触发动作 |
|:-----|:-----|:--:|:-----|
| **Burst 检测** | 30 秒 | ≥ 10 次 | 暂停 30s，返回等待提示 |
| **Global Cap** | 5 分钟 | ≥ 50 次 | 彻底阻断，疑似递归死循环 |
| **Deny Escalation** | 不限 | ≥ 3 次连续拒绝 | 自动升级 enforce 模式 |

### 行为说明

```
正常:     exec(1) exec(2) ... exec(9) → 放行
Burst:    exec(10) → 暂停 30s ⏳
Global:   exec(50+) → 阻断 🚫 (记录 audit)
Escalate: deny(1) deny(2) deny(3) → 自动 enforce 🔴
```

**Escalation 重置**：会话结束时自动清除。如需立即重置，开启新会话（`/new`）。

---

## 🔒 Guardrail 自防护

> **威胁背景**：有案例显示 AI Agent 被拦截后会**主动调查并尝试 kill guardrail 进程**。

### 防护措施

| 防护项 | 实现 |
|:-----|:-----|
| **进程保护** | `kill/pkill/killall` 目标含 `openclaw\|clawguard` → DENY |
| **服务保护** | `systemctl --user stop/disable openclaw-gateway` → DENY |
| **目录保护** | 删除/移动 `~/.clawguard/` 下文件 → DENY |
| **插件保护** | 删除/移动 `@victorqr/clawguard` 插件文件 → DENY |
| **策略完整性** | `policy.ini` SHA256 校验，篡改+损坏 → 回退 enforce |
| **哈希初始化** | 首次加载自动计算并存储 SHA256 到 `~/.clawguard/.policy-hash` |

### 完整性校验流程

```
加载 policy.ini
    ↓
第一次加载？→ 计算 SHA256 → 存储到 .policy-hash → 通过
    ↓
后续加载 → 比对存储的 SHA256
    ├── 一致 → 通过 ✅
    └── 不一致 → 解析新内容
              ├── 解析成功 → 更新哈希（合法修改） → 通过 ✅
              └── 解析失败 → 回退 enforce 模式 🚫
```

---

## 📡 通道感知策略

> **设计原则**：不同通道安全上下文不同，不能用同一把尺子量。

### 通道解析

从 `ctx.sessionKey` 解析通道类型（格式：`agent:main:<provider>:<chatType>:<id>`）。

| 通道类型 | sessionKey 特征 | 策略 | 说明 |
|:-----|:-----|:-----|:-----|
| **私聊** | `:direct:` | supervised | 完全信任，跟随 policy.ini |
| **群聊** | `:group:` | enforce | 仅允许白名单命令，防止群内误操作 |
| **Cron** | `:cron:` | permissive | 自动放行，全量审计 |
| **终端** | `terminal` | supervised | 跟随 policy.ini |
| **未知** | 其他 | enforce | 默认严格（安全优先） |

### 群聊策略详情

在群聊通道中：
- **exec 工具**：仅允许 `ALLOW` 白名单中的命令
- **read 工具**：正常放行（只读操作无风险）
- **write 工具**：正常评估（文件路径规则适用）
- **网络工具**：正常评估（域名白名单适用）

---

## 🧠 会话管理

### 会话审批记忆

| 操作 | 行为 |
|:-----|:-----|
| 点击「始终允许」 | 同一会话内相同命令/路径/域名自动放行 |
| 会话结束 (`session_end`) | 自动清除该会话的所有审批记忆 |
| `/new` 命令 | 新会话，审批记忆重置 |
| `/reset` 命令 | 同一会话，审批记忆保留 |

### 审批记忆格式

```
exec:systemctl --user restart openclaw-gateway
file:/home/victor/.openclaw/workspace/user_workspace/temp/backup.tar.gz
net:https://api.github.com/repos/VictorQR/clawguard
```

---

## 📊 审计日志

### 格式

JSONL，按日期分文件：`~/.clawguard/audit/YYYY-MM-DD.jsonl`

```jsonl
{"timestamp":"2026-05-09T10:53:20.000Z","toolName":"exec","params":"{\"command\":\"ls -la\"}","result":"","toolCallId":"abc123","durationMs":12,"error":null,"session":"agent:main:qqbot:direct:0a39eb...","command":"ls -la"}
{"timestamp":"2026-05-09T10:53:25.000Z","toolName":"exec","params":"{\"command\":\"rm -rf /tmp/test\"}","result":"","toolCallId":"def456","durationMs":5,"error":null,"decision":"DENY","rule":"rm_rf_deny","session":"agent:main:qqbot:direct:0a39eb...","command":"rm -rf /tmp/test"}
```

### 字段说明

| 字段 | 类型 | 说明 |
|:-----|:-----|:-----|
| `timestamp` | ISO 8601 | 事件时间 |
| `toolName` | string | 工具名（exec/write/read/web_fetch 等） |
| `params` | JSON string | 工具参数（已脱敏） |
| `result` | string | 执行结果（已脱敏，超过 64KB 截断） |
| `toolCallId` | string? | 工具调用唯一 ID |
| `durationMs` | number | 执行耗时（毫秒） |
| `error` | string? | 错误信息 |
| `decision` | string? | DENY / ALLOW / APPROVE |
| `rule` | string? | 匹配的规则 pattern |
| `session` | string | 会话标识（`agent:main:qqbot:direct:...`） |
| `command` | string? | 提取的命令文本（仅 exec 工具） |

### 脱敏规则

以下模式自动替换为 `[REDACTED]`：
- GitHub Token (`ghp_`, `github_pat_`)
- Bearer Token
- JWT (`eyJ...`)
- API Key (`sk-`, `api_key=`)
- SSH 私钥 (`-----BEGIN`)
- AWS Access Key (`AKIA`, `ASIA`)
- 密码参数 (`password=`, `passwd=`, `--password`)

### 日志轮转

- 超过 90 天的日志文件自动移至系统回收站（`gio trash`）
- 每次 `after_tool_call` 触发时检查

---

## 📈 统计与周报

### 实时统计

每会话自动跟踪：
- 工具调用总数
- 拦截次数与审批次数
- 按工具类型分布
- 总执行耗时
- TOP 10 被拦截命令

### 热力图

按小时聚合，输出格式：

```json
[
  {"hour": "00:00", "total": 5, "denied": 0, "approved": 0},
  {"hour": "01:00", "total": 120, "denied": 3, "approved": 2},
  {"hour": "02:00", "total": 87, "denied": 1, "approved": 1}
]
```

### 周报

通过 Gateway 方法生成：

```bash
curl -s http://127.0.0.1:18789/gateway/clawguard.report \
  -H "Content-Type: application/json" \
  -d '{"type":"weekly"}' | jq
```

返回 7 天汇总，包含：
- 总命令数 / 拦截数 / 审批数 / 拦截率
- 活跃会话数
- TOP 10 被拦截命令
- 当日热力图
- 所有活跃会话详情

---

## ⚙️ 配置详解

### Policy 文件

位置：`~/.clawguard/policy.ini`

```ini
# ClawGuard Policy File
# =====================
# 运行模式（permissive | supervised | enforce）
mode = supervised

# ── 命令白名单 ──────────────────────────
# 支持前缀匹配，$WORKSPACE 自动解析
allow_cmd = gio trash *
allow_cmd = git status
allow_cmd = git log
allow_cmd = git diff
allow_cmd = python3 $WORKSPACE/user_workspace/
allow_cmd = npx tsx tests/

# ── 域名白名单 ──────────────────────────
allow_domain = api.github.com
allow_domain = api.deepseek.com
allow_domain = api.tavily.ai
allow_domain = registry.npmjs.org
allow_domain = pypi.org

# ── 文件写入白名单 ──────────────────────
# 支持 ** glob，~ 自动展开
allow_write = ~/.openclaw/workspace/**
allow_write = /tmp/**
```

### 三级模式对比

| 模式 | DENY 规则 | APPROVE 规则 | ALLOW 规则 | 速率限制 | 通道感知 |
|:-----|:--:|:--:|:--:|:--:|:--:|
| `permissive` | 仅记录 | 仅记录 | 放行 | ✅ 生效 | ✅ 生效 |
| `supervised` | 拦截 | 审批弹窗 | 放行 | ✅ 生效 | ✅ 生效 |
| `enforce` | 拦截 | **降级为 DENY** | 放行 | ✅ 生效 | ✅ 生效 |

### 热加载

- 文件变更后 100ms 自动重载（适配 `write-then-rename` 原子写入）
- SHA256 校验通过才接受新策略
- 损坏的策略文件触发 fallback enforce 模式

---

## 🏗️ 架构

```
OpenClaw Gateway 进程
│
├── 其他插件 / 原生工具
│
└── @victorqr/clawguard (进程内 TypeScript 插件)
    │
    ├── before_tool_call (priority=100)
    │   ├── parseChannelType()    → 通道解析（私聊/群聊/Cron）
    │   ├── RateLimiter.check()   → 速率限制（burst/global/escalation）
    │   ├── extractCommand()      → 统一命令提取
    │   ├── checkBypass()         → 编码绕过检测
    │   ├── Policy.checkCommand() → Policy 文件规则
    │   ├── checkCommand()        → 三段式规则引擎（DENY>ALLOW>APPROVE）
    │   ├── checkFileWrite/Read() → 文件路径规则
    │   └── checkDomain()         → 网络域名白名单
    │
    ├── after_tool_call (priority=50)
    │   ├── auditLog.append()     → 脱敏 → JSONL 写入
    │   └── stats.recordCall()    → 更新会话统计
    │
    ├── RateLimiter (v0.2.0)
    │   ├── 30s sliding window burst detection
    │   ├── 5min global cap
    │   └── Consecutive deny → auto enforce
    │
    ├── StatsCollector (v0.2.0)
    │   ├── Per-session counters
    │   ├── Hourly heatmap
    │   └── Weekly report generator
    │
    ├── PolicyEngine
    │   ├── ~/.clawguard/policy.ini → parse → watch
    │   ├── ~/.clawguard/.policy-hash → SHA256 校验
    │   └── 损坏时回退 enforce 兜底
    │
    ├── AuditLogger
    │   ├── ~/.clawguard/audit/YYYY-MM-DD.jsonl
    │   └── 90 天轮转 + 敏感信息脱敏
    │
    └── Gateway Methods
        ├── clawguard.status  → 完整运行状态
        ├── clawguard.config  → 策略重载/查看
        └── clawguard.report  → 周报/热力图/会话统计
```

### 模块依赖

```
index.ts
├── rateLimiter.ts    # 速率限制（无外部依赖）
├── session-stats.ts  # 统计收集（fs）
├── policy.ts         # 策略引擎（fs, crypto, os）
├── audit.ts          # 审计日志（fs, os）
├── rules.ts          # 规则加载匹配（fs）
├── extractor.ts      # 命令提取（无依赖）
├── bypass.ts         # 绕过检测（无依赖）
├── file-rules.ts     # 文件规则（fs, minimatch）
├── network-rules.ts  # 网络规则（url）
└── types.ts          # 类型定义
```

---

## 📡 API 参考

### Gateway Methods

| 方法 | 参数 | 返回 | 说明 |
|:-----|:-----|:-----|:-----|
| `clawguard.status` | — | StatusObject | 完整运行状态（模式/规则/速率/统计/完整性） |
| `clawguard.config` | `{action:"reload"}`? | ConfigObject | 策略查看或重载 |
| `clawguard.report` | `{type:"weekly"}`? | ReportObject | 周报（7天汇总）或当前统计 |

### clawguard.status 返回结构

```typescript
{
  plugin: string;          // "ClawGuard"
  version: string;         // "0.2.0"
  mode: string;            // "permissive" | "supervised" | "enforce"
  fallbackMode: boolean;   // 是否处于回退 enforce 模式
  integrity: boolean;      // policy.ini SHA256 完整性
  rules: {
    deny: number;          // DENY 规则数
    allow: number;         // ALLOW 规则数
    approve: number;       // APPROVE 规则数
  };
  auditDir: string;        // 审计日志目录
  policySummary: {
    mode: string;
    rules: number;
    fallback: boolean;
    integrity: boolean;
  };
  activeSessions: number;  // 活跃会话数
  rateLimit: {             // 当前会话速率状态
    recentExecs: number;
    denyCount: number;
    escalated: boolean;
    paused: boolean;
    pauseRemaining: number;
  } | null;
  currentSession: {        // 当前会话统计
    sessionKey: string;
    channel: string;
    commandCount: number;
    denyCount: number;
    approveCount: number;
    bypassDetections: number;
    totalDurationMs: number;
    topDenied: Array<{command:string; count:number}>;
    toolCalls: Record<string, number>;
  } | null;
}
```

### 插件生命周期钩子

| 钩子 | Priority | 说明 |
|:-----|:--:|:-----|
| `before_tool_call` | 100 | 最先执行，可阻断/审批/修改参数 |
| `after_tool_call` | 50 | 异步并行执行，审计记录 |
| `session_end` | — | 清理会话级数据 |

---

## 🧪 测试

```bash
cd ~/github/clawguard

# TypeScript 编译
npm run build

# 单元测试（规则引擎 + 绕过检测）
npx tsx tests/rules.test.ts

# 集成测试（端到端拦截）
npx tsx tests/integration.test.ts
```

---

## 📋 依赖

| 依赖 | 版本 | 用途 |
|:-----|:-----|:-----|
| Node.js | ≥ 22 | 运行时 |
| OpenClaw | ≥ 2026.3.24-beta.2 | `before_tool_call` / `after_tool_call` 钩子 |
| minimatch | ≥ 9 | glob 路径匹配 |

---

*ClawGuard — 运行时安全，从源头开始。*
