# 🛡️ ClawGuard — OpenClaw Runtime Security Plugin

> 轻量级 OpenClaw 安全插件，基于 `before_tool_call` 钩子实现运行时工具调用拦截。
> 零外部依赖、全本地决策、不引入单点故障。

## ✨ 功能概览

| 模块 | 说明 |
|:-----|:-----|
| **三段式规则引擎** | DENY（彻底拦截）> ALLOW（直接放行）> APPROVE（需审批） |
| **编码绕过检测** | base64 管道执行、eval 动态代码、命令混淆、进程替换 |
| **文件路径规则** | 读/写分开评估，通配符白名单，symlink 解析 |
| **网络域名白名单** | 内网自动放行，未知域名默认拒绝 |
| **Policy 文件** | INI 格式，热加载（写时复制+原子 rename），损坏自动兜底 |
| **审计日志** | 脱敏 JSONL，90 天自动轮转，并发安全 |
| **三级运行模式** | permissive（仅记录）/ supervised（需审批）/ enforce（直接拦截）|

### 三张规则表

#### 🚫 DENY — 彻底拦截

| 类别 | 示例 |
|:-----|:-----|
| 递归删除 | `rm -rf /`, `rm -rf ~` |
| 磁盘操作 | `mkfs`, `fdisk`, `dd if=/dev/sda` |
| Fork Bomb | `:(){ :|:& };:` |
| 远程代码执行 | `curl ... \| bash`, `wget ... \| sh` |
| 反弹 Shell | `bash -i >& /dev/tcp`, `nc -e /bin/bash` |
| 凭据窃取 | `cat /etc/shadow` |
| 系统控制 | `reboot`, `shutdown`, `halt` |
| 编码绕过 | `base64 -d \| sh`, `eval $(...)` |
| 环境注入 | `PATH=`, `LD_PRELOAD=`, `PYTHONPATH=` |

#### ✅ ALLOW — 直接放行

| 类别 | 示例 |
|:-----|:-----|
| 只读文件 | `ls`, `cat`, `head`, `tail` |
| 文件导航 | `cd`, `pwd`, `which`, `whoami` |
| Git 只读 | `git status`, `git log`, `git diff` |
| 包查看 | `pip list`, `npm list` |
| 系统回收站 | `gio trash` (rm 唯一替代) |
| 文本处理 | `grep`, `sed`, `awk`, `sort`, `wc` |
| 进程查看 | `ps`, `top`, `free`, `df` |
| 测试运行 | `npx tsx tests/` |

#### 🔶 APPROVE — 需审批

| 类别 | 示例 |
|:-----|:-----|
| 文件删除 | `rm` (非 gio trash) |
| 提权操作 | `sudo` |
| 权限修改 | `chmod`, `chown` |
| 软件安装 | `pip install`, `npm install`, `apt-get install` |
| Git 写入 | `git push`, `git commit` |
| 容器操作 | `docker run`, `kubectl apply` |
| SSH/远程 | `ssh user@host`, `scp`, `rsync` |
| 归档解压 | `tar -xzf`, `unzip` |

## 🚀 快速开始

### 安装

```bash
# 方式一：ClawHub（推荐）
openclaw plugins install clawhub:@victorqr/clawguard

# 方式二：本地开发
git clone https://github.com/VictorQR/clawguard.git
cd clawguard
npm install
npm run build
openclaw plugins install ./dist

# 方式三：手工复制
cp -r clawguard ~/.openclaw/extensions/
openclaw gateway restart
```

### 验证安装

```bash
# 查看插件状态
openclaw plugins list | grep clawguard

# 检查运行模式与规则统计
curl -s http://127.0.0.1:18789/gateway/clawguard.status | jq
```

### 输出示例

```json
{
  "plugin": "ClawGuard",
  "version": "0.1.0",
  "mode": "supervised",
  "fallbackMode": false,
  "rules": { "deny": 29, "allow": 44, "approve": 30 },
  "auditDir": "/home/victor/.clawguard/audit",
  "activeSessions": 2
}
```

## ⚙️ 配置

Policy 文件位置：`~/.clawguard/policy.ini`

```ini
# ClawGuard Policy File
# 模式: permissive | supervised | enforce
mode = supervised

# 允许的命令（前缀匹配）
allow_cmd = gio trash *
allow_cmd = git status
allow_cmd = git log
allow_cmd = python3 $WORKSPACE/user_workspace/

# 允许的域名
allow_domain = api.github.com
allow_domain = api.deepseek.com
allow_domain = api.tavily.ai

# 允许的文件写入路径
allow_write = ~/.openclaw/workspace/**
```

**三级模式**：

| 模式 | 行为 |
|:-----|:-----|
| `permissive` | 仅记录审计日志，不拦截任何操作 |
| `supervised` | 可疑操作需用户审批（需 SDK 支持 `requireApproval`） |
| `enforce` | 危险操作直接拦截，APPROVE 类操作降级为 DENY |

**Policy 热加载**：文件变更后自动重载（100ms 延迟，适配原子 rename）。

## 🏗️ 架构

```
OpenClaw Gateway 进程
├── 其他插件 / 原生工具
│
└── clawguard-plugin (进程内 TypeScript)
    │
    ├── before_tool_call (priority=100)
    │   ├── extractCommand()  → 统一 command/cmd/script/args
    │   ├── checkBypass()     → 编码绕过检测
    │   ├── Policy.checkCommand() → Policy 文件规则
    │   ├── checkCommand()    → 三段式规则引擎
    │   ├── checkFileWrite/Read() → 文件路径规则
    │   └── checkDomain()     → 网络域名白名单
    │
    ├── after_tool_call (priority=50)
    │   └── auditLog.append() → 脱敏 → JSONL 写入
    │
    ├── PolicyEngine
    │   ├── ~/.clawguard/policy.ini → parse → watch
    │   └── 损坏时回退 deny-all 兜底
    │
    └── AuditLogger
        ├── ~/.clawguard/audit/YYYY-MM-DD.jsonl
        └── 90 天轮转 + 敏感信息脱敏
```

## 📊 审计日志

格式：JSONL，按日期分文件

```jsonl
{"ts":"2026-05-08T23:30:00.000Z","tool":"exec","cmd":"gio trash sessions/*.deleted.*","params":"...","result":"","decision":"ALLOW","rule":"whitelist_gio_trash","duration":12,"session":"abc123"}
{"ts":"2026-05-08T23:31:00.000Z","tool":"exec","cmd":"rm -rf /tmp","params":"...","result":"","decision":"DENY","rule":"blacklist_rm_rf","reason":"🚫 CRITICAL: Recursive deletion of system directories","session":"abc123"}
```

**脱敏规则**：GitHub Token、Bearer Token、JWT、API Key、SSH 私钥、AWS Access Key 等自动替换为 `[REDACTED]`。

## 🔗 与 dir-inventory 的关系

```
clawguard-plugin (运行时实时拦截)         dir-inventory (事后扫描清理)
┌──────────────────────────────┐         ┌──────────────────────────┐
│ before_tool_call             │         │ 每日 18:00 扫描          │
│  → 拦截 rm — 强制 gio trash  │         │ → 报告未清理文件         │
│  → 拦截高危命令               │         │ → 自动 gio trash        │
│  → 记录 audit 日志            │         │ → 生成清理报告           │
└──────────────────────────────┘         └──────────────────────────┘
         │                                        │
         └─────── 共享 ~/.clawguard/policy.ini ────┘
         └─────── 共享 $WORKSPACE 变量解析 ─────────┘
```

两个组件互补：ClawGuard 负责**事前拦截**（运行时），dir-inventory 负责**事后清理**（定时扫描）。

## 📋 依赖

| 依赖 | 版本 | 用途 |
|:-----|:-----|:-----|
| Node.js | ≥ 22 | 运行时 |
| OpenClaw | ≥ 2026.3.24-beta.2 | before_tool_call 钩子支持 |
| minimatch | ≥ 9 | glob 路径匹配 |

## 🧪 测试

```bash
npm run build                  # TypeScript 编译

# 单元测试 (33 tests)
npx tsx tests/rules.test.ts

# 集成测试 (34 tests)
npx tsx tests/integration.test.ts
```

## 📝 许可证

MIT License — Copyright (c) 2026 VictorQR

---

*ClawGuard v0.1.0 — 运行时安全，从源头开始。*
