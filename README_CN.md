<p align="center">
  <pre>
  ██████╗ ██╗    ██╗███╗   ██╗ █████╗  ██████╗ ███████╗███╗   ██╗████████╗
  ██╔══██╗██║    ██║████╗  ██║██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝
  ██████╔╝██║ █╗ ██║██╔██╗ ██║███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║
  ██╔═══╝ ██║███╗██║██║╚██╗██║██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║
  ██║     ╚███╔███╔╝██║ ╚████║██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║
  ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝
  </pre>
</p>

<p align="center">
  <b>AI 驱动的自动化渗透测试框架</b>
</p>

<p align="center">
  中文文档 | <a href="./README.md">English</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/LLM-Multi--Provider-blueviolet.svg" alt="Multi Provider">
  <img src="https://img.shields.io/badge/license-仅限授权使用-red.svg" alt="License">
</p>

---

> **警告：本工具仅限对已获得书面授权的目标使用。未经授权对目标进行渗透测试违反法律，使用者需自行承担全部法律责任。**

## 什么是 PwnAgent？

PwnAgent 是一个支持多 LLM Provider 的 AI 驱动渗透测试框架。采用 **ReAct（Reason + Act）** 智能体架构，能够自主执行从信息收集到漏洞利用的完整渗透测试流程。当前支持 Anthropic 官方接口、MiniMax 的 Anthropic 兼容接口，并为多种 OpenAI-compatible 厂商预留了配置入口。内置 SafetyGuard 安全门卫机制，确保所有操作严格限定在授权范围内。

## 核心特性

- **多 Provider LLM 抽象层** — Brain / Planner / Ask / Exploit / Post-Exploit 统一走 provider 配置，可在 `config.yaml` 中切换 Anthropic、MiniMax 和其他兼容厂商
- **单 Agent + 并行工具执行** — 基于 ReAct 循环，单个 Agent 通过 `ThreadPoolExecutor` 并行调度多个工具，兼顾推理一致性与执行效率
- **动态规划与失败恢复** — Planner 在每个阶段生成执行计划（支持并行组 / 顺序步骤），失败时 Replanner 自动调整策略，最多重试 2 次
- **RAG 知识增强** — 基于 ChromaDB 的知识库（内置 OWASP Top 10），为 Agent 决策提供上下文参考
- **SafetyGuard 安全门卫** — 所有工具调用前强制检查授权范围（CIDR / 域名 / 通配符）+ 速率限制，不可绕过
- **纯 Python 工具回退** — 所有外部二进制工具（nmap、nuclei、httpx）均有纯 Python 实现，零依赖开箱即用
- **MCP Server** — 通过 Model Context Protocol 将所有工具暴露给 Claude Code，可直接在 IDE 中调用
- **插件化工具系统** — ToolRegistry 自动发现内置工具，支持从外部目录加载自定义插件

## 架构

```
┌─────────────────────────────────────────────────────────┐
│                     Input Router                         │
│              scan | ask | tools | report                 │
└────────┬──────────────────┬─────────────────────────────┘
         │                  │
    [扫描任务]          [知识查询]
         │                  │
         v                  v
┌─────────────────┐  ┌──────────────┐
│   Planner (RAG) │  │   Knowledge  │
│   生成阶段计划   │  │  Agent (RAG) │
└────────┬────────┘  └──────────────┘
         │
         v
┌─────────────────────────────────────┐
│          ReAct Agent Loop            │
│                                     │
│  Brain (LLM Provider) ──> 并行工具执行│
│       ^                  │          │
│       └──── 观察结果 <───┘          │
│                                     │
│  失败 → Replanner → 调整计划重试     │
└────────┬────────────────────────────┘
         │
         v
┌─────────────────────────────────────┐
│  Phase State Machine                 │
│  INIT → RECON → SCAN → EXPLOIT →    │
│  POST_EXPLOIT → REPORT → DONE       │
└─────────────────────────────────────┘
         │
         v
    报告输出 (Markdown + HTML)
```

## 项目结构

```
penagent/
├── main.py                 # CLI 入口（Input Router）
├── mcp_server.py           # MCP Server（Claude Code 集成）
├── config.yaml             # 全局配置
├── install.sh              # 一键安装脚本
├── pyproject.toml          # 依赖管理
│
├── core/                   # 核心引擎
│   ├── agent.py            # ReAct 主循环 + 并行工具执行
│   ├── brain.py            # Provider 交互（流式 + 多工具调用）
│   ├── config.py           # config.yaml / .env 加载
│   ├── llm.py              # 多 Provider 适配层
│   ├── planner.py          # 动态规划器 + Replanner
│   ├── memory.py           # 短期上下文 + SQLite 长期持久化
│   ├── safety.py           # SafetyGuard 授权检查 + 速率限制
│   └── state_machine.py    # 渗透测试阶段状态机
│
├── tools/                  # 工具层
│   ├── registry.py         # 工具注册中心（自动发现 + 插件加载）
│   ├── nmap_tool.py        # 端口扫描（nmap + Python 回退）
│   ├── httpx_tool.py       # Web 探测（httpx + Python 回退）
│   ├── nuclei_tool.py      # 漏洞扫描（nuclei + Python 回退）
│   ├── xss_tool.py         # XSS 检测（反射型 + DOM 型）
│   ├── sqli_tool.py        # SQL 注入检测（sqlmap）
│   ├── ssrf_tool.py        # SSRF + 开放重定向检测
│   ├── subdomain_tool.py   # 子域名枚举（DNS + crt.sh）
│   ├── dirbust_tool.py     # 目录爆破
│   ├── jwt_tool.py         # JWT 安全分析
│   └── pure/               # 纯 Python 实现（零外部依赖）
│       ├── port_scanner.py # 异步端口扫描器
│       ├── vuln_checker.py # 规则漏洞检查器
│       └── onedaypoc.py    # 1-day CVE PoC 指纹检测
│
├── modules/                # 功能模块
│   ├── recon.py            # 信息收集编排
│   ├── web_scan.py         # Web 扫描编排
│   ├── exploit_gen.py      # 漏洞利用生成
│   ├── post_exploit.py     # 后渗透模块
│   └── reporter.py         # 报告生成（Markdown + HTML）
│
├── knowledge/              # RAG 知识库
│   ├── ingest.py           # 知识导入（OWASP / CVE / Markdown）
│   └── retriever.py        # 向量检索接口
│
├── db/                     # SQLite 数据库（会话持久化）
└── reports/                # 报告输出目录
```

## 快速开始

### 1. 安装

```bash
# 一键安装（推荐）
chmod +x install.sh && ./install.sh

# 或手动安装
pip install anthropic openai python-dotenv rich typer httpx jinja2 pyyaml chromadb "mcp[cli]"
```

### 2. 配置 API Key

```bash
# 任选一个你要使用的 provider
export ANTHROPIC_API_KEY="sk-ant-..."
export MINIMAX_API_KEY="your-minimax-key"
export OPENAI_API_KEY="your-openai-key"

# 然后在 config.yaml 里切换 llm.provider，例如:
# llm:
#   provider: "minimax"
```

### 3. 运行扫描

```bash
# 基础扫描
python3 main.py scan http://target.com --scope target.com

# 指定多个授权范围
python3 main.py scan 192.168.1.100 --scope "192.168.1.0/24,*.target.com"

# 非交互模式 + 详细输出
python3 main.py scan http://target.com --scope target.com --no-interactive --verbose

# 禁用动态规划器（直接由 Claude 自主决策）
python3 main.py scan http://target.com --scope target.com --no-planner

# 加载自定义插件
python3 main.py scan http://target.com --scope target.com --plugins ./my_plugins
```

## CLI 命令

| 命令 | 说明 |
|------|------|
| `scan <target> --scope <范围>` | 执行完整 AI 驱动渗透测试 |
| `ask <问题>` | 向知识库提问（不执行扫描） |
| `tools` | 列出所有已注册工具 |
| `report <session_id>` | 从历史 session 重新生成报告 |
| `sessions` | 列出历史测试 session |
| `ingest <文件路径>` | 向知识库导入文档 |

```bash
# 查看所有工具
python3 main.py tools

# 按类别筛选
python3 main.py tools --category recon

# 提问安全问题
python3 main.py ask "如何检测 JWT none algorithm 攻击？"

# 导入 OWASP 知识
python3 main.py ingest --owasp

# 导入自定义知识
python3 main.py ingest ./cve-2024-report.json
```

## MCP Server（Claude Code 集成）

PwnAgent 提供 MCP Server，可将所有安全测试工具直接暴露给 Claude Code。

### 配置

在 `~/.claude/settings.json` 中添加：

```json
{
  "mcpServers": {
    "pwnagent": {
      "command": "python3",
      "args": ["/path/to/penagent/mcp_server.py"],
      "env": {
        "PWNAGENT_SCOPE": "192.168.1.0/24,target.com",
        "PWNAGENT_RATE_LIMIT": "10"
      }
    }
  }
}
```

### 可用 MCP 工具

配置完成后，在 Claude Code 中可直接调用：

| 工具 | 说明 |
|------|------|
| `nmap_scan` | 端口扫描 |
| `httpx_probe` | Web 服务探测 |
| `nuclei_scan` | 漏洞扫描 |
| `xss_scan` | XSS 检测 |
| `sqli_scan` | SQL 注入检测 |
| `ssrf_scan` | SSRF 检测 |
| `subdomain_enum` | 子域名枚举 |
| `dirbust` | 目录爆破 |
| `jwt_analyze` | JWT 安全分析 |
| `python_port_scan` | 纯 Python 端口扫描 |
| `python_vuln_check` | 纯 Python 漏洞检查 |
| `onedaypoc_scan` | 1-day CVE 指纹检测 |
| `generate_report` | 生成渗透测试报告 |

## 内置工具

### 外部工具（有纯 Python 回退）

| 工具 | 用途 | 未安装时 |
|------|------|----------|
| nmap | 端口扫描 | 自动使用 `python_port_scan`（异步 TCP 连接扫描） |
| nuclei | 漏洞扫描 | 自动使用 `python_vuln_check`（规则匹配） |
| httpx (Go) | Web 探测 | 自动使用 Python `httpx` 库 |
| sqlmap | SQL 注入 | 基础检测仍可用，深度扫描不可用 |
| Playwright | DOM XSS | 跳过 DOM XSS 检测，反射型 XSS 仍可用 |

### 纯 Python 工具（零依赖）

| 工具 | 用途 |
|------|------|
| `python_port_scan` | asyncio 并发端口扫描 |
| `python_vuln_check` | 规则漏洞指纹检测 |
| `onedaypoc_scan` | 15+ 已知 CVE PoC 检测 |
| `xss_scan` | 反射型 + DOM XSS |
| `ssrf_scan` | SSRF + 开放重定向 |
| `subdomain_enum` | DNS 爆破 + crt.sh |
| `dirbust` | 异步目录爆破 |
| `jwt_analyze` | JWT none alg / 弱密钥 / kid 注入检测 |

## 自定义插件

在任意目录下创建 Python 文件，PwnAgent 会自动发现并注册：

```python
# my_plugins/custom_scanner.py

TOOL_NAME = "my_custom_scan"
TOOL_CATEGORY = "scan"
TOOL_DESCRIPTION = "我的自定义扫描器"

def my_custom_scan(target: str, options: str = "") -> dict:
    """自定义扫描逻辑。"""
    # ... 你的代码
    return {"status": "done", "findings": [...]}
```

```bash
python3 main.py scan http://target.com --scope target.com --plugins ./my_plugins
```

## 安全机制

### SafetyGuard

所有工具调用前必须通过 SafetyGuard 授权检查：

- **CIDR 范围检查** — IP 必须在授权 CIDR 内
- **域名匹配** — 支持精确匹配和通配符（`*.example.com`）
- **子域名保护** — `notexample.com` 不会匹配 `example.com`
- **URL 解析防御** — 拦截 `http://evil@authorized_ip` 等绕过尝试
- **速率限制** — 每工具可配置 QPS 上限，防止过度扫描

### 交互模式

默认启用交互模式，在高风险操作（漏洞利用、后渗透）前暂停确认。

## 配置

编辑 `config.yaml`：

```yaml
# 工具路径（留空自动检测 PATH）
tools:
  nmap: ""
  httpx: ""
  nuclei: ""
  sqlmap: ""

# 速率限制（每秒最大请求数）
rate_limits:
  default: 10
  nmap_scan: 1
  nuclei_scan: 50

# Agent 行为
agent:
  max_steps: 50
  interactive: true
  verbose: false

# LLM Provider
llm:
  provider: "anthropic"
  providers:
    anthropic:
      api_style: "anthropic"
      api_key_env: "ANTHROPIC_API_KEY"
      api_key: ""
      base_url: ""
    minimax:
      api_style: "anthropic"
      api_key_env: "MINIMAX_API_KEY"
      api_key: ""
      base_url: "https://api.minimax.io/anthropic/v1"
    openai:
      api_style: "openai"
      api_key_env: "OPENAI_API_KEY"
      api_key: ""
      base_url: "https://api.openai.com/v1"

# 报告输出
report:
  output_dir: "./reports"
  formats: [markdown, html]
```

## 系统要求

- Python 3.11+
- 任一已配置的 LLM Provider API Key（Anthropic / MiniMax / OpenAI-compatible）
- 可选：nmap、nuclei、httpx (Go)、sqlmap、Playwright

## 技术栈

| 组件 | 技术 |
|------|------|
| LLM | Anthropic / MiniMax / OpenAI-compatible |
| Agent 框架 | 原生 ReAct 实现（无 LangChain 依赖） |
| 流式通信 | Anthropic / OpenAI-compatible Streaming |
| 并行执行 | `concurrent.futures.ThreadPoolExecutor` |
| 持久化 | SQLite（WAL 模式） |
| 知识库 | ChromaDB 向量数据库 |
| CLI | Typer + Rich |
| MCP | Model Context Protocol（stdio） |
| 报告 | Jinja2 模板（Markdown + HTML） |

## 许可证

本项目仅供安全研究和授权渗透测试使用。
