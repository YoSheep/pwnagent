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
  <b>AI-Powered Autonomous Penetration Testing Framework</b>
</p>

<p align="center">
  <a href="./README_CN.md">中文文档</a> | English
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/LLM-Claude-blueviolet.svg" alt="Claude">
  <img src="https://img.shields.io/badge/license-authorized--use--only-red.svg" alt="License">
</p>

---

> **WARNING: This tool is strictly for authorized penetration testing only. Using this tool against targets without explicit written authorization is illegal. Users bear full legal responsibility for any misuse.**

## What is PwnAgent?

PwnAgent is an AI-driven penetration testing framework built on Anthropic Claude. It uses a **ReAct (Reason + Act)** agent architecture to autonomously execute the full pentest lifecycle — from reconnaissance to exploitation to reporting. A built-in SafetyGuard ensures all operations are strictly confined to authorized scope.

## Key Features

- **Single Agent + Parallel Tool Execution** — ReAct loop powered by Claude, with `ThreadPoolExecutor` for concurrent tool dispatch. Balances reasoning coherence with execution speed
- **Dynamic Planning & Recovery** — Planner generates phase-specific execution plans (parallel groups / sequential steps). On failure, Replanner auto-adjusts strategy with up to 2 retries
- **RAG-Enhanced Decisions** — ChromaDB knowledge base (ships with OWASP Top 10) provides contextual reference for agent decision-making
- **SafetyGuard** — Mandatory pre-execution authorization checks (CIDR / domain / wildcard) + rate limiting. Cannot be bypassed
- **Pure Python Fallbacks** — Every external binary tool (nmap, nuclei, httpx) has a pure Python implementation. Zero-dependency out-of-the-box
- **MCP Server** — Exposes all tools via Model Context Protocol for direct use in Claude Code / IDE
- **Plugin System** — ToolRegistry with auto-discovery of built-in tools + external plugin directory loading

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Input Router                         │
│              scan | ask | tools | report                 │
└────────┬──────────────────┬─────────────────────────────┘
         │                  │
    [Scan Task]        [Knowledge Query]
         │                  │
         v                  v
┌─────────────────┐  ┌──────────────┐
│   Planner (RAG) │  │  Knowledge   │
│  Phase planning  │  │  Agent (RAG) │
└────────┬────────┘  └──────────────┘
         │
         v
┌─────────────────────────────────────┐
│          ReAct Agent Loop            │
│                                     │
│  Brain (Claude) ──> Parallel Tools   │
│       ^                  │          │
│       └── Observations <─┘          │
│                                     │
│  Failure → Replanner → Retry        │
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
    Report Output (Markdown + HTML)
```

## Project Structure

```
penagent/
├── main.py                 # CLI entry point (Input Router)
├── mcp_server.py           # MCP Server (Claude Code integration)
├── config.yaml             # Global configuration
├── install.sh              # One-click installer
├── pyproject.toml          # Dependency management
│
├── core/                   # Core engine
│   ├── agent.py            # ReAct main loop + parallel tool execution
│   ├── brain.py            # Claude API interaction (streaming + multi-tool calls)
│   ├── planner.py          # Dynamic planner + Replanner
│   ├── memory.py           # Short-term context + SQLite long-term persistence
│   ├── safety.py           # SafetyGuard: authorization + rate limiting
│   └── state_machine.py    # Pentest phase state machine
│
├── tools/                  # Tool layer
│   ├── registry.py         # Tool registry (auto-discovery + plugin loading)
│   ├── nmap_tool.py        # Port scanning (nmap + Python fallback)
│   ├── httpx_tool.py       # Web probing (httpx + Python fallback)
│   ├── nuclei_tool.py      # Vulnerability scanning (nuclei + Python fallback)
│   ├── xss_tool.py         # XSS detection (reflected + DOM)
│   ├── sqli_tool.py        # SQL injection detection (sqlmap)
│   ├── ssrf_tool.py        # SSRF + open redirect detection
│   ├── subdomain_tool.py   # Subdomain enumeration (DNS + crt.sh)
│   ├── dirbust_tool.py     # Directory bruteforce
│   ├── jwt_tool.py         # JWT security analysis
│   └── pure/               # Pure Python implementations (zero external deps)
│       ├── port_scanner.py # Async port scanner
│       ├── vuln_checker.py # Rule-based vulnerability checker
│       └── onedaypoc.py    # 1-day CVE PoC fingerprinting
│
├── modules/                # Feature modules
│   ├── recon.py            # Reconnaissance orchestration
│   ├── web_scan.py         # Web scanning orchestration
│   ├── exploit_gen.py      # Exploit generation
│   ├── post_exploit.py     # Post-exploitation
│   └── reporter.py         # Report generation (Markdown + HTML)
│
├── knowledge/              # RAG knowledge base
│   ├── ingest.py           # Knowledge ingestion (OWASP / CVE / Markdown)
│   └── retriever.py        # Vector retrieval interface
│
├── db/                     # SQLite database (session persistence)
└── reports/                # Report output directory
```

## Quick Start

### 1. Install

```bash
# One-click install (recommended)
chmod +x install.sh && ./install.sh

# Or manual install
pip install anthropic rich typer httpx jinja2 pyyaml chromadb "mcp[cli]"
```

### 2. Set API Key

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

### 3. Run a Scan

```bash
# Basic scan
python3 main.py scan http://target.com --scope target.com

# Multiple authorized scopes
python3 main.py scan 192.168.1.100 --scope "192.168.1.0/24,*.target.com"

# Non-interactive + verbose output
python3 main.py scan http://target.com --scope target.com --no-interactive --verbose

# Disable dynamic planner (let Claude decide freely)
python3 main.py scan http://target.com --scope target.com --no-planner

# Load custom plugins
python3 main.py scan http://target.com --scope target.com --plugins ./my_plugins
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `scan <target> --scope <scope>` | Run full AI-driven penetration test |
| `ask <question>` | Query the knowledge base (no scanning) |
| `tools` | List all registered tools |
| `report <session_id>` | Re-generate report from a saved session |
| `sessions` | List historical test sessions |
| `ingest <file_path>` | Import documents into knowledge base |

```bash
# List all tools
python3 main.py tools

# Filter by category
python3 main.py tools --category recon

# Ask a security question
python3 main.py ask "How to detect JWT none algorithm attacks?"

# Import OWASP knowledge
python3 main.py ingest --owasp

# Import custom knowledge
python3 main.py ingest ./cve-2024-report.json
```

## MCP Server (Claude Code Integration)

PwnAgent provides an MCP Server that exposes all security testing tools directly to Claude Code.

### Configuration

Add to `~/.claude/settings.json`:

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

### Available MCP Tools

Once configured, these tools are available directly in Claude Code:

| Tool | Description |
|------|-------------|
| `nmap_scan` | Port scanning |
| `httpx_probe` | Web service probing |
| `nuclei_scan` | Vulnerability scanning |
| `xss_scan` | XSS detection |
| `sqli_scan` | SQL injection detection |
| `ssrf_scan` | SSRF detection |
| `subdomain_enum` | Subdomain enumeration |
| `dirbust` | Directory bruteforce |
| `jwt_analyze` | JWT security analysis |
| `python_port_scan` | Pure Python port scanner |
| `python_vuln_check` | Pure Python vuln checker |
| `onedaypoc_scan` | 1-day CVE fingerprinting |
| `generate_report` | Generate pentest report |

## Built-in Tools

### External Tools (with Pure Python Fallbacks)

| Tool | Purpose | When Not Installed |
|------|---------|-------------------|
| nmap | Port scanning | Auto-fallback to `python_port_scan` (async TCP connect) |
| nuclei | Vulnerability scanning | Auto-fallback to `python_vuln_check` (rule matching) |
| httpx (Go) | Web probing | Auto-fallback to Python `httpx` library |
| sqlmap | SQL injection | Basic detection still works, deep scan unavailable |
| Playwright | DOM XSS | DOM XSS skipped, reflected XSS still works |

### Pure Python Tools (Zero Dependencies)

| Tool | Purpose |
|------|---------|
| `python_port_scan` | asyncio concurrent port scanning |
| `python_vuln_check` | Rule-based vulnerability fingerprinting |
| `onedaypoc_scan` | 15+ known CVE PoC detection |
| `xss_scan` | Reflected + DOM XSS |
| `ssrf_scan` | SSRF + open redirect |
| `subdomain_enum` | DNS bruteforce + crt.sh |
| `dirbust` | Async directory bruteforce |
| `jwt_analyze` | JWT none alg / weak key / kid injection |

## Custom Plugins

Create a Python file in any directory, and PwnAgent will auto-discover and register it:

```python
# my_plugins/custom_scanner.py

TOOL_NAME = "my_custom_scan"
TOOL_CATEGORY = "scan"
TOOL_DESCRIPTION = "My custom scanner"

def my_custom_scan(target: str, options: str = "") -> dict:
    """Custom scanning logic."""
    # ... your code
    return {"status": "done", "findings": [...]}
```

```bash
python3 main.py scan http://target.com --scope target.com --plugins ./my_plugins
```

## Safety Mechanisms

### SafetyGuard

All tool calls must pass SafetyGuard authorization before execution:

- **CIDR Range Check** — IPs must fall within authorized CIDR ranges
- **Domain Matching** — Supports exact match and wildcards (`*.example.com`)
- **Subdomain Protection** — `notexample.com` won't match `example.com`
- **URL Parse Defense** — Blocks bypass attempts like `http://evil@authorized_ip`
- **Rate Limiting** — Per-tool configurable QPS caps to prevent excessive scanning

### Interactive Mode

Interactive mode is enabled by default. The agent pauses for user confirmation before high-risk operations (exploitation, post-exploitation).

## Configuration

Edit `config.yaml`:

```yaml
# Tool paths (leave empty for auto-detection via PATH)
tools:
  nmap: ""
  httpx: ""
  nuclei: ""
  sqlmap: ""

# Rate limits (max requests per second per tool)
rate_limits:
  default: 10
  nmap_scan: 1
  nuclei_scan: 50

# Agent behavior
agent:
  max_steps: 50
  model: "claude-opus-4-5"
  interactive: true
  verbose: false

# Report output
report:
  output_dir: "./reports"
  formats: [markdown, html]
```

## Requirements

- Python 3.11+
- Anthropic API Key
- Optional: nmap, nuclei, httpx (Go), sqlmap, Playwright

## Tech Stack

| Component | Technology |
|-----------|-----------|
| LLM | Anthropic Claude (native tool_use protocol) |
| Agent Framework | Native ReAct implementation (no LangChain) |
| Streaming | Anthropic Streaming API (event-driven) |
| Parallel Execution | `concurrent.futures.ThreadPoolExecutor` |
| Persistence | SQLite (WAL mode) |
| Knowledge Base | ChromaDB vector database |
| CLI | Typer + Rich |
| MCP | Model Context Protocol (stdio) |
| Reports | Jinja2 templates (Markdown + HTML) |

## License

This project is for authorized security research and penetration testing only.
