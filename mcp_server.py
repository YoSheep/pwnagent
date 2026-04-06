"""
PwnAgent MCP Server
将所有安全测试工具暴露为 MCP tools，供 Claude Code 及其他 MCP 客户端直接调用。

启动方式（stdio，适用于 Claude Code）:
  python3 mcp_server.py

Claude Code 配置（~/.claude/settings.json）:
  {
    "mcpServers": {
      "pwnagent": {
        "command": "python3",
        "args": ["/path/to/penagent/mcp_server.py"]
      }
    }
  }
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    name="pwnagent",
    instructions=(
        "PwnAgent 安全测试工具集。\n"
        "包含端口扫描、Web 探测、漏洞扫描、1-day CVE 检测、"
        "XSS/SQLi/SSRF 检测、子域名枚举、目录爆破、JWT 分析等工具。\n"
        "所有工具默认直接执行，请仅在合法授权场景中使用。"
    ),
)

def _check(target: str, tool_name: str):
    return None


# ==================================================================
# 侦察工具
# ==================================================================

@mcp.tool()
def nmap_scan(target: str, ports: str = "top1000", flags: str = "-sV") -> dict:
    """
    端口扫描与服务识别。nmap 不可用时自动使用纯 Python 扫描器。

    Args:
        target: 目标 IP 或域名
        ports:  "top1000" / "1-65535" / "80,443,8080"
        flags:  nmap 额外参数（nmap 可用时生效）
    """
    _check(target, "nmap_scan")
    from tools.nmap_tool import nmap_scan as _fn
    return _fn(target=target, ports=ports, flags=flags)


@mcp.tool()
def httpx_probe(target: str, paths: list[str] | None = None) -> dict:
    """
    Web 服务探测：状态码、标题、服务器、技术栈。

    Args:
        target: 目标 URL 或 IP
        paths:  额外探测路径，如 ["/admin", "/api"]
    """
    _check(target, "httpx_probe")
    from tools.httpx_tool import httpx_probe as _fn
    return _fn(target=target, paths=paths)


@mcp.tool()
def subdomain_enum(
    domain: str,
    use_crtsh: bool = True,
    wordlist: list[str] | None = None,
) -> dict:
    """
    子域名枚举：DNS 爆破 + crt.sh 证书透明日志。

    Args:
        domain:    根域名，如 example.com
        use_crtsh: 是否查询 crt.sh（需外网访问）
        wordlist:  自定义字典（可选）
    """
    _check(f"http://{domain}", "subdomain_enum")
    from tools.subdomain_tool import subdomain_enum as _fn
    return _fn(domain=domain, use_crtsh=use_crtsh, wordlist=wordlist)


@mcp.tool()
def dirbust(
    target: str,
    categories: list[str] | None = None,
    extra_paths: list[str] | None = None,
    interesting_codes: list[int] | None = None,
) -> dict:
    """
    目录/文件爆破。内置 admin、api、sensitive、backup、logs、common 等类别路径字典。

    Args:
        target:           目标 URL
        categories:       要测试的类别，None 表示全部
                          可选: admin / api / sensitive / backup / logs / common / auth_bypass
        extra_paths:      额外自定义路径
        interesting_codes: 感兴趣的 HTTP 状态码，默认 [200,301,302,401,403,500]
    """
    _check(target, "dirbust")
    from tools.dirbust_tool import dirbust as _fn
    return _fn(target=target, categories=categories,
               extra_paths=extra_paths, interesting_codes=interesting_codes)


# ==================================================================
# 漏洞扫描工具
# ==================================================================

@mcp.tool()
def nuclei_scan(target: str, severity: str = "critical,high,medium", tags: str = "") -> dict:
    """
    漏洞模板扫描。nuclei 不可用时使用内置纯 Python 规则检查器。

    Args:
        target:   目标 URL
        severity: "critical,high,medium,low,info"
        tags:     模板标签过滤，如 "cve,owasp"（nuclei 可用时生效）
    """
    _check(target, "nuclei_scan")
    from tools.nuclei_tool import nuclei_scan as _fn
    return _fn(target=target, severity=severity, tags=tags)


@mcp.tool()
def onedaypoc_scan(target: str, severity: str = "critical,high") -> dict:
    """
    1-day CVE PoC 检测（仅探测，不利用）。
    覆盖 Log4Shell、Spring4Shell、ActiveMQ、Confluence、PHP CGI、
    Citrix Bleed、Fortinet、PAN-OS、MOVEit、TeamCity、CrushFTP 等 15+ CVE。

    Args:
        target:   目标 URL
        severity: 严重程度过滤
    """
    _check(target, "onedaypoc_scan")
    from tools.pure.onedaypoc import onedaypoc_scan as _fn
    return _fn(target=target, severity=severity)


@mcp.tool()
def xss_scan(target: str, params: list[str] | None = None) -> dict:
    """
    XSS 漏洞检测（反射型 + DOM 型）。

    Args:
        target: 目标 URL（可含参数，如 http://host/search?q=test）
        params: 额外要测试的参数名
    """
    _check(target, "xss_scan")
    from tools.xss_tool import xss_scan as _fn
    return _fn(target=target, params=params)


@mcp.tool()
def sqli_scan(
    target: str, data: str = "", level: int = 1, risk: int = 1
) -> dict:
    """
    SQL 注入检测（启发式 + sqlmap）。

    Args:
        target: 目标 URL（含 GET 参数）
        data:   POST 数据（可选）
        level:  sqlmap 检测级别 1-5
        risk:   sqlmap 风险等级 1-3
    """
    _check(target, "sqli_scan")
    from tools.sqli_tool import sqli_scan as _fn
    return _fn(target=target, data=data, level=level, risk=risk)


@mcp.tool()
def ssrf_scan(target: str, params: list[str] | None = None) -> dict:
    """
    SSRF 漏洞检测 + 开放重定向检测。

    Args:
        target: 目标 URL（可含查询参数）
        params: 额外要测试的参数名（如 ["url", "callback"]）
    """
    _check(target, "ssrf_scan")
    from tools.ssrf_tool import ssrf_scan as _fn
    return _fn(target=target, params=params)


@mcp.tool()
def python_vuln_check(target: str, severity: str = "critical,high,medium") -> dict:
    """
    纯 Python 漏洞检查（无需 nuclei）。
    内置规则：Git/env 暴露、phpinfo、目录列举、CORS、备份文件、管理后台、Swagger 等。

    Args:
        target:   目标 URL
        severity: 严重程度过滤
    """
    _check(target, "python_vuln_check")
    from tools.pure.vuln_checker import python_vuln_check as _fn
    return _fn(target=target, severity=severity)


# ==================================================================
# 专项分析工具
# ==================================================================

@mcp.tool()
def jwt_analyze(token: str) -> dict:
    """
    JWT Token 安全分析。
    检测：None 算法攻击、弱密钥爆破、算法混淆、无过期时间、
    敏感信息泄露、kid 注入、jku/jwk/x5u 注入。

    Args:
        token: JWT token 字符串
    """
    from tools.jwt_tool import jwt_analyze as _fn
    return _fn(token=token)


@mcp.tool()
def jwt_extract(response_headers: dict, response_body: str) -> dict:
    """
    从 HTTP 响应中自动提取所有 JWT token 并分析。

    Args:
        response_headers: HTTP 响应头（dict）
        response_body:    HTTP 响应体（字符串）
    """
    from tools.jwt_tool import extract_jwt_from_response, jwt_analyze
    tokens = extract_jwt_from_response(response_headers, response_body)
    return {
        "found_tokens": len(tokens),
        "analyses": [jwt_analyze(t) for t in tokens],
    }


@mcp.tool()
def python_port_scan(target: str, ports: str = "top1000") -> dict:
    """
    纯 Python 异步端口扫描（零外部依赖）。

    Args:
        target: 目标 IP 或域名
        ports:  "top1000" / "1-1000" / "80,443,8080"
    """
    _check(target, "python_port_scan")
    from tools.pure.port_scanner import python_port_scan as _fn
    return _fn(target=target, ports=ports)


# ==================================================================
# 报告工具
# ==================================================================

@mcp.tool()
def generate_report(
    target: str,
    title: str = "渗透测试报告",
    tester: str = "PwnAgent",
    output_dir: str = "./reports",
) -> dict:
    """
    从最近一次 session 生成 Markdown + HTML 报告。

    Args:
        target:     目标（用于匹配 session）
        title:      报告标题
        tester:     测试人员名称
        output_dir: 报告输出目录
    """
    from core.memory import LongTermMemory
    from modules.reporter import generate_report_from_db

    mem = LongTermMemory()
    try:
        cur = mem.conn.execute(
            "SELECT id, target, scope, phase, summary FROM sessions "
            "WHERE target LIKE ? ORDER BY updated_at DESC LIMIT 1",
            (f"%{target}%",)
        )
        row = cur.fetchone()
        if not row:
            return {"error": f"未找到目标 '{target}' 的 session"}
        session_id = row[0]
        session_data = mem.load_session(session_id)
        result = generate_report_from_db(session_id, session_data, mem, output_dir)
        return {"status": "ok", **result}
    finally:
        mem.close()


# ==================================================================
# 入口
# ==================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="PwnAgent MCP Server")
    parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio")
    args = parser.parse_args()

    print("[PwnAgent MCP] 启动，未启用授权检查", file=sys.stderr)
    mcp.run(transport=args.transport)
