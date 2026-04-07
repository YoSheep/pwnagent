"""
PentestPilot MCP Server
将所有安全测试工具暴露为 MCP tools，供 Claude Code 及其他 MCP 客户端直接调用。

启动方式（stdio，适用于 Claude Code）:
  python3 mcp_server.py

Claude Code 配置（~/.claude/settings.json）:
  {
    "mcpServers": {
      "pentestpilot": {
        "command": "python3",
        "args": ["/path/to/pentestpilot/mcp_server.py"]
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
    name="pentestpilot",
    instructions=(
        "PentestPilot 安全测试工具集。\n"
        "包含端口扫描、Web 探测、漏洞扫描、1-day CVE 检测、"
        "XSS/SQLi/SSRF 检测、子域名枚举、目录爆破、JWT 分析、"
        "认证工作流、文件上传、密码哈希破解等工具。\n"
        "所有工具默认直接执行，请仅在合法授权场景中使用。"
    ),
)

def _check(target: str, tool_name: str):
    return None


# ==================================================================
# 侦察工具
# ==================================================================

@mcp.tool()
def nmap_scan(
    target: str,
    ports: str = "top1000",
    flags: str = "-sV",
    scan_type: str = "legacy",
    timing: int = 3,
    additional_flags: str = "",
) -> dict:
    """
    端口扫描与服务识别。nmap 不可用时自动使用纯 Python 扫描器。

    Args:
        target: 目标 IP 或域名
        ports:  "top1000" / "1-65535" / "80,443,8080"
        flags:  兼容旧参数，额外 nmap flags
        scan_type: legacy / quick / full / version / custom
        timing: nmap 时间模板 0-5（对应 -T0..-T5）
        additional_flags: MCP 风格附加 flags（白名单过滤）
    """
    _check(target, "nmap_scan")
    from tools.nmap_tool import nmap_scan as _fn
    return _fn(
        target=target,
        ports=ports,
        flags=flags,
        scan_type=scan_type,
        timing=timing,
        additional_flags=additional_flags,
    )


@mcp.tool()
def httpx_probe(
    target: str,
    paths: list[str] | None = None,
    headers: dict[str, str] | None = None,
    capture_body: bool = False,
) -> dict:
    """
    Web 服务探测：状态码、标题、服务器、技术栈。

    Args:
        target: 目标 URL 或 IP
        paths:  额外探测路径，如 ["/admin", "/api"]
        headers: 自定义请求头
        capture_body: 是否返回 body 预览/正文
    """
    _check(target, "httpx_probe")
    from tools.httpx_tool import httpx_probe as _fn
    return _fn(target=target, paths=paths, headers=headers, capture_body=capture_body)


@mcp.tool()
def page_intel(
    target: str,
    path: str = "",
    headers: dict[str, str] | None = None,
    session_alias: str = "",
    include_external_scripts: bool = True,
    max_external_scripts: int = 5,
) -> dict:
    """
    页面情报提取：读取页面、表单、脚本和接口候选。

    Args:
        target: 目标 URL
        path: 相对路径，如 /admin
        headers: 自定义请求头
        session_alias: 复用认证会话
        include_external_scripts: 是否继续抓取外链 JS
        max_external_scripts: 最多抓取的外链脚本数
    """
    _check(target, "page_intel")
    from tools.page_intel_tool import page_intel as _fn
    return _fn(
        target=target,
        path=path,
        headers=headers,
        session_alias=session_alias,
        include_external_scripts=include_external_scripts,
        max_external_scripts=max_external_scripts,
    )


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
    headers: dict[str, str] | None = None,
    engine: str = "auto",
    threads: int = 25,
    recursive: bool = False,
    extensions: list[str] | None = None,
    include_status: list[int] | None = None,
    exclude_status: list[int] | None = None,
    wordlist_categories: list[str] | None = None,
    max_time: int = 0,
    cookie: str = "",
    user_agent: str = "",
    proxy: str = "",
) -> dict:
    """
    目录/文件爆破。支持 `dirsearch` 与纯 Python 两种引擎。

    Args:
        target:           目标 URL
        categories:       内置类别，None 表示全部
                          可选: admin / api / sensitive / backup / logs / common / auth_bypass
        extra_paths:      额外自定义路径
        interesting_codes: Python fallback 感兴趣状态码
        headers:          自定义请求头
        engine:           auto / dirsearch / python
        threads:          并发数
        recursive:        是否递归（dirsearch）
        extensions:       dirsearch 扩展名
        include_status:   dirsearch include-status
        exclude_status:   dirsearch exclude-status
        wordlist_categories: dirsearch 内置词典分类
        max_time:         dirsearch 最大运行时长（秒）
        cookie:           请求 Cookie
        user_agent:       自定义 UA
        proxy:            代理 URL
    """
    _check(target, "dirbust")
    from tools.dirbust_tool import dirbust as _fn
    return _fn(
        target=target,
        categories=categories,
        extra_paths=extra_paths,
        interesting_codes=interesting_codes,
        headers=headers,
        engine=engine,
        threads=threads,
        recursive=recursive,
        extensions=extensions,
        include_status=include_status,
        exclude_status=exclude_status,
        wordlist_categories=wordlist_categories,
        max_time=max_time,
        cookie=cookie,
        user_agent=user_agent,
        proxy=proxy,
    )


@mcp.tool()
def dirsearch_init(update: bool = True, force_clone: bool = False) -> dict:
    """
    初始化/更新 dirsearch 运行时（自动 clone/pull）。

    Args:
        update: 是否尝试更新（受更新时间间隔限制）
        force_clone: 目录冲突时是否强制 clone
    """
    from tools.dirbust_tool import dirsearch_init as _fn
    return _fn(update=update, force_clone=force_clone)


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
def xss_scan(
    target: str,
    params: list[str] | None = None,
    deep: bool = True,
    max_urls: int = 8,
    max_requests: int = 70,
) -> dict:
    """
    XSS 漏洞检测（反射型 + DOM 型）。

    Args:
        target: 目标 URL（可含参数，如 http://host/search?q=test）
        params: 额外要测试的参数名
        deep: 是否从页面中提取同源链接/表单扩展扫描
        max_urls: 最多测试的候选 URL 数
        max_requests: 本次扫描最大请求数
    """
    _check(target, "xss_scan")
    from tools.xss_tool import xss_scan as _fn
    return _fn(
        target=target,
        params=params,
        deep=deep,
        max_urls=max_urls,
        max_requests=max_requests,
    )


@mcp.tool()
def sqli_scan(
    target: str,
    data: str = "",
    level: int = 1,
    risk: int = 1,
    mode: str = "detect",
    db_name: str = "",
    table_name: str = "",
    columns: str = "",
    cookie: str = "",
    profile: str = "default",
    tamper: str = "",
    use_common_dict: bool = False,
) -> dict:
    """
    SQL 注入检测/利用（sqlmap 驱动）。

    Args:
        target: 目标 URL（含 GET 参数）
        data:   POST 数据（可选）
        level:  sqlmap 检测级别 1-5
        risk:   sqlmap 风险等级 1-3
        mode:   detect / enumerate / dump
        db_name: 指定数据库名（enumerate/dump）
        table_name: 指定表名（enumerate/dump）
        columns: 指定列名，逗号分隔（dump）
        cookie: 认证 Cookie（可选）
        profile: default / fast / deep / waf_bypass
        tamper: 手动指定 tamper 链（逗号分隔），会覆盖 profile 默认值
        use_common_dict: 是否启用 common-tables/common-columns/smalldict
    """
    _check(target, "sqli_scan")
    from tools.sqli_tool import sqli_scan as _fn
    return _fn(
        target=target,
        data=data,
        level=level,
        risk=risk,
        mode=mode,
        db_name=db_name,
        table_name=table_name,
        columns=columns,
        cookie=cookie,
        profile=profile,
        tamper=tamper,
        use_common_dict=use_common_dict,
    )


@mcp.tool()
def sqlmap_init(update: bool = True, force_clone: bool = False) -> dict:
    """
    初始化 sqlmap 运行时（自动 clone/pull）。

    Args:
        update: 是否尝试执行更新
        force_clone: 目录冲突时是否强制 clone（默认 false，避免破坏数据）
    """
    from tools.sqli_tool import sqlmap_prepare as _fn
    return _fn(update=update, force_clone=force_clone)


@mcp.tool()
def sqlmap_scan_url(
    url: str,
    data: str = "",
    cookie: str = "",
    level: int = 1,
    risk: int = 1,
    technique: str = "BEUSTQ",
    profile: str = "default",
    tamper: str = "",
    use_common_dict: bool = False,
) -> dict:
    """
    SQLMap URL 检测（MCP 风格接口）。
    """
    _check(url, "sqlmap_scan_url")
    from tools.sqli_tool import sqlmap_scan_url as _fn
    return _fn(
        url=url,
        data=data,
        cookie=cookie,
        level=level,
        risk=risk,
        technique=technique,
        profile=profile,
        tamper=tamper,
        use_common_dict=use_common_dict,
    )


@mcp.tool()
def sqlmap_enumerate_databases(url: str, data: str = "", cookie: str = "") -> dict:
    """
    SQLMap 枚举数据库（--dbs）。
    """
    _check(url, "sqlmap_enumerate_databases")
    from tools.sqli_tool import sqlmap_enumerate_databases as _fn
    return _fn(url=url, data=data, cookie=cookie)


@mcp.tool()
def sqlmap_enumerate_tables(url: str, database: str, data: str = "", cookie: str = "") -> dict:
    """
    SQLMap 枚举指定数据库中的表（--tables）。
    """
    _check(url, "sqlmap_enumerate_tables")
    from tools.sqli_tool import sqlmap_enumerate_tables as _fn
    return _fn(url=url, database=database, data=data, cookie=cookie)


@mcp.tool()
def sqlmap_enumerate_columns(
    url: str,
    database: str,
    table: str,
    data: str = "",
    cookie: str = "",
) -> dict:
    """
    SQLMap 枚举指定表字段（--columns）。
    """
    _check(url, "sqlmap_enumerate_columns")
    from tools.sqli_tool import sqlmap_enumerate_columns as _fn
    return _fn(url=url, database=database, table=table, data=data, cookie=cookie)


@mcp.tool()
def sqlmap_dump_table(
    url: str,
    database: str,
    table: str,
    columns: str = "",
    where: str = "",
    limit: int = 0,
    data: str = "",
    cookie: str = "",
) -> dict:
    """
    SQLMap 导出指定表数据（--dump）。
    """
    _check(url, "sqlmap_dump_table")
    from tools.sqli_tool import sqlmap_dump_table as _fn
    return _fn(
        url=url,
        database=database,
        table=table,
        columns=columns,
        where=where,
        limit=limit,
        data=data,
        cookie=cookie,
    )


@mcp.tool()
def sqlmap_get_banner(url: str, data: str = "", cookie: str = "") -> dict:
    """
    SQLMap 获取数据库 banner（--banner）。
    """
    _check(url, "sqlmap_get_banner")
    from tools.sqli_tool import sqlmap_get_banner as _fn
    return _fn(url=url, data=data, cookie=cookie)


@mcp.tool()
def sqlmap_get_current_user(url: str, data: str = "", cookie: str = "") -> dict:
    """
    SQLMap 获取当前数据库用户（--current-user）。
    """
    _check(url, "sqlmap_get_current_user")
    from tools.sqli_tool import sqlmap_get_current_user as _fn
    return _fn(url=url, data=data, cookie=cookie)


@mcp.tool()
def sqlmap_get_current_db(url: str, data: str = "", cookie: str = "") -> dict:
    """
    SQLMap 获取当前数据库（--current-db）。
    """
    _check(url, "sqlmap_get_current_db")
    from tools.sqli_tool import sqlmap_get_current_db as _fn
    return _fn(url=url, data=data, cookie=cookie)


@mcp.tool()
def sqlmap_read_file(url: str, file_path: str, data: str = "", cookie: str = "") -> dict:
    """
    SQLMap 文件读取（--file-read）。
    """
    _check(url, "sqlmap_read_file")
    from tools.sqli_tool import sqlmap_read_file as _fn
    return _fn(url=url, file_path=file_path, data=data, cookie=cookie)


@mcp.tool()
def sqlmap_execute_command(url: str, command: str, data: str = "", cookie: str = "") -> dict:
    """
    SQLMap 执行系统命令（--os-cmd）。
    """
    _check(url, "sqlmap_execute_command")
    from tools.sqli_tool import sqlmap_execute_command as _fn
    return _fn(url=url, command=command, data=data, cookie=cookie)


@mcp.tool()
def ssrf_scan(
    target: str,
    params: list[str] | str | None = None,
    max_params: int = 20,
    max_probes_per_param: int = 10,
    concurrency: int = 20,
    requests_per_second: float = 25.0,
    timeout: float = 12.0,
    verify_ssl: bool = False,
    include_open_redirect: bool = True,
    callback_url: str = "",
) -> dict:
    """
    SSRF 漏洞检测 + 开放重定向检测（异步并发，带 baseline 判定）。

    Args:
        target: 目标 URL（可含查询参数）
        params: 额外要测试的参数名（如 ["url", "callback"]）
        max_params: 最多测试参数数量
        max_probes_per_param: 每参数最大 payload 数
        concurrency: 并发请求数
        requests_per_second: 速率限制（<=0 表示不限速）
        timeout: 单请求超时秒数
        verify_ssl: 是否校验证书
        include_open_redirect: 是否附带开放重定向检测
        callback_url: 可选 OAST/回连地址
    """
    _check(target, "ssrf_scan")
    from tools.ssrf_tool import ssrf_scan as _fn
    return _fn(
        target=target,
        params=params,
        max_params=max_params,
        max_probes_per_param=max_probes_per_param,
        concurrency=concurrency,
        requests_per_second=requests_per_second,
        timeout=timeout,
        verify_ssl=verify_ssl,
        include_open_redirect=include_open_redirect,
        callback_url=callback_url,
    )


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
def hash_crack(hash_value: str, extra_words: list[str] | None = None, salt: str = "") -> dict:
    """
    常见 MD5/SHA1/SHA256/SHA512 哈希弱口令破解。

    Args:
        hash_value: 哈希值
        extra_words: 额外字典项
        salt: 可选盐值
    """
    from tools.hash_tool import hash_crack as _fn
    return _fn(hash_value=hash_value, extra_words=extra_words, salt=salt)


@mcp.tool()
def http_request(
    target: str,
    path: str = "",
    method: str = "GET",
    params: dict | None = None,
    headers: dict[str, str] | None = None,
    data: str = "",
    form: dict | None = None,
    json_body: dict | None = None,
    session_alias: str = "",
    capture_body: bool = True,
    follow_redirects: bool = True,
) -> dict:
    """
    发送通用 HTTP 请求，可复用已建立会话。
    """
    _check(target, "http_request")
    from tools.web_workflow_tool import http_request as _fn
    return _fn(
        target=target,
        path=path,
        method=method,
        params=params,
        headers=headers,
        data=data,
        form=form,
        json_body=json_body,
        session_alias=session_alias,
        capture_body=capture_body,
        follow_redirects=follow_redirects,
    )


@mcp.tool()
def login_form(
    target: str,
    username: str,
    password: str,
    login_path: str = "",
    session_alias: str = "default",
    username_field: str = "",
    password_field: str = "",
    extra_fields: dict | None = None,
    headers: dict[str, str] | None = None,
) -> dict:
    """
    自动识别登录表单并保持认证会话。
    """
    _check(target, "login_form")
    from tools.web_workflow_tool import login_form as _fn
    return _fn(
        target=target,
        username=username,
        password=password,
        login_path=login_path,
        session_alias=session_alias,
        username_field=username_field,
        password_field=password_field,
        extra_fields=extra_fields,
        headers=headers,
    )


@mcp.tool()
def upload_file(
    target: str,
    session_alias: str,
    upload_path: str = "",
    file_content: str = "",
    file_path: str = "",
    filename: str = "shell.php",
    field_name: str = "file",
    extra_fields: dict | None = None,
    content_type: str = "application/octet-stream",
    verify_paths: list[str] | None = None,
    headers: dict[str, str] | None = None,
) -> dict:
    """
    使用已建立认证会话上传文件，并可选验证落地路径。
    """
    _check(target, "upload_file")
    from tools.web_workflow_tool import upload_file as _fn
    return _fn(
        target=target,
        session_alias=session_alias,
        upload_path=upload_path,
        file_content=file_content,
        file_path=file_path,
        filename=filename,
        field_name=field_name,
        extra_fields=extra_fields,
        content_type=content_type,
        verify_paths=verify_paths,
        headers=headers,
    )


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
    tester: str = "PentestPilot",
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

    parser = argparse.ArgumentParser(description="PentestPilot MCP Server")
    parser.add_argument("--transport", choices=["stdio", "sse"], default="stdio")
    args = parser.parse_args()

    print("[PentestPilot MCP] 启动，未启用授权检查", file=sys.stderr)
    mcp.run(transport=args.transport)
