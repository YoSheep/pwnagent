"""
web_scan — Web 漏洞扫描模块
整合 nuclei + 1-day PoC + XSS + SQLi + SSRF + 目录爆破，将结果注册为 Finding。
"""
from core.state_machine import Finding
from tools.nuclei_tool import nuclei_scan
from tools.sqli_tool import sqli_scan
from tools.ssrf_tool import ssrf_scan
from tools.xss_tool import xss_scan
from tools.dirbust_tool import dirbust
from tools.pure.onedaypoc import onedaypoc_scan
from tools.pure.vuln_checker import python_vuln_check

_SEVERITY_CVSS = {
    "critical": 9.0, "high": 7.5, "medium": 5.0, "low": 3.0, "info": 0.0,
}


def run_web_scan(session, agent) -> list[Finding]:
    """
    对 session.attack_surface 中的所有 Web 服务执行全面扫描。
    """
    findings = []
    web_services = session.attack_surface.get("web_services", [])
    if not web_services:
        web_services = [{"url": session.target}]

    for svc in web_services:
        url = svc.get("url", svc.get("matched-at", ""))
        if not url:
            continue

        # 1. Nuclei / 纯 Python 通用漏洞扫描
        nuclei_result = nuclei_scan(target=url)
        for item in nuclei_result.get("findings", []):
            sev = item.get("severity", "info").lower()
            f = Finding(
                title=item.get("name", item.get("template_id", "Unknown")),
                severity=sev,
                target=item.get("matched_at", url),
                description=item.get("description", ""),
                payload=item.get("curl_command", ""),
                reproduction=item.get("curl_command", ""),
                remediation=_get_remediation(item),
                cvss=item.get("cvss_score") or _SEVERITY_CVSS.get(sev, 0.0),
            )
            agent.register_finding(f)
            findings.append(f)

        # 2. 1-day CVE PoC 检测
        poc_result = onedaypoc_scan(target=url)
        for item in poc_result.get("findings", []):
            sev = item.get("severity", "high").lower()
            f = Finding(
                title=f"[{item['cve_id']}] {item['name']}",
                severity=sev,
                target=item.get("target", url),
                description=item.get("evidence", ""),
                payload="",
                reproduction=f"目标: {url}\n证据: {item.get('evidence', '')}\n参考: {', '.join(item.get('references', []))}",
                remediation=item.get("remediation", ""),
                cvss=item.get("cvss", _SEVERITY_CVSS.get(sev, 7.0)),
            )
            agent.register_finding(f)
            findings.append(f)

        # 3. 目录爆破
        dir_result = dirbust(target=url, categories=["admin", "sensitive", "backup", "api"])
        for item in dir_result.get("high_interest", []):
            path = item.get("path", "")
            # 只记录高风险路径
            if _is_high_risk_path(path):
                sev = _path_severity(path)
                f = Finding(
                    title=f"敏感路径暴露: {path}",
                    severity=sev,
                    target=item.get("url", url + path),
                    description=f"路径 {path} 可公开访问（HTTP {item.get('status')}），内容类型: {item.get('content_type', '')}",
                    payload="",
                    reproduction=f"GET {item.get('url', url + path)}",
                    remediation="限制敏感路径访问，配置适当的访问控制策略。",
                    cvss=_SEVERITY_CVSS.get(sev, 5.0),
                )
                agent.register_finding(f)
                findings.append(f)

        # 4. XSS 扫描（仅 200 响应页面）
        if svc.get("status_code", 200) == 200:
            xss_result = xss_scan(target=url)
            for item in xss_result.get("reflected_xss", []):
                if item.get("reflected") or item.get("in_xss_context"):
                    f = Finding(
                        title=f"反射型 XSS — 参数: {item.get('param')}",
                        severity="high",
                        target=item.get("url", url),
                        description="发现反射型 XSS，用户输入未经过滤直接输出到页面。",
                        payload=item.get("probe", ""),
                        reproduction=f"URL: {item.get('url', url)}\nPayload: {item.get('probe', '')}",
                        remediation="对所有用户输入进行 HTML 实体编码，实施严格的 CSP 策略。",
                        cvss=7.5,
                    )
                    agent.register_finding(f)
                    findings.append(f)

            for item in xss_result.get("dom_xss", []):
                f = Finding(
                    title="DOM 型 XSS",
                    severity="high",
                    target=item.get("url", url),
                    description="DOM 型 XSS，客户端脚本直接处理用户可控数据并写入 DOM。",
                    payload=item.get("probe", ""),
                    reproduction=f"访问: {item.get('url', url)}",
                    remediation="避免使用 innerHTML/document.write，使用 DOMPurify 净化。",
                    cvss=7.5,
                )
                agent.register_finding(f)
                findings.append(f)

        # 5. SQLi 扫描（含参数 URL）
        if "?" in url:
            sqli_result = sqli_scan(target=url)
            if sqli_result.get("vulnerable"):
                for ind in sqli_result.get("heuristic", {}).get("indicators", [])[:3]:
                    f = Finding(
                        title=f"SQL 注入 — 参数: {ind.get('param', 'unknown')}",
                        severity="critical",
                        target=url,
                        description=f"发现 {ind.get('type', '')} SQL 注入。",
                        payload=ind.get("payload", ind.get("true_payload", "")),
                        reproduction=f"URL: {url}\n参数: {ind.get('param')}\nPayload: {ind.get('payload', '')}",
                        remediation="使用参数化查询，禁止拼接用户输入到 SQL 语句。",
                        cvss=9.8,
                    )
                    agent.register_finding(f)
                    findings.append(f)

        # 6. SSRF 扫描（含参数 URL）
        if "?" in url:
            ssrf_result = ssrf_scan(target=url)
            if ssrf_result.get("vulnerable"):
                for item in ssrf_result.get("findings", [])[:3]:
                    f = Finding(
                        title=f"SSRF — 参数: {item.get('param', 'unknown')}",
                        severity="high",
                        target=item.get("url", url),
                        description=f"服务端请求伪造，类型: {item.get('type', 'ssrf')}",
                        payload=item.get("probe", ""),
                        reproduction=f"URL: {item.get('url', url)}\n参数: {item.get('param')}\nProbe: {item.get('probe', '')}",
                        remediation="白名单验证 URL，禁止访问内网地址，实施 SSRF 防护策略。",
                        cvss=8.6,
                    )
                    agent.register_finding(f)
                    findings.append(f)

    return findings


def _is_high_risk_path(path: str) -> bool:
    high_risk = [
        ".env", ".git", ".svn", "phpinfo", "config", "backup",
        "admin", "phpmyadmin", "adminer", "sql", "dump",
        "shell", "cmd", "webshell",
    ]
    path_lower = path.lower()
    return any(r in path_lower for r in high_risk)


def _path_severity(path: str) -> str:
    critical_paths = [".env", ".git", "backup", "sql", "dump", "shell", "cmd", "webshell"]
    high_paths = ["phpinfo", "config", "phpmyadmin", "adminer"]
    path_lower = path.lower()
    if any(p in path_lower for p in critical_paths):
        return "critical"
    if any(p in path_lower for p in high_paths):
        return "high"
    return "medium"


def _get_remediation(nuclei_item: dict) -> str:
    refs = nuclei_item.get("reference", [])
    if refs:
        return f"参考: {', '.join(refs[:2])}"
    tags = nuclei_item.get("tags", [])
    if "cve" in (t.lower() for t in tags):
        return "参考对应 CVE 的官方修复建议，及时升级受影响组件。"
    return "参考 OWASP 对应类型漏洞的修复建议。"
