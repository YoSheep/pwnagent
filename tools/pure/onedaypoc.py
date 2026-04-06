"""
1-day CVE PoC 检测模块
检测目标是否受近期高危 CVE 影响（仅探测，不利用）。
所有检测均为无害的指纹/响应特征匹配。
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import httpx

TIMEOUT = 10.0
UA = "Mozilla/5.0 (PentestPilot/1.0)"


@dataclass
class CVEResult:
    cve_id: str
    name: str
    severity: str
    cvss: float
    target: str
    vulnerable: bool
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)


# ------------------------------------------------------------------
# 检测注册表
# ------------------------------------------------------------------

_CHECKS: list[tuple[dict, callable]] = []


def _cve(meta: dict):
    def decorator(fn):
        _CHECKS.append((meta, fn))
        return fn
    return decorator


# ------------------------------------------------------------------
# CVE-2021-44228 — Log4Shell（Apache Log4j2 RCE）
# ------------------------------------------------------------------

@_cve({
    "id": "CVE-2021-44228", "name": "Log4Shell — Apache Log4j2 RCE",
    "severity": "critical", "cvss": 10.0,
    "remediation": "升级 Log4j2 至 2.17.1+；或设置 log4j2.formatMsgNoLookups=true",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
})
def check_log4shell(client: httpx.Client, base_url: str) -> dict | None:
    """通过响应头/参数注入 JNDI 特征检测 Log4j 回显行为。"""
    # 检测 Java / Log4j 特征指纹
    try:
        r = client.get(base_url)
        server = r.headers.get("server", "").lower()
        powered = r.headers.get("x-powered-by", "").lower()
        # 检测 Java 应用服务器指纹
        java_indicators = ["tomcat", "jetty", "jboss", "wildfly", "weblogic",
                           "websphere", "spring", "java"]
        if any(ind in server or ind in powered for ind in java_indicators):
            return {
                "evidence": f"检测到 Java 应用服务器: server={server}, x-powered-by={powered}",
                "note": "目标可能运行 Java，建议进一步验证 Log4j 版本（需 DNSLOG 平台配合）",
                "confidence": "medium",
            }
        # 检测错误响应中的 Java 堆栈痕迹
        r2 = client.get(f"{base_url}/nonexistent_path_12345")
        if any(s in r2.text for s in ("java.lang.", "org.apache.", "javax.", "at com.", "at org.")):
            return {
                "evidence": "错误页面包含 Java 堆栈信息",
                "note": "确认为 Java 应用，建议使用 DNSLOG 验证 Log4Shell",
                "confidence": "high",
            }
    except Exception:
        pass
    return None


# ------------------------------------------------------------------
# CVE-2022-22965 — Spring4Shell（Spring Framework RCE）
# ------------------------------------------------------------------

@_cve({
    "id": "CVE-2022-22965", "name": "Spring4Shell — Spring Framework RCE",
    "severity": "critical", "cvss": 9.8,
    "remediation": "升级 Spring Framework 至 5.3.18+ 或 5.2.20+；升级至 Spring Boot 2.6.6+",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
})
def check_spring4shell(client: httpx.Client, base_url: str) -> dict | None:
    try:
        # 检测 Spring Boot Actuator 端点
        actuator_paths = ["/actuator", "/actuator/env", "/actuator/mappings",
                          "/actuator/health", "/manage/health"]
        for path in actuator_paths:
            r = client.get(f"{base_url}{path}")
            if r.status_code == 200 and any(k in r.text for k in
                                            ('"spring"', '"Spring"', 'springBootVersion',
                                             '"activeProfiles"', '"propertySources"')):
                return {
                    "evidence": f"Spring Boot Actuator 暴露: {base_url}{path}",
                    "note": "Actuator 端点暴露，建议检查 Spring 版本是否受 CVE-2022-22965 影响",
                    "confidence": "high",
                }
        # 检测 Spring 特征响应头
        r = client.get(base_url)
        if "spring" in r.headers.get("x-application-context", "").lower():
            return {"evidence": "X-Application-Context 头显示 Spring 应用"}
    except Exception:
        pass
    return None


# ------------------------------------------------------------------
# CVE-2023-46604 — Apache ActiveMQ RCE
# ------------------------------------------------------------------

@_cve({
    "id": "CVE-2023-46604", "name": "Apache ActiveMQ RCE",
    "severity": "critical", "cvss": 10.0,
    "remediation": "升级 ActiveMQ 至 5.15.16、5.16.7、5.17.6 或 5.18.3+",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-46604"],
})
def check_activemq(client: httpx.Client, base_url: str) -> dict | None:
    try:
        # ActiveMQ Web Console 指纹
        for path in ["/admin/", "/admin/queues.jsp", "/hawtio/"]:
            r = client.get(f"{base_url}{path}")
            if r.status_code in (200, 401, 403) and any(
                s in r.text for s in ("ActiveMQ", "activemq", "Apache ActiveMQ")
            ):
                version_match = re.search(r'ActiveMQ[^\d]*(\d+\.\d+\.\d+)', r.text)
                version = version_match.group(1) if version_match else "未知"
                vuln_versions = _activemq_is_vulnerable(version)
                return {
                    "evidence": f"发现 ActiveMQ Web Console: {path}，版本: {version}",
                    "vulnerable_version": vuln_versions,
                    "note": "ActiveMQ 61616 端口的 OpenWire 协议存在 RCE（需端口扫描确认）",
                    "confidence": "high" if vuln_versions else "medium",
                }
    except Exception:
        pass
    return None


def _activemq_is_vulnerable(version: str) -> bool:
    if not version or version == "未知":
        return False
    try:
        parts = [int(x) for x in version.split(".")]
        major, minor, patch = parts[0], parts[1], parts[2]
        if major == 5:
            if minor <= 14:
                return True
            if minor == 15 and patch < 16:
                return True
            if minor == 16 and patch < 7:
                return True
            if minor == 17 and patch < 6:
                return True
            if minor == 18 and patch < 3:
                return True
    except Exception:
        pass
    return False


# ------------------------------------------------------------------
# CVE-2023-22518 — Confluence 未授权数据破坏
# ------------------------------------------------------------------

@_cve({
    "id": "CVE-2023-22518", "name": "Atlassian Confluence 未授权数据破坏",
    "severity": "critical", "cvss": 9.1,
    "remediation": "升级至 Confluence 7.19.16+、8.3.4+、8.4.4+、8.5.3+、8.6.1+",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-22518"],
})
def check_confluence(client: httpx.Client, base_url: str) -> dict | None:
    try:
        r = client.get(base_url)
        if "Confluence" not in r.text and "confluence" not in r.headers.get("x-confluence-request-time", ""):
            # 尝试探测 Confluence 路径
            r2 = client.get(f"{base_url}/login.action")
            if r2.status_code != 200 or "Confluence" not in r2.text:
                return None

        # 检查受影响的端点是否可访问（仅 GET 探测）
        r3 = client.get(f"{base_url}/setup/setupadministrator.action")
        if r3.status_code == 200 and ("setup" in r3.text.lower() or "administrator" in r3.text.lower()):
            return {
                "evidence": f"Setup 端点可访问（HTTP {r3.status_code}），疑似受 CVE-2023-22518 影响",
                "confidence": "high",
            }

        version_match = re.search(r'Confluence[^\d]*(\d+\.\d+(?:\.\d+)?)', r.text)
        if version_match:
            return {
                "evidence": f"发现 Confluence，版本: {version_match.group(1)}",
                "note": "请确认版本是否在受影响范围内",
                "confidence": "medium",
            }
    except Exception:
        pass
    return None


# ------------------------------------------------------------------
# CVE-2024-4577 — PHP CGI 参数注入 RCE（Windows）
# ------------------------------------------------------------------

@_cve({
    "id": "CVE-2024-4577", "name": "PHP CGI 参数注入 RCE",
    "severity": "critical", "cvss": 9.8,
    "remediation": "升级至 PHP 8.3.8+、8.2.20+、8.1.29+；禁用 CGI 模式",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-4577"],
})
def check_php_cgi(client: httpx.Client, base_url: str) -> dict | None:
    try:
        # 探测 PHP CGI 特征（无害参数测试）
        r = client.get(f"{base_url}/index.php?%ADd+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input")
        if r.status_code in (200, 400, 500) and "php" in r.headers.get("content-type", "").lower():
            return {
                "evidence": f"PHP CGI 可能存在参数注入（HTTP {r.status_code}）",
                "note": "需在 Windows 服务器上进一步验证，仅限授权测试",
                "confidence": "medium",
            }
        # 检测 PHP 版本指纹
        r2 = client.get(base_url)
        powered = r2.headers.get("x-powered-by", "")
        if powered.startswith("PHP/"):
            version_str = powered.replace("PHP/", "")
            return {
                "evidence": f"PHP 版本: {version_str}，请确认是否在受影响范围（< 8.1.29 / 8.2.20 / 8.3.8）",
                "confidence": "low",
            }
    except Exception:
        pass
    return None


# ------------------------------------------------------------------
# CVE-2023-4966 — Citrix Bleed（NetScaler 敏感信息泄露）
# ------------------------------------------------------------------

@_cve({
    "id": "CVE-2023-4966", "name": "Citrix Bleed — NetScaler 会话令牌泄露",
    "severity": "critical", "cvss": 9.4,
    "remediation": "升级 NetScaler ADC/Gateway 至修复版本，立即吊销并重新颁发会话令牌",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-4966"],
})
def check_citrix_bleed(client: httpx.Client, base_url: str) -> dict | None:
    try:
        # 检测 Citrix NetScaler 指纹
        citrix_paths = ["/vpn/index.html", "/logon/LogonPoint/index.html",
                        "/cgi/login", "/nf/auth/getAuthenticationRequirements.do"]
        for path in citrix_paths:
            r = client.get(f"{base_url}{path}")
            if r.status_code in (200, 302) and any(
                s in r.text for s in ("Citrix", "NetScaler", "logon_form")
            ):
                return {
                    "evidence": f"发现 Citrix NetScaler/Gateway: {path}",
                    "note": "请检查 NetScaler 版本，CVE-2023-4966 影响 ADC 13.1 < 13.1-49.13 等版本",
                    "confidence": "high",
                }
    except Exception:
        pass
    return None


# ------------------------------------------------------------------
# CVE-2023-27997 — Fortinet FortiOS SSL-VPN Heap Overflow RCE
# ------------------------------------------------------------------

@_cve({
    "id": "CVE-2023-27997", "name": "Fortinet FortiOS SSL-VPN RCE",
    "severity": "critical", "cvss": 9.8,
    "remediation": "升级 FortiOS 至 7.2.5+、7.0.12+、6.4.13+、6.2.15+、6.0.17+",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-27997"],
})
def check_fortinet(client: httpx.Client, base_url: str) -> dict | None:
    try:
        forti_paths = ["/remote/login", "/remote/logincheck", "/vpn/index.html"]
        for path in forti_paths:
            r = client.get(f"{base_url}{path}")
            if r.status_code in (200, 301, 302) and any(
                s in r.text for s in ("FortiGate", "FortiOS", "Fortinet", "SSLVPN")
            ):
                return {
                    "evidence": f"发现 Fortinet FortiOS SSL-VPN: {path}",
                    "note": "请检查 FortiOS 版本是否在受影响范围内",
                    "confidence": "high",
                }
    except Exception:
        pass
    return None


# ------------------------------------------------------------------
# CVE-2024-3400 — Palo Alto PAN-OS 命令注入 RCE
# ------------------------------------------------------------------

@_cve({
    "id": "CVE-2024-3400", "name": "Palo Alto PAN-OS GlobalProtect RCE",
    "severity": "critical", "cvss": 10.0,
    "remediation": "升级至 PAN-OS 10.2.9-h1+、11.0.4-h1+、11.1.2-h3+",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-3400"],
})
def check_panos(client: httpx.Client, base_url: str) -> dict | None:
    try:
        r = client.get(f"{base_url}/global-protect/login.esp")
        if r.status_code == 200 and any(
            s in r.text for s in ("GlobalProtect", "Palo Alto", "PAN-OS")
        ):
            return {
                "evidence": f"发现 Palo Alto GlobalProtect 门户",
                "note": "请确认 PAN-OS 版本，CVE-2024-3400 要求 GlobalProtect 已启用且设备遥测开启",
                "confidence": "high",
            }
    except Exception:
        pass
    return None


# ------------------------------------------------------------------
# CVE-2022-47966 — Zoho ManageEngine RCE
# ------------------------------------------------------------------

@_cve({
    "id": "CVE-2022-47966", "name": "Zoho ManageEngine 未授权 RCE",
    "severity": "critical", "cvss": 9.8,
    "remediation": "升级受影响的 ManageEngine 产品至最新版本",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-47966"],
})
def check_manageengine(client: httpx.Client, base_url: str) -> dict | None:
    try:
        me_paths = ["/ManageEngine/", "/samlLogin", "/SamlResponseServlet"]
        r = client.get(base_url)
        if any(s in r.text for s in ("ManageEngine", "ZOHO Corp", "Zoho")):
            return {
                "evidence": "发现 ManageEngine 产品",
                "note": "请确认产品版本，CVE-2022-47966 通过 SAML 端点触发",
                "confidence": "high",
            }
        for path in me_paths:
            r2 = client.get(f"{base_url}{path}")
            if r2.status_code == 200 and "ManageEngine" in r2.text:
                return {"evidence": f"ManageEngine 路径可访问: {path}"}
    except Exception:
        pass
    return None


# ------------------------------------------------------------------
# CVE-2023-34362 — MOVEit Transfer SQLi → RCE
# ------------------------------------------------------------------

@_cve({
    "id": "CVE-2023-34362", "name": "MOVEit Transfer SQL 注入 RCE",
    "severity": "critical", "cvss": 9.8,
    "remediation": "立即更新 MOVEit Transfer，并检查 webshell 植入情况",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-34362"],
})
def check_moveit(client: httpx.Client, base_url: str) -> dict | None:
    try:
        moveit_paths = ["/moveitisapi/moveitisapi.dll", "/human.aspx",
                        "/guestaccess.aspx", "/api/v1/token"]
        for path in moveit_paths:
            r = client.get(f"{base_url}{path}")
            if r.status_code in (200, 302, 401) and any(
                s in r.text for s in ("MOVEit", "moveit", "ipswitch")
            ):
                return {
                    "evidence": f"发现 MOVEit Transfer: {path}（HTTP {r.status_code}）",
                    "note": "MOVEit Transfer 存在高危 SQLi 漏洞，建议立即更新",
                    "confidence": "high",
                }
    except Exception:
        pass
    return None


# ------------------------------------------------------------------
# CVE-2024-21762 — Fortinet FortiOS 越权文件读取
# ------------------------------------------------------------------

@_cve({
    "id": "CVE-2024-21762", "name": "Fortinet FortiOS 越权文件读取",
    "severity": "critical", "cvss": 9.6,
    "remediation": "升级 FortiOS 至 7.4.3+、7.2.7+、7.0.14+、6.4.15+",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-21762"],
})
def check_fortios_file_read(client: httpx.Client, base_url: str) -> dict | None:
    try:
        r = client.get(f"{base_url}/api/v2/monitor/system/status")
        if r.status_code == 200 and any(
            s in r.text for s in ('"serial"', '"version"', '"type":"FortiGate"')
        ):
            version_match = re.search(r'"version"\s*:\s*"([^"]+)"', r.text)
            return {
                "evidence": f"FortiOS API 端点可访问，版本: {version_match.group(1) if version_match else '未知'}",
                "confidence": "high",
            }
    except Exception:
        pass
    return None


# ------------------------------------------------------------------
# CVE-2023-42793 — JetBrains TeamCity 未授权 RCE
# ------------------------------------------------------------------

@_cve({
    "id": "CVE-2023-42793", "name": "JetBrains TeamCity 未授权 RCE",
    "severity": "critical", "cvss": 9.8,
    "remediation": "升级 TeamCity 至 2023.05.4+",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-42793"],
})
def check_teamcity(client: httpx.Client, base_url: str) -> dict | None:
    try:
        for path in ["/login.html", "/", "/app/rest/server"]:
            r = client.get(f"{base_url}{path}")
            if r.status_code in (200, 401) and any(
                s in r.text for s in ("TeamCity", "JetBrains")
            ):
                version_match = re.search(r'TeamCity[^\d]*(\d{4}\.\d+(?:\.\d+)?)', r.text)
                return {
                    "evidence": f"发现 TeamCity，版本: {version_match.group(1) if version_match else '未知'}",
                    "note": "CVE-2023-42793 可通过 /app/rest/users/id:1/tokens/RPC2 触发（需授权验证）",
                    "confidence": "high",
                }
    except Exception:
        pass
    return None


# ------------------------------------------------------------------
# CVE-2024-4040 — CrushFTP 服务端模板注入（SSTI）
# ------------------------------------------------------------------

@_cve({
    "id": "CVE-2024-4040", "name": "CrushFTP VFS 沙箱逃逸 / 未授权文件读取",
    "severity": "critical", "cvss": 9.8,
    "remediation": "升级 CrushFTP 至 11.1.0+（v10 用户升级至 10.7.1+）",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-4040"],
})
def check_crushftp(client: httpx.Client, base_url: str) -> dict | None:
    try:
        r = client.get(f"{base_url}/")
        if "CrushFTP" in r.text or "crushftp" in r.text.lower():
            version_match = re.search(r'CrushFTP[^\d]*(\d+\.\d+(?:\.\d+)?)', r.text)
            return {
                "evidence": f"发现 CrushFTP，版本: {version_match.group(1) if version_match else '未知'}",
                "confidence": "high",
            }
    except Exception:
        pass
    return None


# ------------------------------------------------------------------
# 通用 WordPress 检测
# ------------------------------------------------------------------

@_cve({
    "id": "WP-DETECT", "name": "WordPress 安装检测",
    "severity": "info", "cvss": 0.0,
    "remediation": "确保 WordPress 核心、主题和插件保持最新版本",
    "references": [],
})
def check_wordpress(client: httpx.Client, base_url: str) -> dict | None:
    try:
        r = client.get(base_url)
        if any(s in r.text for s in ("wp-content", "wp-includes", "WordPress")):
            # 获取 WordPress 版本
            r2 = client.get(f"{base_url}/wp-login.php")
            version_match = re.search(r'ver=(\d+\.\d+(?:\.\d+)?)', r2.text)
            plugins = []
            # 检测常见高危插件
            for plugin in ["woocommerce", "contact-form-7", "elementor", "yoast-seo"]:
                rp = client.get(f"{base_url}/wp-content/plugins/{plugin}/readme.txt")
                if rp.status_code == 200:
                    plugins.append(plugin)
            return {
                "evidence": (
                    f"WordPress 站点，版本: {version_match.group(1) if version_match else '未知'}, "
                    f"检测到插件: {', '.join(plugins) or '无'}"
                ),
                "note": "建议使用 WPScan 进行深度 WordPress 漏洞扫描",
                "confidence": "high",
            }
    except Exception:
        pass
    return None


# ------------------------------------------------------------------
# 主接口
# ------------------------------------------------------------------

def onedaypoc_scan(
    target: str,
    severity: str = "critical,high",
) -> dict[str, Any]:
    """
    对目标执行 1-day CVE PoC 检测。
    :param target:   目标 URL
    :param severity: 严重程度过滤
    """
    allowed = {s.strip().lower() for s in severity.split(",")}
    base_url = target.rstrip("/")
    results = []

    with httpx.Client(
        follow_redirects=True,
        timeout=TIMEOUT,
        verify=False,
        headers={"User-Agent": UA},
    ) as client:
        for meta, check_fn in _CHECKS:
            if meta["severity"] not in allowed:
                continue
            try:
                hit = check_fn(client, base_url)
                if hit:
                    results.append(CVEResult(
                        cve_id=meta["id"],
                        name=meta["name"],
                        severity=meta["severity"],
                        cvss=meta["cvss"],
                        target=hit.get("matched_at", base_url),
                        vulnerable=hit.get("confidence", "medium") == "high",
                        evidence=hit.get("evidence", ""),
                        remediation=meta["remediation"],
                        references=meta["references"],
                    ))
            except Exception:
                continue

    return {
        "target": target,
        "cve_checks_run": len(_CHECKS),
        "findings": [
            {
                "cve_id": r.cve_id,
                "name": r.name,
                "severity": r.severity,
                "cvss": r.cvss,
                "target": r.target,
                "vulnerable": r.vulnerable,
                "evidence": r.evidence,
                "remediation": r.remediation,
                "references": r.references,
            }
            for r in results
        ],
        "total": len(results),
    }
