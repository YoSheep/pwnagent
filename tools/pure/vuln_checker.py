"""
纯 Python 漏洞检查器（替代 nuclei 基础检测）
内置常见漏洞/配置错误检测规则，无需外部依赖。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass
class VulnRule:
    id: str
    name: str
    severity: str           # critical / high / medium / low / info
    description: str
    cvss: float = 0.0
    tags: list[str] = field(default_factory=list)


# ------------------------------------------------------------------
# 内置规则库
# ------------------------------------------------------------------

_RULES: list[tuple[VulnRule, callable]] = []


def _rule(vuln: VulnRule):
    """装饰器：注册检测函数。"""
    def decorator(fn):
        _RULES.append((vuln, fn))
        return fn
    return decorator


@_rule(VulnRule("EXPO-GIT", "Git 仓库暴露", "high",
                "/.git/HEAD 可公开访问，源代码可能泄露。", 7.5, ["exposure", "git"]))
def check_git_exposure(client: httpx.Client, base_url: str) -> dict | None:
    try:
        r = client.get(f"{base_url}/.git/HEAD", timeout=8)
        if r.status_code == 200 and "ref:" in r.text:
            return {"matched_at": f"{base_url}/.git/HEAD", "evidence": r.text[:100]}
    except Exception:
        pass
    return None


@_rule(VulnRule("EXPO-ENV", ".env 文件暴露", "critical",
                ".env 文件可公开访问，可能包含数据库密码、API 密钥等敏感信息。", 9.1, ["exposure", "config"]))
def check_env_exposure(client: httpx.Client, base_url: str) -> dict | None:
    for path in ["/.env", "/.env.local", "/.env.production", "/.env.backup"]:
        try:
            r = client.get(f"{base_url}{path}", timeout=8)
            if r.status_code == 200 and any(k in r.text for k in ("DB_PASSWORD", "SECRET_KEY", "API_KEY", "PASSWORD=")):
                return {"matched_at": f"{base_url}{path}", "evidence": r.text[:200]}
        except Exception:
            pass
    return None


@_rule(VulnRule("EXPO-PHPINFO", "phpinfo() 页面暴露", "medium",
                "phpinfo() 页面泄露 PHP 配置、服务器路径、扩展信息。", 5.3, ["exposure", "php"]))
def check_phpinfo(client: httpx.Client, base_url: str) -> dict | None:
    for path in ["/phpinfo.php", "/info.php", "/php_info.php", "/test.php"]:
        try:
            r = client.get(f"{base_url}{path}", timeout=8)
            if r.status_code == 200 and "PHP Version" in r.text:
                return {"matched_at": f"{base_url}{path}"}
        except Exception:
            pass
    return None


@_rule(VulnRule("MISCONF-LISTING", "目录列举", "medium",
                "Web 服务器允许目录列举，可能泄露敏感文件。", 5.3, ["misconfiguration"]))
def check_dir_listing(client: httpx.Client, base_url: str) -> dict | None:
    for path in ["/", "/uploads/", "/backup/", "/files/", "/static/"]:
        try:
            r = client.get(f"{base_url}{path}", timeout=8)
            if r.status_code == 200 and any(s in r.text.lower() for s in
                                            ("index of /", "directory listing", "parent directory")):
                return {"matched_at": f"{base_url}{path}"}
        except Exception:
            pass
    return None


@_rule(VulnRule("MISCONF-CORS", "宽松 CORS 配置", "medium",
                "Access-Control-Allow-Origin: * 允许任意来源跨域请求。", 5.4, ["misconfiguration", "cors"]))
def check_cors(client: httpx.Client, base_url: str) -> dict | None:
    try:
        r = client.get(base_url, headers={"Origin": "https://evil.com"}, timeout=8)
        acao = r.headers.get("access-control-allow-origin", "")
        if acao == "*" or acao == "https://evil.com":
            return {"matched_at": base_url, "evidence": f"Access-Control-Allow-Origin: {acao}"}
    except Exception:
        pass
    return None


@_rule(VulnRule("MISCONF-HEADERS", "安全响应头缺失", "low",
                "缺少 X-Frame-Options、CSP、HSTS 等安全响应头。", 3.1, ["misconfiguration", "headers"]))
def check_security_headers(client: httpx.Client, base_url: str) -> dict | None:
    try:
        r = client.get(base_url, timeout=8)
        missing = []
        for header in ("x-frame-options", "content-security-policy",
                       "strict-transport-security", "x-content-type-options"):
            if header not in r.headers:
                missing.append(header)
        if len(missing) >= 2:
            return {"matched_at": base_url, "evidence": f"缺少: {', '.join(missing)}"}
    except Exception:
        pass
    return None


@_rule(VulnRule("EXPO-BACKUP", "备份文件暴露", "high",
                "发现可公开访问的备份文件，可能包含源代码或数据。", 7.5, ["exposure", "backup"]))
def check_backup_files(client: httpx.Client, base_url: str) -> dict | None:
    # 从 URL 提取域名猜测备份文件名
    hostname = base_url.split("//")[-1].split("/")[0].split(":")[0]
    candidates = [
        "/backup.zip", "/backup.tar.gz", "/backup.sql",
        f"/{hostname}.zip", f"/{hostname}.sql",
        "/db.sql", "/database.sql", "/dump.sql",
        "/wp-backup.zip", "/site.zip",
    ]
    for path in candidates:
        try:
            r = client.head(f"{base_url}{path}", timeout=8)
            if r.status_code == 200:
                return {"matched_at": f"{base_url}{path}"}
        except Exception:
            pass
    return None


@_rule(VulnRule("EXPO-ADMIN", "管理后台暴露", "medium",
                "发现可公开访问的管理后台路径。", 5.3, ["exposure", "admin"]))
def check_admin_panels(client: httpx.Client, base_url: str) -> dict | None:
    paths = ["/admin", "/admin/", "/wp-admin/", "/administrator/",
             "/manager/", "/cpanel", "/phpmyadmin/", "/adminer.php"]
    found = []
    for path in paths:
        try:
            r = client.get(f"{base_url}{path}", timeout=8)
            if r.status_code in (200, 401, 403):
                found.append({"path": path, "status": r.status_code})
        except Exception:
            pass
    if found:
        return {"matched_at": base_url, "evidence": found}
    return None


@_rule(VulnRule("EXPO-SWAGGER", "API 文档暴露", "info",
                "Swagger/OpenAPI 文档可公开访问，泄露完整 API 结构。", 0.0, ["exposure", "api"]))
def check_swagger(client: httpx.Client, base_url: str) -> dict | None:
    for path in ["/swagger-ui.html", "/api/docs", "/api/swagger.json",
                 "/v1/swagger.json", "/openapi.json", "/docs"]:
        try:
            r = client.get(f"{base_url}{path}", timeout=8)
            if r.status_code == 200 and any(k in r.text for k in ("swagger", "openapi", "Swagger UI")):
                return {"matched_at": f"{base_url}{path}"}
        except Exception:
            pass
    return None


# ------------------------------------------------------------------
# 主接口
# ------------------------------------------------------------------

def python_vuln_check(target: str, severity: str = "critical,high,medium") -> dict[str, Any]:
    """
    纯 Python 漏洞检查，nuclei 不可用时的 fallback。
    :param target:   目标 URL
    :param severity: 逗号分隔的严重程度过滤
    """
    allowed_severities = {s.strip().lower() for s in severity.split(",")}
    base_url = target.rstrip("/")

    findings = []
    with httpx.Client(
        follow_redirects=True,
        timeout=10.0,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (PwnAgent/1.0)"},
    ) as client:
        for vuln, check_fn in _RULES:
            if vuln.severity not in allowed_severities:
                continue
            result = check_fn(client, base_url)
            if result:
                findings.append({
                    "template_id": vuln.id,
                    "name": vuln.name,
                    "severity": vuln.severity,
                    "description": vuln.description,
                    "matched_at": result.get("matched_at", target),
                    "evidence": result.get("evidence", ""),
                    "cvss_score": vuln.cvss,
                    "tags": vuln.tags,
                    "tool": "python-vuln-checker",
                })

    return {
        "findings": findings,
        "total": len(findings),
        "target": target,
        "tool": "python-vuln-checker",
    }
