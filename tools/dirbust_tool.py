"""
dirbust_tool — 目录/文件爆破（纯 Python，asyncio 并发）
内置精选字典，覆盖常见敏感路径、管理后台、API 端点、备份文件。
"""
from __future__ import annotations

import asyncio
from typing import Any

import httpx

_UA = "Mozilla/5.0 (PentestPilot/1.0)"

# 精选路径字典（按类别组织）
_WORDLIST = {
    "admin": [
        "/admin", "/admin/", "/admin/login", "/admin/index.php",
        "/administrator/", "/administrator/index.php",
        "/wp-admin/", "/wp-login.php",
        "/cpanel", "/cpanel/", "/whm", "/webmail",
        "/manager/", "/manager/html",          # Tomcat Manager
        "/phpmyadmin/", "/phpmyadmin/index.php",
        "/adminer.php", "/adminer/",
        "/dashboard/", "/panel/", "/control/",
        "/user/login", "/users/sign_in",
    ],
    "api": [
        "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
        "/api/swagger.json", "/api/openapi.json",
        "/swagger-ui.html", "/swagger-ui/", "/swagger/",
        "/openapi.json", "/openapi.yaml",
        "/graphql", "/graphiql", "/playground",
        "/rest/", "/rest/api/",
        "/api/users", "/api/admin", "/api/config",
    ],
    "sensitive": [
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
        "/.svn/entries", "/.svn/wc.db",
        "/.DS_Store",
        "/config.php", "/config.yml", "/config.yaml", "/config.json",
        "/configuration.php",          # Joomla
        "/settings.py", "/settings.php",
        "/web.config", "/applicationHost.config",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt",
    ],
    "backup": [
        "/backup/", "/backup.zip", "/backup.tar.gz", "/backup.sql",
        "/backup.bak", "/db.sql", "/database.sql", "/dump.sql",
        "/site.zip", "/www.zip", "/html.zip",
        "/old/", "/bak/", "/archive/",
        "/wp-backup.zip",
    ],
    "logs": [
        "/logs/", "/log/", "/log.txt", "/error.log", "/access.log",
        "/debug.log", "/app.log", "/application.log",
        "/var/log/", "/tmp/",
    ],
    "common": [
        "/info.php", "/phpinfo.php", "/test.php", "/test.html",
        "/upload/", "/uploads/", "/files/", "/file/",
        "/download/", "/downloads/",
        "/static/", "/assets/", "/public/",
        "/src/", "/source/",
        "/shell.php", "/cmd.php", "/webshell.php",   # 检测是否已被入侵
        "/healthz", "/health", "/ping", "/status",
        "/metrics",                                   # Prometheus
        "/actuator",                                  # Spring Boot
        "/console",                                   # H2/Jetty console
    ],
    "auth_bypass": [
        "/admin%20/", "/admin%2f/", "/ADMIN/",
        "/.." , "/./admin",
        "/admin;/", "/admin?",
    ],
}

_ALL_PATHS = [p for paths in _WORDLIST.values() for p in paths]


async def _probe_path(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    interesting_codes: set[int],
) -> dict | None:
    url = base_url.rstrip("/") + path
    try:
        resp = await client.head(url, timeout=6)
        if resp.status_code in interesting_codes:
            # 对有趣的响应做 GET 获取更多信息
            try:
                get_resp = await client.get(url, timeout=8)
                return {
                    "path": path,
                    "url": url,
                    "status": get_resp.status_code,
                    "size": len(get_resp.content),
                    "content_type": get_resp.headers.get("content-type", ""),
                    "server": get_resp.headers.get("server", ""),
                    "redirect": str(get_resp.url) if get_resp.history else None,
                    "title": _extract_title(get_resp.text),
                }
            except Exception:
                return {"path": path, "url": url, "status": resp.status_code}
    except Exception:
        pass
    return None


async def _async_dirbust(
    base_url: str,
    paths: list[str],
    interesting_codes: set[int],
    concurrency: int = 30,
) -> list[dict]:
    sem = asyncio.Semaphore(concurrency)
    results = []

    async with httpx.AsyncClient(
        follow_redirects=False,
        verify=False,
        headers={"User-Agent": _UA},
        timeout=10.0,
    ) as client:
        async def bounded_probe(path):
            async with sem:
                return await _probe_path(client, base_url, path, interesting_codes)

        raw = await asyncio.gather(*[bounded_probe(p) for p in paths])
        results = [r for r in raw if r is not None]

    return results


def dirbust(
    target: str,
    categories: list[str] | None = None,
    extra_paths: list[str] | None = None,
    interesting_codes: list[int] | None = None,
) -> dict[str, Any]:
    """
    目录/文件爆破。
    :param target:           目标 URL
    :param categories:       要测试的类别（admin/api/sensitive/backup/logs/common/auth_bypass）
                             None 表示全部
    :param extra_paths:      额外自定义路径列表
    :param interesting_codes: 感兴趣的 HTTP 状态码，默认 [200,204,301,302,401,403,500]
    """
    codes = set(interesting_codes or [200, 204, 301, 302, 401, 403, 500])

    # 构建路径列表
    if categories:
        paths = []
        for cat in categories:
            paths.extend(_WORDLIST.get(cat, []))
    else:
        paths = list(_ALL_PATHS)

    if extra_paths:
        paths.extend(extra_paths)

    # 去重
    paths = list(dict.fromkeys(paths))

    # 运行
    from tools.pure import run_async
    findings = run_async(_async_dirbust(target, paths, codes))

    # 分类结果
    high_interest = [f for f in findings if f["status"] in (200, 204)]
    auth_protected = [f for f in findings if f["status"] in (401, 403)]
    redirects = [f for f in findings if f["status"] in (301, 302)]

    return {
        "target": target,
        "paths_tested": len(paths),
        "findings": findings,
        "high_interest": high_interest,  # 直接可访问
        "auth_protected": auth_protected,  # 需认证
        "redirects": redirects,
        "total": len(findings),
    }


def _extract_title(html: str) -> str:
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:100] if m else ""

