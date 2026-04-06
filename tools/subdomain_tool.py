"""
subdomain_tool — 纯 Python 子域名枚举
DNS 爆破 + 证书透明日志（crt.sh）查询
"""
from __future__ import annotations

import asyncio
import json
import socket
from typing import Any

import httpx

# 常见子域名字典（内置精简版）
_WORDLIST = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "admin", "administrator", "portal", "dashboard", "panel",
    "api", "api2", "api-v1", "v1", "v2", "rest",
    "dev", "development", "staging", "stage", "test", "testing",
    "uat", "qa", "sandbox", "demo", "beta",
    "app", "apps", "mobile", "m",
    "blog", "news", "forum", "community", "wiki",
    "shop", "store", "pay", "payment",
    "cdn", "static", "assets", "media", "images", "img",
    "vpn", "remote", "rdp", "ssh",
    "git", "gitlab", "github", "svn", "jenkins", "ci", "cd",
    "jira", "confluence", "wiki", "docs", "help", "support",
    "internal", "intranet", "corp",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "monitor", "grafana", "prometheus", "kibana",
    "auth", "login", "sso", "oauth",
    "backup", "bak", "old", "archive",
    "mx", "mx1", "mx2", "ns", "ns1", "ns2",
]


async def _resolve(hostname: str) -> dict | None:
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, socket.gethostbyname, hostname)
        return {"subdomain": hostname, "ip": result, "source": "dns_bruteforce"}
    except (socket.gaierror, socket.herror):
        return None


async def _brute_dns(domain: str, wordlist: list[str], concurrency: int = 50) -> list[dict]:
    sem = asyncio.Semaphore(concurrency)

    async def bounded_resolve(sub):
        async with sem:
            return await _resolve(f"{sub}.{domain}")

    results = await asyncio.gather(*[bounded_resolve(w) for w in wordlist])
    return [r for r in results if r is not None]


def _query_crtsh(domain: str) -> list[dict]:
    """查询 crt.sh 证书透明日志，获取历史/当前子域名。"""
    found = []
    try:
        with httpx.Client(timeout=15.0, follow_redirects=True) as client:
            resp = client.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                headers={"Accept": "application/json"},
            )
            if resp.status_code == 200:
                entries = resp.json()
                seen = set()
                for entry in entries:
                    name = entry.get("name_value", "")
                    for sub in name.splitlines():
                        sub = sub.strip().lower().lstrip("*.")
                        if sub.endswith(f".{domain}") and sub not in seen:
                            seen.add(sub)
                            # 尝试解析 IP
                            try:
                                ip = socket.gethostbyname(sub)
                            except Exception:
                                ip = ""
                            found.append({
                                "subdomain": sub,
                                "ip": ip,
                                "source": "crt.sh",
                                "issuer": entry.get("issuer_name", ""),
                            })
    except Exception:
        pass
    return found


def subdomain_enum(
    domain: str,
    use_crtsh: bool = True,
    wordlist: list[str] | None = None,
) -> dict[str, Any]:
    """
    子域名枚举：DNS 爆破 + crt.sh 证书透明日志。
    :param domain:    根域名（如 example.com）
    :param use_crtsh: 是否查询 crt.sh（需要访问外网）
    :param wordlist:  自定义字典（可选，默认使用内置字典）
    """
    wl = wordlist or _WORDLIST
    results: dict[str, dict] = {}

    # 1. DNS 爆破
    from tools.pure import run_async
    brute_results = run_async(_brute_dns(domain, wl))

    for r in brute_results:
        results[r["subdomain"]] = r

    # 2. crt.sh 证书透明日志
    if use_crtsh:
        for r in _query_crtsh(domain):
            if r["subdomain"] not in results:
                results[r["subdomain"]] = r

    # 检测每个子域名的 Web 服务
    subdomains = list(results.values())
    _probe_web_services(subdomains)

    return {
        "domain": domain,
        "subdomains": subdomains,
        "total": len(subdomains),
        "with_web": sum(1 for s in subdomains if s.get("web_status")),
    }


def _probe_web_services(subdomains: list[dict]):
    """批量探测子域名的 Web 服务状态。"""
    with httpx.Client(
        follow_redirects=True,
        timeout=8.0,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (PwnAgent/1.0)"},
    ) as client:
        for sub in subdomains:
            hostname = sub["subdomain"]
            for scheme in ("https", "http"):
                try:
                    resp = client.get(f"{scheme}://{hostname}/", timeout=5)
                    sub["web_status"] = resp.status_code
                    sub["web_url"] = f"{scheme}://{hostname}/"
                    sub["web_title"] = _extract_title(resp.text)
                    sub["server"] = resp.headers.get("server", "")
                    break
                except Exception:
                    continue


def _extract_title(html: str) -> str:
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:100] if m else ""


