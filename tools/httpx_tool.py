"""
httpx_tool — Web 服务探测（httpx + Python httpx fallback）
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

import httpx as _httpx


def httpx_probe(target: str, paths: list[str] | None = None) -> dict[str, Any]:
    """
    探测 Web 服务基本信息。
    优先使用 Go httpx 二进制（projectdiscovery/httpx），
    若不存在则降级为 Python httpx 探测。
    """
    if shutil.which("httpx"):
        return _probe_with_binary(target, paths or [])
    return _probe_with_python(target, paths or [])


# ------------------------------------------------------------------
# Go httpx 二进制
# ------------------------------------------------------------------

def _probe_with_binary(target: str, paths: list) -> dict[str, Any]:
    targets = [target] + [f"{target.rstrip('/')}/{p.lstrip('/')}" for p in paths]
    input_data = "\n".join(targets)

    cmd = [
        "httpx",
        "-title", "-status-code", "-tech-detect",
        "-content-length", "-server", "-follow-redirects",
        "-json", "-silent",
    ]
    try:
        proc = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired:
        return {"error": "httpx 超时"}
    except Exception as e:
        return {"error": f"httpx 执行失败: {e}"}

    results = []
    for line in proc.stdout.strip().splitlines():
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return {"results": results, "tool": "httpx-binary"}


# ------------------------------------------------------------------
# Python httpx fallback
# ------------------------------------------------------------------

def _probe_with_python(target: str, paths: list) -> dict[str, Any]:
    urls = [target] + [f"{target.rstrip('/')}/{p.lstrip('/')}" for p in paths]
    results = []

    with _httpx.Client(
        follow_redirects=True,
        timeout=15.0,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (PentestPilot/1.0)"},
    ) as client:
        for url in urls:
            try:
                resp = client.get(url)
                title = _extract_title(resp.text)
                results.append({
                    "url": str(resp.url),
                    "status_code": resp.status_code,
                    "title": title,
                    "content_length": len(resp.content),
                    "server": resp.headers.get("server", ""),
                    "x_powered_by": resp.headers.get("x-powered-by", ""),
                    "content_type": resp.headers.get("content-type", ""),
                    "redirect_chain": [str(r.url) for r in resp.history],
                })
            except Exception as e:
                results.append({"url": url, "error": str(e)})

    return {"results": results, "tool": "python-httpx"}


def _extract_title(html: str) -> str:
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:200] if m else ""
