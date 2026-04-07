"""
httpx_tool — Web 服务探测（httpx + Python httpx fallback）
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

import httpx as _httpx

from tools.web_utils import normalize_string_list, summarize_http_response


def httpx_probe(
    target: str,
    paths: list[str] | str | None = None,
    headers: dict[str, str] | None = None,
    capture_body: bool = False,
    max_body_chars: int = 1200,
) -> dict[str, Any]:
    """
    探测 Web 服务基本信息。
    优先使用 Go httpx 二进制（projectdiscovery/httpx），
    若不存在则降级为 Python httpx 探测。
    """
    normalized_paths = normalize_string_list(paths)
    if shutil.which("httpx") and not headers and not capture_body:
        return _probe_with_binary(target, normalized_paths)
    return _probe_with_python(target, normalized_paths, headers=headers, capture_body=capture_body, max_body_chars=max_body_chars)


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

def _probe_with_python(
    target: str,
    paths: list[str],
    headers: dict[str, str] | None = None,
    capture_body: bool = False,
    max_body_chars: int = 1200,
) -> dict[str, Any]:
    urls = [target] + [f"{target.rstrip('/')}/{p.lstrip('/')}" for p in paths]
    results = []
    merged_headers = {"User-Agent": "Mozilla/5.0 (PentestPilot/1.0)"}
    if headers:
        merged_headers.update(headers)

    with _httpx.Client(
        follow_redirects=True,
        timeout=15.0,
        verify=False,
        headers=merged_headers,
    ) as client:
        for url in urls:
            try:
                resp = client.get(url)
                results.append(
                    summarize_http_response(
                        resp,
                        include_body=capture_body,
                        max_body_chars=max_body_chars,
                    )
                )
            except Exception as e:
                results.append({"url": url, "error": str(e)})

    return {"results": results, "tool": "python-httpx"}
