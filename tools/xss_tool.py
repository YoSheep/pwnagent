"""
xss_tool — XSS 检测（反射型 + DOM 型）
使用 httpx 做基础检测，可选接入 Playwright 验证 DOM XSS。
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Any

import httpx


# 无害探针（不会实际弹框，仅检测回显）
_REFLECTION_PROBES = [
    '<scr\x00ipt>alert(1)</script>',  # 空字节绕过
    '"><img src=x onerror=prompt(1)>',
    "';alert(1)//",
    '{{7*7}}',                          # 模板注入检测
    'javascript:alert(1)',
]

_XSS_INDICATORS = [
    r'<script[^>]*>alert\(',
    r'onerror\s*=\s*["\']?prompt\(',
    r'javascript:alert',
    r'<img[^>]+onerror',
]


def xss_scan(target: str, params: list[str] | None = None) -> dict[str, Any]:
    """
    扫描目标 URL 的 XSS 漏洞。
    :param target: 目标 URL（含查询参数，如 http://host/search?q=test）
    :param params: 额外要测试的参数名列表
    """
    parsed = urllib.parse.urlparse(target)
    existing_params = dict(urllib.parse.parse_qsl(parsed.query))
    all_params = list(existing_params.keys()) + (params or [])

    if not all_params:
        # 没有参数时探测常见参数名
        all_params = ["q", "search", "query", "id", "name", "input", "text", "value"]

    results = []
    with httpx.Client(
        follow_redirects=True,
        timeout=15.0,
        verify=False,
        headers={"User-Agent": "Mozilla/5.0 (PwnAgent/1.0)"},
    ) as client:
        for param in all_params:
            for probe in _REFLECTION_PROBES:
                encoded = urllib.parse.quote(probe, safe="")
                test_params = dict(existing_params)
                test_params[param] = probe

                try:
                    resp = client.get(
                        parsed._replace(query="").geturl(),
                        params=test_params,
                    )
                    body = resp.text

                    # 检查探针是否原样回显（反射型 XSS 指征）
                    reflected = probe in body or urllib.parse.unquote(encoded) in body
                    # 检查是否触发 XSS 上下文
                    in_xss_context = any(
                        re.search(pattern, body, re.IGNORECASE)
                        for pattern in _XSS_INDICATORS
                    )

                    if reflected or in_xss_context:
                        results.append({
                            "type": "reflected_xss",
                            "param": param,
                            "probe": probe,
                            "url": str(resp.url),
                            "status_code": resp.status_code,
                            "reflected": reflected,
                            "in_xss_context": in_xss_context,
                            "evidence": _extract_context(body, probe, 100),
                        })
                except Exception as e:
                    results.append({"param": param, "probe": probe, "error": str(e)})

    # DOM XSS 检测（Playwright，可选）
    dom_results = _dom_xss_scan(target) if _playwright_available() else []

    return {
        "target": target,
        "reflected_xss": results,
        "dom_xss": dom_results,
        "vulnerable": len(results) > 0 or len(dom_results) > 0,
    }


def _extract_context(html: str, probe: str, context_chars: int = 100) -> str:
    idx = html.find(probe)
    if idx == -1:
        return ""
    start = max(0, idx - context_chars)
    end = min(len(html), idx + len(probe) + context_chars)
    return html[start:end]


def _playwright_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


def _dom_xss_scan(target: str) -> list[dict]:
    """使用 Playwright 检测 DOM XSS（需安装 playwright）。"""
    results = []
    try:
        from playwright.sync_api import sync_playwright

        dom_probes = [
            "#<img src=x onerror=window._xss_triggered=1>",
            "?xss=<script>window._xss_triggered=1</script>",
        ]

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.on("dialog", lambda d: d.dismiss())  # 关闭 alert 弹窗

            for probe_suffix in dom_probes:
                test_url = target + probe_suffix
                try:
                    page.goto(test_url, timeout=10000)
                    triggered = page.evaluate("() => window._xss_triggered === 1")
                    if triggered:
                        results.append({
                            "type": "dom_xss",
                            "url": test_url,
                            "probe": probe_suffix,
                        })
                except Exception:
                    pass

            browser.close()
    except Exception:
        pass

    return results
