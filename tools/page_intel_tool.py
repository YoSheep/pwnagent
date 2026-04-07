"""
page_intel_tool — 页面理解与接口线索提取。
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse

from tools.web_utils import extract_html_surface, infer_endpoint_tags
from tools.web_workflow_tool import http_request

_ENDPOINT_PATTERNS = [
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|url\s*:)\s*\(?\s*["']([^"'?#]+(?:\?[^"']*)?)["']""", re.IGNORECASE),
    re.compile(r"""["']((?:/|\./|\.\./)?(?:api|graphql|rest|ajax|admin|login|upload|session)[^"'\\s<>]*)["']""", re.IGNORECASE),
]

_METHOD_PATTERN = re.compile(r"""\b(GET|POST|PUT|DELETE|PATCH)\b""", re.IGNORECASE)


def page_intel(
    target: str,
    path: str = "",
    headers: dict[str, str] | None = None,
    session_alias: str = "",
    include_external_scripts: bool = True,
    max_external_scripts: int = 5,
    max_body_chars: int = 2500,
) -> dict[str, Any]:
    """
    读取页面，提取表单、脚本、接口候选、参数名和下一跳页面线索。
    """
    include_external_scripts = _to_bool(include_external_scripts, default=True)
    max_external_scripts = _to_int(max_external_scripts, default=5, minimum=0, maximum=20)
    max_body_chars = _to_int(max_body_chars, default=2500, minimum=200, maximum=20000)

    page_result = http_request(
        target=target,
        path=path,
        method="GET",
        headers=headers,
        session_alias=session_alias,
        capture_body=True,
        max_body_chars=max_body_chars,
        follow_redirects=True,
    )
    response = page_result.get("response", {})
    body = response.get("body") or response.get("body_preview") or ""
    base_url = response.get("url") or target
    surface = extract_html_surface(base_url, body)

    inline_candidates = _extract_endpoint_candidates(base_url, surface.get("inline_scripts", []), source="inline_script")
    body_candidates = _extract_endpoint_candidates(base_url, [body], source="page_body")
    link_candidates = _link_candidates(base_url, surface.get("interesting_links", []), source="page_link")
    navigation_candidates = _navigation_candidates(base_url, surface)
    form_actions = _form_actions(base_url, surface)

    external_scripts = []
    script_candidates = []
    if include_external_scripts:
        for script_url in surface.get("script_sources", [])[:max_external_scripts]:
            script_result = http_request(
                target=script_url,
                method="GET",
                headers=headers,
                session_alias=session_alias,
                capture_body=True,
                max_body_chars=max_body_chars,
                follow_redirects=True,
            )
            script_response = script_result.get("response", {})
            script_body = script_response.get("body") or script_response.get("body_preview") or ""
            external_scripts.append({
                "url": script_response.get("url", script_url),
                "status_code": script_response.get("status_code", 0),
                "content_type": script_response.get("content_type", ""),
            })
            script_candidates.extend(
                _extract_endpoint_candidates(script_response.get("url", script_url), [script_body], source="external_script")
            )

    api_candidates = _sort_candidates(_dedupe_items(
        body_candidates + inline_candidates + script_candidates + form_actions + link_candidates
    ))
    navigation_candidates = _sort_candidates(_dedupe_items(
        navigation_candidates + form_actions + link_candidates
    ))
    params_observed = sorted({
        param
        for item in api_candidates
        for param in item.get("param_names", [])
    })

    page_summary = {
        "url": base_url,
        "title": response.get("title", ""),
        "status_code": response.get("status_code", 0),
        "form_actions": form_actions,
        "interesting_links": link_candidates,
        "navigation_candidates": navigation_candidates[:25],
        "script_sources": surface.get("script_sources", []),
        "external_scripts": external_scripts,
        "api_candidates": api_candidates[:40],
        "params_observed": params_observed[:40],
        "login_forms": surface.get("login_forms", []),
        "upload_forms": surface.get("upload_forms", []),
    }

    return {
        "target": target,
        "session_alias": session_alias or "default",
        "requested_url": page_result.get("requested_url", base_url),
        "response": response,
        "page_summary": page_summary,
    }


def _extract_endpoint_candidates(base_url: str, texts: list[str], source: str) -> list[dict[str, Any]]:
    results = []
    for text in texts:
        if not text:
            continue
        method_hint = _METHOD_PATTERN.search(text[:500])
        for pattern in _ENDPOINT_PATTERNS:
            for match in pattern.findall(text):
                candidate = str(match).strip()
                normalized = _normalize_candidate_url(base_url, candidate)
                if not normalized:
                    continue
                parsed = urlparse(normalized)
                results.append({
                    "url": normalized,
                    "path": parsed.path or "/",
                    "method": method_hint.group(1).upper() if method_hint else "GET",
                    "source": source,
                    "tags": infer_endpoint_tags(normalized),
                    "param_names": sorted(dict(parse_qsl(parsed.query)).keys()),
                })
    return results


def _form_actions(base_url: str, surface: dict[str, Any]) -> list[dict[str, Any]]:
    results = []
    for form in surface.get("forms", []):
        action = form.get("action") or base_url
        normalized = _normalize_candidate_url(base_url, action)
        if not normalized:
            continue
        input_names = [item.get("name", "") for item in form.get("inputs", []) if item.get("name")]
        results.append({
            "url": normalized,
            "path": urlparse(normalized).path or "/",
            "method": form.get("method", "GET"),
            "source": "form_action",
            "tags": infer_endpoint_tags(normalized, surface),
            "param_names": sorted(set(input_names)),
            "enctype": form.get("enctype", ""),
        })
    return results


def _link_candidates(base_url: str, links: list[str], source: str) -> list[dict[str, Any]]:
    results = []
    for link in links[:20]:
        normalized = _normalize_candidate_url(base_url, link)
        if not normalized:
            continue
        parsed = urlparse(normalized)
        results.append({
            "url": normalized,
            "path": parsed.path or "/",
            "method": "GET",
            "source": source,
            "tags": infer_endpoint_tags(normalized),
            "param_names": sorted(dict(parse_qsl(parsed.query)).keys()),
        })
    return results


def _navigation_candidates(base_url: str, surface: dict[str, Any]) -> list[dict[str, Any]]:
    results = []
    for item in surface.get("navigation_links", [])[:20]:
        normalized = _normalize_candidate_url(base_url, str(item.get("url", "")))
        if not normalized:
            continue
        parsed = urlparse(normalized)
        score = int(item.get("score", 0) or 0)
        tags = set(infer_endpoint_tags(normalized, surface))
        tags.add("navigation")
        if parsed.query:
            tags.add("dynamic")
        results.append({
            "url": normalized,
            "path": parsed.path or "/",
            "method": "GET",
            "source": "navigation_link",
            "tags": sorted(tags),
            "param_names": sorted(dict(parse_qsl(parsed.query)).keys()),
            "score": score,
            "reason": "；".join(item.get("reasons", [])),
        })
    return results


def _normalize_candidate_url(base_url: str, candidate: str) -> str:
    candidate = candidate.strip()
    if not candidate:
        return ""
    lowered = candidate.lower()
    if lowered.startswith(("javascript:", "data:", "mailto:", "#")):
        return ""
    return urljoin(base_url, candidate)


def _dedupe_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for item in items:
        key = f"{item.get('method', 'GET')} {item.get('url', '')}"
        existing = deduped.get(key)
        if not existing:
            deduped[key] = item
            continue
        merged_tags = sorted(set(existing.get("tags", [])) | set(item.get("tags", [])))
        merged_params = sorted(set(existing.get("param_names", [])) | set(item.get("param_names", [])))
        existing["tags"] = merged_tags
        existing["param_names"] = merged_params
        existing["score"] = max(int(existing.get("score", 0) or 0), int(item.get("score", 0) or 0))
        if not existing.get("reason") and item.get("reason"):
            existing["reason"] = item.get("reason", "")
    return list(deduped.values())


def _sort_candidates(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        items,
        key=lambda item: (
            -int(item.get("score", 0) or 0),
            "dynamic" not in item.get("tags", []),
            item.get("path", ""),
            item.get("url", ""),
        ),
    )


def _to_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"true", "1", "yes", "y", "on"}:
            return True
        if text in {"false", "0", "no", "n", "off"}:
            return False
    return default


def _to_int(value: Any, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    result = default
    if isinstance(value, bool):
        result = int(value)
    elif isinstance(value, int):
        result = value
    elif isinstance(value, float):
        result = int(value)
    elif isinstance(value, str):
        text = value.strip()
        if text and text.lstrip("-").isdigit():
            try:
                result = int(text)
            except Exception:
                result = default

    if minimum is not None and result < minimum:
        result = minimum
    if maximum is not None and result > maximum:
        result = maximum
    return result
