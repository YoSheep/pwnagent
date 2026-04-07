"""
Web 工具共用的 HTTP/HTML 解析辅助函数。
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse


_JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
_HIGH_VALUE_PATH_MARKERS = ("/admin", "/login", "/upload", "/api", "/dashboard")
_DYNAMIC_PATH_MARKERS = (
    "/cat",
    "/post",
    "/item",
    "/image",
    "/img",
    "/photo",
    "/gallery",
    "/album",
    "/article",
    "/view",
)
_DYNAMIC_PARAM_MARKERS = {
    "id",
    "cat",
    "category",
    "post",
    "item",
    "page",
    "image",
    "img",
    "photo",
    "album",
    "gallery",
    "view",
    "user",
    "user_id",
}
_DYNAMIC_EXTENSIONS = (".php", ".asp", ".aspx", ".jsp", ".do", ".action")


def normalize_string_list(value: list[str] | str | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            text = str(item).strip()
            if text:
                result.append(text)
        return result

    text = str(value).strip()
    if not text:
        return []
    if "," in text:
        return [part.strip() for part in text.split(",") if part.strip()]
    return [text]


def normalize_int_list(value: list[int] | str | None) -> list[int]:
    if value is None:
        return []
    if isinstance(value, list):
        return [int(item) for item in value]
    items = normalize_string_list(value)
    result: list[int] = []
    for item in items:
        try:
            result.append(int(item))
        except ValueError:
            continue
    return result


def extract_title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip()[:200] if match else ""


class _SurfaceParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.script_sources: list[str] = []
        self.inline_scripts: list[str] = []
        self._current_form: dict[str, Any] | None = None
        self._inside_script = False
        self._script_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        tag = tag.lower()

        if tag == "a":
            href = attr_map.get("href", "").strip()
            if href:
                self.links.append(urljoin(self.base_url, href))
            return

        if tag == "form":
            self._current_form = {
                "action": urljoin(self.base_url, attr_map.get("action", "") or self.base_url),
                "method": (attr_map.get("method", "get") or "get").upper(),
                "enctype": attr_map.get("enctype", "application/x-www-form-urlencoded"),
                "inputs": [],
            }
            self.forms.append(self._current_form)
            return

        if tag in {"input", "textarea", "select"} and self._current_form is not None:
            input_type = attr_map.get("type", "text" if tag == "input" else tag)
            self._current_form["inputs"].append({
                "name": attr_map.get("name", ""),
                "type": input_type.lower(),
                "value": attr_map.get("value", ""),
            })
            return

        if tag == "script":
            src = attr_map.get("src", "").strip()
            if src:
                self.script_sources.append(urljoin(self.base_url, src))
                self._inside_script = False
                self._script_chunks = []
            else:
                self._inside_script = True
                self._script_chunks = []

    def handle_data(self, data: str):
        if self._inside_script and data:
            self._script_chunks.append(data)

    def handle_endtag(self, tag: str):
        tag = tag.lower()
        if tag == "form":
            self._current_form = None
            return
        if tag == "script":
            if self._inside_script:
                joined = "".join(self._script_chunks).strip()
                if joined:
                    self.inline_scripts.append(joined[:4000])
            self._inside_script = False
            self._script_chunks = []


def extract_html_surface(base_url: str, body: str) -> dict[str, Any]:
    parser = _SurfaceParser(base_url)
    try:
        parser.feed(body or "")
    except Exception:
        pass

    forms = parser.forms[:10]
    links = parser.links[:25]

    login_forms = []
    upload_forms = []
    for form in forms:
        inputs = form.get("inputs", [])
        input_names = {i.get("name", "").lower() for i in inputs}
        input_types = {i.get("type", "").lower() for i in inputs}

        if "password" in input_types or any(name in input_names for name in {"password", "passwd", "pass"}):
            login_forms.append(form)
        if "file" in input_types or form.get("enctype", "").lower() == "multipart/form-data":
            upload_forms.append(form)

    navigation_links = classify_navigation_links(base_url, links, limit=20)

    interesting_links = _dedupe_urls(
        [
            link for link in links
            if any(marker in link.lower() for marker in _HIGH_VALUE_PATH_MARKERS)
        ] + [item["url"] for item in navigation_links]
    )[:15]

    return {
        "forms": forms,
        "login_forms": login_forms[:5],
        "upload_forms": upload_forms[:5],
        "links": links,
        "interesting_links": interesting_links,
        "navigation_links": navigation_links,
        "script_sources": parser.script_sources[:15],
        "inline_scripts": parser.inline_scripts[:8],
    }


def classify_navigation_links(base_url: str, links: list[str], limit: int = 20) -> list[dict[str, Any]]:
    base = urlparse(base_url)
    results: list[dict[str, Any]] = []
    seen: set[str] = set()

    for raw_link in links:
        link = str(raw_link).strip()
        if not link or link in seen:
            continue
        seen.add(link)

        parsed = urlparse(link)
        if parsed.scheme not in {"http", "https"}:
            continue
        if base.netloc and parsed.netloc and parsed.netloc != base.netloc:
            continue

        score, reasons = _score_navigation_link(parsed)
        if score <= 0:
            continue

        results.append({
            "url": link,
            "path": parsed.path or "/",
            "score": score,
            "reasons": reasons,
            "param_names": sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}),
        })

    results.sort(key=lambda item: (-int(item.get("score", 0)), item.get("path", ""), item.get("url", "")))
    return results[:limit]


def extract_jwt_tokens(headers: dict[str, Any] | None, body: str) -> list[str]:
    tokens: set[str] = set()
    for value in (headers or {}).values():
        tokens.update(_JWT_PATTERN.findall(str(value)))
    tokens.update(_JWT_PATTERN.findall(body or ""))
    return sorted(tokens)


def infer_endpoint_tags(url: str, surface: dict[str, Any] | None = None) -> list[str]:
    parsed = urlparse(url)
    path = parsed.path.lower()
    tags: list[str] = []

    if any(marker in path for marker in ("/admin", "/administrator", "/dashboard", "/panel")):
        tags.append("admin")
    if any(marker in path for marker in ("/login", "/signin", "/auth", "/session")):
        tags.append("login")
    if any(marker in path for marker in ("/upload", "/uploads", "/file", "/import")):
        tags.append("upload")
    if any(marker in path for marker in ("/api", "/graphql", "/rest")):
        tags.append("api")
    if parsed.query:
        tags.append("dynamic")

    if surface:
        if surface.get("login_forms"):
            tags.append("login_form")
        if surface.get("upload_forms"):
            tags.append("upload_form")
        if surface.get("jwt_tokens"):
            tags.append("jwt")

    return sorted(set(tags))


def summarize_http_response(
    response: Any,
    include_body: bool = False,
    max_body_chars: int = 1200,
) -> dict[str, Any]:
    if isinstance(max_body_chars, str):
        text = max_body_chars.strip()
        if text.lstrip("-").isdigit():
            max_body_chars = int(text)
        else:
            max_body_chars = 1200
    elif isinstance(max_body_chars, float):
        max_body_chars = int(max_body_chars)
    elif isinstance(max_body_chars, bool):
        max_body_chars = int(max_body_chars)
    elif not isinstance(max_body_chars, int):
        max_body_chars = 1200

    if max_body_chars < 200:
        max_body_chars = 200
    if max_body_chars > 20000:
        max_body_chars = 20000

    body = response.text or ""
    surface = extract_html_surface(str(response.url), body)
    headers = {k: v for k, v in response.headers.items()}
    jwt_tokens = extract_jwt_tokens(headers, body[: max_body_chars * 2])

    body_preview = body[:max_body_chars]
    summary = {
        "url": str(response.url),
        "status_code": response.status_code,
        "title": extract_title(body),
        "content_length": len(response.content),
        "server": response.headers.get("server", ""),
        "x_powered_by": response.headers.get("x-powered-by", ""),
        "content_type": response.headers.get("content-type", ""),
        "redirect_chain": [str(item.url) for item in response.history],
        "headers": headers,
        "cookies": dict(response.cookies),
        "forms": surface["forms"],
        "login_forms": surface["login_forms"],
        "upload_forms": surface["upload_forms"],
        "links": surface["links"],
        "interesting_links": surface["interesting_links"],
        "navigation_links": surface["navigation_links"],
        "script_sources": surface["script_sources"],
        "inline_script_count": len(surface["inline_scripts"]),
        "jwt_tokens": jwt_tokens,
        "endpoint_tags": infer_endpoint_tags(str(response.url), {**surface, "jwt_tokens": jwt_tokens}),
        "body_preview": body_preview,
    }
    if include_body:
        summary["body"] = body[: max_body_chars * 4]
    return summary


def _score_navigation_link(parsed) -> tuple[int, list[str]]:
    path = (parsed.path or "/").lower()
    query_names = {key.lower() for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    score = 0
    reasons: list[str] = []

    if parsed.query:
        score += 5
        reasons.append("带查询参数")

    if any(path.endswith(ext) for ext in _DYNAMIC_EXTENSIONS):
        score += 3
        reasons.append("动态脚本路径")

    if any(marker in path for marker in _DYNAMIC_PATH_MARKERS):
        score += 3
        reasons.append("内容页/详情页路径")

    matched_params = sorted(query_names & _DYNAMIC_PARAM_MARKERS)
    if matched_params:
        score += 4
        reasons.append(f"参数像业务主键: {', '.join(matched_params[:3])}")

    if any(marker in path for marker in _HIGH_VALUE_PATH_MARKERS):
        score += 5
        reasons.append("高价值路径")

    if path not in {"", "/"} and not query_names:
        score += 1
        reasons.append("可继续跟进的站内页面")

    return score, reasons


def _dedupe_urls(urls: list[str]) -> list[str]:
    seen: set[str] = set()
    results: list[str] = []
    for url in urls:
        text = str(url).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        results.append(text)
    return results
