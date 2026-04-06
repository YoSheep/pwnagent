"""
ssrf_tool — SSRF（服务端请求伪造）检测
检测 URL 参数、Webhook 字段、文件导入等 SSRF 入口点。
"""
from __future__ import annotations

import re
import urllib.parse
from typing import Any

import httpx

_UA = "Mozilla/5.0 (PwnAgent/1.0)"
_TIMEOUT = 12.0

# 内网地址探针（无害，仅检测响应差异）
_INTERNAL_PROBES = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/latest/meta-data/",   # AWS IMDS
    "http://metadata.google.internal/",              # GCP IMDS
    "http://169.254.169.254/metadata/v1/",           # Azure IMDS
    "http://100.100.100.200/latest/meta-data/",      # 阿里云 IMDS
]

# 常见 SSRF 参数名
_SSRF_PARAMS = [
    "url", "callback", "redirect", "redirect_url", "return_url", "next",
    "image", "img", "src", "href", "link", "file", "path", "load",
    "fetch", "proxy", "request", "uri", "endpoint", "target", "dest",
    "to", "goto", "open", "ref", "return",
]

# 检测 SSRF 命中的响应特征
_CLOUD_META_INDICATORS = [
    "ami-id", "instance-id", "local-ipv4",      # AWS
    "instance/id", "project/project-id",         # GCP
    "subscriptionId", "azureEnvironment",         # Azure
    "owner-account-id",                           # 阿里云
]


def ssrf_scan(target: str, params: list[str] | None = None) -> dict[str, Any]:
    """
    扫描目标 URL 的 SSRF 漏洞。
    :param target: 目标 URL（可含查询参数）
    :param params: 额外要测试的参数名列表
    """
    parsed = urllib.parse.urlparse(target)
    existing_params = dict(urllib.parse.parse_qsl(parsed.query))
    base_url = parsed._replace(query="").geturl()

    all_params = list(existing_params.keys())
    # 加入常见 SSRF 参数名（不在已有参数中的）
    for p in (params or []) + _SSRF_PARAMS:
        if p not in all_params:
            all_params.append(p)

    results = []

    with httpx.Client(
        follow_redirects=False,   # 不跟随重定向，观察 302 目标
        timeout=_TIMEOUT,
        verify=False,
        headers={"User-Agent": _UA},
    ) as client:
        # 基线请求
        try:
            baseline = client.get(target)
            baseline_len = len(baseline.content)
            baseline_status = baseline.status_code
        except Exception:
            baseline_len, baseline_status = 0, 0

        for param in all_params[:20]:  # 最多测试 20 个参数
            for probe in _INTERNAL_PROBES[:3]:  # 每参数测试前3个探针
                test_params = dict(existing_params)
                test_params[param] = probe

                try:
                    resp = client.get(base_url, params=test_params, timeout=_TIMEOUT)
                    body = resp.text

                    # 特征1：云元数据关键词出现在响应中
                    meta_hit = any(ind in body for ind in _CLOUD_META_INDICATORS)

                    # 特征2：重定向到内网地址
                    location = resp.headers.get("location", "")
                    redirect_hit = (
                        resp.status_code in (301, 302, 303, 307, 308)
                        and any(h in location for h in ("127.0.0.1", "localhost", "169.254"))
                    )

                    # 特征3：响应内容与基线差异显著且包含可疑内容
                    content_diff = abs(len(resp.content) - baseline_len) > 500
                    internal_response = any(
                        s in body.lower() for s in
                        ("root:", "etc/passwd", "aws", "metadata", "internal", "private")
                    )

                    if meta_hit or redirect_hit or (content_diff and internal_response):
                        results.append({
                            "type": "ssrf",
                            "param": param,
                            "probe": probe,
                            "url": str(resp.url),
                            "status_code": resp.status_code,
                            "evidence": {
                                "meta_keywords_found": meta_hit,
                                "redirect_to_internal": redirect_hit,
                                "location": location,
                                "response_preview": body[:300],
                            },
                        })
                        break  # 此参数已确认，不再测试其他探针
                except httpx.ConnectTimeout:
                    # 连接超时可能意味着内网请求被发出（DNS 查询时间不同）
                    results.append({
                        "type": "ssrf_timeout",
                        "param": param,
                        "probe": probe,
                        "note": "连接超时，可能 SSRF 触发了内网请求（建议配合 DNSLOG 验证）",
                    })
                except Exception:
                    pass

        # 额外检测：开放重定向（可配合 SSRF 利用）
        open_redirect = _check_open_redirect(client, base_url, existing_params, all_params)
        if open_redirect:
            results.extend(open_redirect)

    return {
        "target": target,
        "vulnerable": len(results) > 0,
        "findings": results,
        "params_tested": all_params[:20],
    }


def _check_open_redirect(
    client: httpx.Client,
    base_url: str,
    existing_params: dict,
    param_names: list[str],
) -> list[dict]:
    redirect_payloads = [
        "//evil.com",
        "https://evil.com",
        "//evil.com/%2F..",
    ]
    results = []
    redirect_params = [p for p in param_names if p in (
        "redirect", "redirect_url", "return_url", "next", "goto", "url", "to"
    )]
    for param in redirect_params[:5]:
        for payload in redirect_payloads:
            test_params = dict(existing_params)
            test_params[param] = payload
            try:
                resp = client.get(base_url, params=test_params, timeout=8)
                location = resp.headers.get("location", "")
                if resp.status_code in (301, 302, 303, 307, 308) and "evil.com" in location:
                    results.append({
                        "type": "open_redirect",
                        "param": param,
                        "payload": payload,
                        "location": location,
                        "url": str(resp.url),
                    })
                    break
            except Exception:
                pass
    return results
