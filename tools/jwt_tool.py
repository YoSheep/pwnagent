"""
jwt_tool — JWT 安全分析
检测：None 算法攻击、弱密钥爆破、算法混淆（RS256→HS256）、敏感信息泄露
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any


# 常见弱密钥字典
_WEAK_SECRETS = [
    "secret", "password", "123456", "qwerty", "admin", "test",
    "jwt_secret", "my_secret", "supersecret", "changeme",
    "mysecretkey", "your-256-bit-secret", "your-secret-key",
    "hs256secret", "jwtsecret", "secret123", "token_secret",
    "app_secret", "flask_secret", "django-insecure",
    "", " ",  # 空密钥
]


def jwt_analyze(token: str) -> dict[str, Any]:
    """
    全面分析 JWT token 的安全性。
    :param token: JWT token 字符串
    :returns: 完整分析结果，包含所有发现的问题
    """
    results: dict[str, Any] = {
        "token": token[:80] + "..." if len(token) > 80 else token,
        "valid_format": False,
        "header": {},
        "payload": {},
        "issues": [],
    }

    # 解析 token
    parts = token.strip().split(".")
    if len(parts) != 3:
        results["issues"].append({
            "type": "format_error",
            "severity": "info",
            "detail": f"不是标准 JWT 格式（期望3段，得到{len(parts)}段）",
        })
        return results

    results["valid_format"] = True
    header_b64, payload_b64, signature_b64 = parts

    # 解码 header
    header = _b64_decode_json(header_b64)
    payload = _b64_decode_json(payload_b64)
    results["header"] = header
    results["payload"] = payload

    if header is None or payload is None:
        results["issues"].append({"type": "decode_error", "severity": "info", "detail": "无法解码 JWT 内容"})
        return results

    # ------------------------------------------------------------------
    # 检查1：None 算法攻击
    # ------------------------------------------------------------------
    alg = header.get("alg", "").lower()
    if alg in ("none", "null", ""):
        results["issues"].append({
            "type": "none_algorithm",
            "severity": "critical",
            "detail": "JWT 使用 'none' 算法，签名未被验证，可伪造任意 payload",
            "poc": _forge_none_token(payload),
        })

    # ------------------------------------------------------------------
    # 检查2：弱密钥爆破（HS256/HS384/HS512）
    # ------------------------------------------------------------------
    if alg.startswith("hs"):
        cracked = _brute_weak_secret(header_b64, payload_b64, signature_b64, alg)
        if cracked is not None:
            results["issues"].append({
                "type": "weak_secret",
                "severity": "critical",
                "detail": f"JWT 使用弱密钥签名，密钥为: '{cracked}'",
                "cracked_secret": cracked,
                "poc": _forge_with_secret(payload, cracked, alg),
            })

    # ------------------------------------------------------------------
    # 检查3：算法混淆（RS256 → HS256）
    # ------------------------------------------------------------------
    if alg in ("rs256", "rs384", "rs512", "es256", "es384", "es512"):
        results["issues"].append({
            "type": "algorithm_confusion",
            "severity": "high",
            "detail": (
                f"使用非对称算法 {alg.upper()}，若服务端实现不当，"
                "可能存在将算法改为 HS256 并用公钥作为密钥的混淆攻击"
            ),
            "recommendation": "验证服务端是否拒绝算法切换请求",
        })

    # ------------------------------------------------------------------
    # 检查4：过期时间
    # ------------------------------------------------------------------
    exp = payload.get("exp")
    if exp is None:
        results["issues"].append({
            "type": "no_expiration",
            "severity": "medium",
            "detail": "JWT 无过期时间（exp 字段缺失），token 永久有效",
        })
    else:
        now = time.time()
        if exp < now:
            results["issues"].append({
                "type": "expired",
                "severity": "info",
                "detail": f"Token 已过期（exp: {exp}, 当前时间: {int(now)}）",
            })
        else:
            lifetime = exp - now
            if lifetime > 86400 * 30:  # 超过30天
                results["issues"].append({
                    "type": "long_expiration",
                    "severity": "low",
                    "detail": f"Token 有效期过长（剩余 {int(lifetime/86400)} 天）",
                })

    # ------------------------------------------------------------------
    # 检查5：敏感信息泄露
    # ------------------------------------------------------------------
    sensitive_keys = ["password", "passwd", "pwd", "secret", "key", "token",
                      "api_key", "private_key", "credit_card", "ssn", "pin"]
    for key in sensitive_keys:
        if key in payload:
            results["issues"].append({
                "type": "sensitive_data",
                "severity": "high",
                "detail": f"Payload 中包含敏感字段: '{key}'",
                "value_preview": str(payload[key])[:20] + "..." if len(str(payload[key])) > 20 else str(payload[key]),
            })

    # ------------------------------------------------------------------
    # 检查6：不安全的配置字段
    # ------------------------------------------------------------------
    kid = header.get("kid", "")
    if kid:
        # kid 注入检测
        if any(c in kid for c in ("'", '"', ";", "--", "/")):
            results["issues"].append({
                "type": "kid_injection",
                "severity": "critical",
                "detail": f"JWT header 'kid' 字段包含可疑字符: {kid}，可能存在 SQLi 或路径遍历",
            })
        # kid 是文件路径
        if kid.startswith("/") or ".." in kid:
            results["issues"].append({
                "type": "kid_path_traversal",
                "severity": "high",
                "detail": f"'kid' 字段为文件路径: {kid}，可能触发任意文件读取",
            })

    jku = header.get("jku", "")
    jwk = header.get("jwk", "")
    x5u = header.get("x5u", "")
    if jku:
        results["issues"].append({
            "type": "jku_injection",
            "severity": "high",
            "detail": f"JWT header 包含 'jku' (JWK Set URL): {jku}，可通过替换 URL 注入自定义公钥",
        })
    if jwk:
        results["issues"].append({
            "type": "embedded_jwk",
            "severity": "high",
            "detail": "JWT header 内嵌了 'jwk'（公钥），可被替换为攻击者控制的密钥对",
        })
    if x5u:
        results["issues"].append({
            "type": "x5u_injection",
            "severity": "high",
            "detail": f"JWT header 包含 'x5u' (X.509 URL): {x5u}",
        })

    # 汇总
    results["risk_level"] = _calc_risk(results["issues"])
    results["issue_count"] = len(results["issues"])
    return results


def extract_jwt_from_response(headers: dict, body: str) -> list[str]:
    """从 HTTP 响应头/体中提取所有 JWT token。"""
    tokens = []
    jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')

    # 从响应头提取
    for _, value in headers.items():
        tokens.extend(jwt_pattern.findall(value))

    # 从响应体提取
    tokens.extend(jwt_pattern.findall(body))

    return list(set(tokens))


# ------------------------------------------------------------------
# 内部工具
# ------------------------------------------------------------------

def _b64_decode_json(s: str) -> dict | None:
    try:
        padding = 4 - len(s) % 4
        s += "=" * (padding % 4)
        decoded = base64.urlsafe_b64decode(s)
        return json.loads(decoded)
    except Exception:
        return None


def _b64_encode(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).rstrip(b"=").decode()


def _sign_hs(data: str, secret: str, alg: str) -> str:
    hash_map = {"hs256": hashlib.sha256, "hs384": hashlib.sha384, "hs512": hashlib.sha512}
    hash_fn = hash_map.get(alg.lower(), hashlib.sha256)
    sig = hmac.new(secret.encode(), data.encode(), hash_fn).digest()
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


def _verify_hs(header_b64: str, payload_b64: str, sig_b64: str, secret: str, alg: str) -> bool:
    try:
        data = f"{header_b64}.{payload_b64}"
        expected = _sign_hs(data, secret, alg)
        # 规范化 base64 比较
        sig_norm = sig_b64.rstrip("=")
        exp_norm = expected.rstrip("=")
        return hmac.compare_digest(sig_norm, exp_norm)
    except Exception:
        return False


def _brute_weak_secret(
    header_b64: str, payload_b64: str, sig_b64: str, alg: str
) -> str | None:
    for secret in _WEAK_SECRETS:
        if _verify_hs(header_b64, payload_b64, sig_b64, secret, alg):
            return secret
    return None


def _forge_none_token(payload: dict) -> str:
    header = {"alg": "none", "typ": "JWT"}
    return f"{_b64_encode(header)}.{_b64_encode(payload)}."


def _forge_with_secret(payload: dict, secret: str, alg: str) -> str:
    header = {"alg": alg.upper(), "typ": "JWT"}
    h = _b64_encode(header)
    p = _b64_encode(payload)
    sig = _sign_hs(f"{h}.{p}", secret, alg)
    return f"{h}.{p}.{sig}"


def _calc_risk(issues: list[dict]) -> str:
    severities = [i.get("severity", "info") for i in issues]
    if "critical" in severities:
        return "critical"
    if "high" in severities:
        return "high"
    if "medium" in severities:
        return "medium"
    if "low" in severities:
        return "low"
    return "info"
