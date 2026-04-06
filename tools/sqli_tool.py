"""
sqli_tool — SQL 注入检测（sqlmap 封装 + 轻量级启发式检测）
"""
import json
import re
import shutil
import subprocess
import urllib.parse
from typing import Any

import httpx


# ------------------------------------------------------------------
# 主接口
# ------------------------------------------------------------------

def sqli_scan(
    target: str,
    data: str = "",
    level: int = 1,
    risk: int = 1,
) -> dict[str, Any]:
    """
    :param target: 目标 URL（含参数）
    :param data:   POST 数据（可选）
    :param level:  sqlmap 检测级别 1-5
    :param risk:   sqlmap 风险等级 1-3
    """
    heuristic = _heuristic_sqli(target)

    sqlmap_result: dict = {}
    if shutil.which("sqlmap"):
        sqlmap_result = _run_sqlmap(target, data, level, risk)
    else:
        sqlmap_result = {"warning": "sqlmap 未安装，仅使用启发式检测。"}

    vulnerable = heuristic.get("vulnerable", False) or sqlmap_result.get("vulnerable", False)

    return {
        "target": target,
        "vulnerable": vulnerable,
        "heuristic": heuristic,
        "sqlmap": sqlmap_result,
    }


# ------------------------------------------------------------------
# 启发式检测（无 sqlmap 时的轻量探针）
# ------------------------------------------------------------------

_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"ORA-\d{5}",
    r"microsoft ole db provider for sql server",
    r"syntax error.*sql",
    r"pg_query\(\)",
    r"supplied argument is not a valid postgresql",
    r"sqlite3\.operationalerror",
]

_BOOLEAN_PAYLOADS = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("1 OR 1=1", "1 OR 1=2"),
]


def _heuristic_sqli(target: str) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(target)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    if not params:
        return {"skipped": "无 GET 参数可测试"}

    indicators = []
    base_url = parsed._replace(query="").geturl()

    with httpx.Client(
        follow_redirects=True, timeout=15.0, verify=False,
        headers={"User-Agent": "Mozilla/5.0 (PentestPilot/1.0)"},
    ) as client:
        # 基线响应
        try:
            baseline = client.get(base_url, params=params)
            baseline_len = len(baseline.text)
        except Exception as e:
            return {"error": str(e)}

        for param_name in list(params.keys())[:5]:  # 最多测试前5个参数
            # 错误型注入检测
            error_params = dict(params)
            error_params[param_name] = params[param_name] + "'"
            try:
                resp = client.get(base_url, params=error_params)
                body_lower = resp.text.lower()
                for pattern in _ERROR_PATTERNS:
                    if re.search(pattern, body_lower, re.IGNORECASE):
                        indicators.append({
                            "type": "error_based",
                            "param": param_name,
                            "pattern": pattern,
                            "payload": "'",
                        })
                        break
            except Exception:
                pass

            # 布尔型注入检测
            for true_payload, false_payload in _BOOLEAN_PAYLOADS:
                try:
                    true_params = dict(params)
                    true_params[param_name] = true_payload
                    false_params = dict(params)
                    false_params[param_name] = false_payload

                    true_resp = client.get(base_url, params=true_params)
                    false_resp = client.get(base_url, params=false_params)

                    # 响应长度差异大于 20% 视为可疑
                    true_len = len(true_resp.text)
                    false_len = len(false_resp.text)
                    if false_len > 0:
                        diff_ratio = abs(true_len - false_len) / false_len
                        if diff_ratio > 0.2 and true_resp.status_code == 200:
                            indicators.append({
                                "type": "boolean_based",
                                "param": param_name,
                                "true_payload": true_payload,
                                "false_payload": false_payload,
                                "length_diff_ratio": round(diff_ratio, 3),
                            })
                except Exception:
                    pass

    return {
        "vulnerable": len(indicators) > 0,
        "indicators": indicators,
    }


# ------------------------------------------------------------------
# sqlmap 封装
# ------------------------------------------------------------------

def _run_sqlmap(target: str, data: str, level: int, risk: int) -> dict[str, Any]:
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="pentestpilot_sqlmap_")
    cmd = [
        "sqlmap",
        "-u", target,
        "--level", str(level),
        "--risk", str(risk),
        "--batch",
        "--output-dir", tmpdir,
        "--forms",
    ]
    if data:
        cmd += ["--data", data]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return {"error": "sqlmap 超时（300s）"}
    except Exception as e:
        return {"error": f"sqlmap 执行失败: {e}"}

    # 解析 sqlmap 输出
    output_lower = proc.stdout.lower()
    vulnerable = (
        "is vulnerable" in output_lower
        or ("parameter" in output_lower and "is injectable" in output_lower)
    )

    injections = []
    for match in re.finditer(
        r"Parameter: (\S+).*?Type: (.*?)\n.*?Payload: (.*?)\n",
        proc.stdout, re.DOTALL
    ):
        injections.append({
            "parameter": match.group(1),
            "type": match.group(2).strip(),
            "payload": match.group(3).strip(),
        })

    return {
        "vulnerable": vulnerable,
        "injections": injections,
        "raw_summary": proc.stdout[-2000:] if proc.stdout else "",
    }
