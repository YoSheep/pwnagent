"""
nuclei_tool — Nuclei 模板扫描封装
"""
import json
import shutil
import subprocess
from typing import Any


def nuclei_scan(
    target: str,
    severity: str = "critical,high,medium",
    tags: str = "",
) -> dict[str, Any]:
    """
    使用 nuclei 扫描目标。
    :param severity: 逗号分隔的严重程度，如 critical,high
    :param tags:     模板标签，如 cve,owasp（可选）
    """
    if not shutil.which("nuclei"):
        from tools.pure.vuln_checker import python_vuln_check
        return python_vuln_check(target, severity)

    cmd = [
        "nuclei",
        "-u", target,
        "-severity", severity,
        "-json",
        "-silent",
        "-no-color",
        "-rate-limit", "50",
    ]
    if tags:
        cmd += ["-tags", tags]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return {"error": "nuclei 扫描超时（300s）"}
    except Exception as e:
        return {"error": f"nuclei 执行失败: {e}"}

    findings = []
    for line in proc.stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            findings.append({
                "template_id": item.get("template-id", ""),
                "name": item.get("info", {}).get("name", ""),
                "severity": item.get("info", {}).get("severity", ""),
                "description": item.get("info", {}).get("description", ""),
                "matched_at": item.get("matched-at", ""),
                "matcher_name": item.get("matcher-name", ""),
                "extracted_results": item.get("extracted-results", []),
                "curl_command": item.get("curl-command", ""),
                "tags": item.get("info", {}).get("tags", []),
                "reference": item.get("info", {}).get("reference", []),
                "cvss_score": item.get("info", {}).get("classification", {}).get("cvss-score", 0),
            })
        except json.JSONDecodeError:
            continue

    return {
        "findings": findings,
        "total": len(findings),
        "target": target,
    }
