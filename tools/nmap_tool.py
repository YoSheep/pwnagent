"""
nmap_tool — nmap 扫描封装（兼容旧调用 + MCP 风格参数）
"""
from __future__ import annotations

import re
import shlex
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

_TARGET_RE = re.compile(r"^[a-zA-Z0-9.\-_:\/]+$")
_PORTS_RE = re.compile(r"^(top1000|all|[\d,\-]+)$")
_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9._:=,+%/@\-]+$")
_DANGEROUS_TOKEN_CHARS = {";", "&", "|", "`", "$", "(", ")", "<", ">", '"', "'"}

# 白名单策略参考 nmap-mcp-server，并结合当前项目已有参数
_ALLOWED_SIMPLE_FLAGS = {
    "-sS", "-sT", "-sA", "-sW", "-sM", "-sU", "-sN", "-sF", "-sX",
    "-O", "-sV", "-sC", "-F", "-p-", "-v", "-vv", "--open", "--reason",
    "--traceroute", "-Pn", "-PP", "-PM", "-PO", "-PE", "-PS", "-PA", "-PU", "-PY",
    "-6", "-4", "-b", "-D", "-S", "-e", "-g", "-f", "-i", "-M", "-R", "-r",
    "-A", "-n",
}
_ALLOWED_VALUE_FLAGS = {
    "-p",
    "--top-ports",
    "--script",
    "--script-args",
    "--version-intensity",
    "--host-timeout",
    "--max-rate",
    "--min-rate",
    "--max-retries",
    "-T",
}
_ALLOWED_SCAN_TYPES = {"legacy", "quick", "full", "version", "custom"}


def nmap_scan(
    target: str,
    ports: str = "top1000",
    flags: str = "-sV",
    scan_type: str = "legacy",
    timing: int = 3,
    additional_flags: str = "",
) -> dict[str, Any]:
    """
    运行 nmap 扫描并返回结构化结果。

    Args:
        target: 目标 IP / 域名 / CIDR
        ports: "top1000" / "all" / "80,443" / "1-1000"
        flags: 兼容旧参数，额外 nmap flags（白名单过滤）
        scan_type: legacy / quick / full / version / custom
        timing: nmap -T 模板，0-5
        additional_flags: MCP 风格附加参数（白名单过滤）
    """
    scan_type = str(scan_type or "legacy").strip().lower()
    if scan_type not in _ALLOWED_SCAN_TYPES:
        return {
            "error": f"不支持的 scan_type: {scan_type}",
            "available_scan_types": sorted(_ALLOWED_SCAN_TYPES),
        }

    timing_value = _normalize_timing(timing)
    ports_value = str(ports or "top1000").strip().lower()

    if not _TARGET_RE.match(target):
        return {"error": f"目标格式不合法: {target}"}
    if not _PORTS_RE.match(ports_value):
        return {"error": f"端口格式不合法: {ports}"}

    if not shutil.which("nmap"):
        from tools.pure.port_scanner import python_port_scan

        fallback_ports = _ports_for_python_fallback(scan_type=scan_type, ports=ports_value)
        fallback = python_port_scan(target, fallback_ports)
        fallback.update(
            {
                "scanner": "python-fallback",
                "scan_profile": scan_type,
                "timing": timing_value,
            }
        )
        return fallback

    profile_args = _profile_args(scan_type=scan_type, ports=ports_value)

    effective_flags = str(flags or "").strip()
    if scan_type in {"quick", "full"} and effective_flags == "-sV":
        # 保持兼容：旧默认 flags 为 -sV，但 quick/full 模式不应被默认值覆盖
        effective_flags = ""

    sanitized_flags, dropped_flags = _sanitize_flags(effective_flags)
    sanitized_extra, dropped_extra = _sanitize_flags(additional_flags)

    cmd = ["nmap", "-oX", "-", f"-T{timing_value}"] + profile_args + sanitized_flags + sanitized_extra + [target]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return {"error": "nmap 扫描超时（300s）"}
    except Exception as exc:
        return {"error": f"nmap 执行失败: {exc}"}

    if proc.returncode != 0 and not proc.stdout.strip():
        return {
            "error": proc.stderr.strip() or "nmap 返回非零退出码",
            "command": " ".join(cmd),
            "exit_code": proc.returncode,
        }

    parsed = _parse_nmap_xml(proc.stdout, " ".join(cmd))
    parsed["scan_profile"] = scan_type
    parsed["timing"] = timing_value
    parsed["scanner"] = "nmap"
    parsed["dropped_flags"] = sorted(set(dropped_flags + dropped_extra))
    parsed["exit_code"] = proc.returncode
    if proc.stderr.strip():
        parsed["stderr_tail"] = proc.stderr.strip()[-1200:]
    return parsed


def _normalize_timing(value: int) -> int:
    if isinstance(value, bool):
        timing = int(value)
    elif isinstance(value, int):
        timing = value
    elif isinstance(value, float):
        timing = int(value)
    else:
        text = str(value).strip()
        timing = int(text) if text.lstrip("-").isdigit() else 3
    if timing < 0:
        return 0
    if timing > 5:
        return 5
    return timing


def _profile_args(scan_type: str, ports: str) -> list[str]:
    args: list[str] = []

    if scan_type == "quick":
        args.append("-F")
    elif scan_type == "full":
        args.append("-p-")
    elif scan_type == "version":
        args.append("-sV")
    elif scan_type == "legacy":
        if ports == "top1000":
            args.extend(["--top-ports", "1000"])
        elif ports == "all":
            args.append("-p-")
        else:
            args.extend(["-p", ports])

    if scan_type in {"quick", "version"} and ports not in {"", "top1000"}:
        if ports == "all":
            args = [a for a in args if a != "-F"]
            if "-p-" not in args:
                args.append("-p-")
        else:
            args.extend(["-p", ports])
    return args


def _ports_for_python_fallback(scan_type: str, ports: str) -> str:
    if ports == "all":
        return "1-65535"
    if scan_type == "full" and ports == "top1000":
        return "1-65535"
    return ports or "top1000"


def _sanitize_flags(raw_flags: str) -> tuple[list[str], list[str]]:
    text = str(raw_flags or "").strip()
    if not text:
        return [], []

    try:
        tokens = shlex.split(text)
    except Exception:
        return [], [text]

    safe_tokens: list[str] = []
    dropped_tokens: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index].strip()
        if not token:
            index += 1
            continue
        if _is_dangerous_token(token):
            dropped_tokens.append(token)
            index += 1
            continue

        if token in _ALLOWED_SIMPLE_FLAGS:
            safe_tokens.append(token)
            index += 1
            continue

        if token in {f"-T{i}" for i in range(0, 6)}:
            # timing 由外层参数管理，这里仍允许兼容输入
            safe_tokens.append(token)
            index += 1
            continue

        if token in _ALLOWED_VALUE_FLAGS:
            if index + 1 >= len(tokens):
                dropped_tokens.append(token)
                index += 1
                continue
            value = tokens[index + 1].strip()
            if not _is_safe_value_token(value):
                dropped_tokens.extend([token, value])
                index += 2
                continue
            safe_tokens.extend([token, value])
            index += 2
            continue

        if token.startswith("--script=") or token.startswith("--top-ports=") or token.startswith("-p"):
            if _is_safe_value_token(token):
                safe_tokens.append(token)
            else:
                dropped_tokens.append(token)
            index += 1
            continue

        dropped_tokens.append(token)
        index += 1

    return safe_tokens, dropped_tokens


def _is_dangerous_token(token: str) -> bool:
    return any(char in token for char in _DANGEROUS_TOKEN_CHARS)


def _is_safe_value_token(token: str) -> bool:
    if not token:
        return False
    if _is_dangerous_token(token):
        return False
    return bool(_SAFE_TOKEN_RE.fullmatch(token))


def _parse_nmap_xml(xml_output: str, command: str) -> dict[str, Any]:
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        return {"error": f"XML 解析失败: {exc}", "raw": xml_output[:2000], "command": command}

    hosts: list[dict[str, Any]] = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        state = status_el.get("state", "") if status_el is not None else ""
        reason = status_el.get("reason", "") if status_el is not None else ""
        if state and state != "up":
            continue

        ipv4 = host_el.find("address[@addrtype='ipv4']")
        ipv6 = host_el.find("address[@addrtype='ipv6']")
        mac = host_el.find("address[@addrtype='mac']")
        hostname_el = host_el.find("hostnames/hostname")

        host_result: dict[str, Any] = {
            "ip": (ipv4.get("addr", "") if ipv4 is not None else "") or (ipv6.get("addr", "") if ipv6 is not None else ""),
            "ipv4": ipv4.get("addr", "") if ipv4 is not None else "",
            "ipv6": ipv6.get("addr", "") if ipv6 is not None else "",
            "mac": mac.get("addr", "") if mac is not None else "",
            "hostname": hostname_el.get("name", "") if hostname_el is not None else "",
            "state": state or "up",
            "reason": reason,
            "ports": [],
        }

        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            host_result["ports"].append(
                {
                    "port": int(port_el.get("portid", 0)),
                    "proto": port_el.get("protocol", "tcp"),
                    "state": state_el.get("state", ""),
                    "reason": state_el.get("reason", ""),
                    "service": service_el.get("name", "") if service_el is not None else "",
                    "product": service_el.get("product", "") if service_el is not None else "",
                    "version": (
                        f"{service_el.get('product', '')} {service_el.get('version', '')}".strip()
                        if service_el is not None
                        else ""
                    ),
                    "extrainfo": service_el.get("extrainfo", "") if service_el is not None else "",
                }
            )

        hosts.append(host_result)

    return {
        "hosts": hosts,
        "command": command,
        "open_port_count": sum(len(host.get("ports", [])) for host in hosts),
        "host_count": len(hosts),
    }
