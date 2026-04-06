"""
nmap_tool — nmap 封装
"""
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any

# nmap 允许的安全 flags 白名单
_ALLOWED_FLAGS = {
    "-sV", "-sS", "-sT", "-sU", "-sN", "-sF", "-sX", "-sA",
    "-O", "-A", "-Pn", "-n", "-v", "-vv", "-T0", "-T1", "-T2", "-T3", "-T4", "-T5",
    "--open", "--reason", "--traceroute", "--version-intensity",
}


def nmap_scan(target: str, ports: str = "top1000", flags: str = "-sV") -> dict[str, Any]:
    """
    运行 nmap 扫描并返回结构化结果。
    nmap 不可用时自动 fallback 到纯 Python 端口扫描器。
    """
    if not shutil.which("nmap"):
        from tools.pure.port_scanner import python_port_scan
        return python_port_scan(target, ports)

    # 输入验证：target 只允许 IP、域名、CIDR
    if not re.match(r'^[a-zA-Z0-9.\-:/]+$', target):
        return {"error": f"目标格式不合法: {target}"}

    # ports 只允许数字、逗号、横线和 top 关键字
    if ports != "top1000" and not re.match(r'^[\d,\-]+$', ports):
        return {"error": f"端口格式不合法: {ports}"}

    # flags 白名单过滤
    safe_flags = [f for f in flags.split() if f in _ALLOWED_FLAGS or f.lstrip("-") in ("",)]
    safe_flags = [f for f in safe_flags if f]  # 去空

    port_arg = "--top-ports 1000" if ports == "top1000" else f"-p {ports}"
    cmd = ["nmap", "-oX", "-"] + port_arg.split() + safe_flags + [target]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return {"error": "nmap 扫描超时（300s）"}
    except Exception as e:
        return {"error": f"nmap 执行失败: {e}"}

    if proc.returncode != 0 and not proc.stdout.strip():
        return {"error": proc.stderr or "nmap 返回非零退出码"}

    return _parse_nmap_xml(proc.stdout, " ".join(cmd))


def _parse_nmap_xml(xml_output: str, command: str) -> dict[str, Any]:
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as e:
        return {"error": f"XML 解析失败: {e}", "raw": xml_output[:2000]}

    hosts = []
    for host_el in root.findall("host"):
        state_el = host_el.find("status")
        if state_el is None or state_el.get("state") != "up":
            continue

        # IP / hostname
        addr_el = host_el.find("address[@addrtype='ipv4']")
        ip = addr_el.get("addr") if addr_el is not None else ""
        hostname_el = host_el.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else ""

        # 端口
        ports = []
        for port_el in host_el.findall("ports/port"):
            state = port_el.find("state")
            if state is None or state.get("state") != "open":
                continue
            service_el = port_el.find("service")
            ports.append({
                "port": int(port_el.get("portid", 0)),
                "proto": port_el.get("protocol", "tcp"),
                "state": state.get("state"),
                "service": service_el.get("name", "") if service_el is not None else "",
                "version": (
                    f"{service_el.get('product','')} {service_el.get('version','')}".strip()
                    if service_el is not None else ""
                ),
            })

        hosts.append({"ip": ip, "hostname": hostname, "state": "up", "ports": ports})

    return {"hosts": hosts, "command": command, "open_port_count": sum(len(h["ports"]) for h in hosts)}
