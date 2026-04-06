"""
纯 Python 端口扫描器（替代 nmap）
使用 asyncio 并发扫描，无需外部依赖。
"""
from __future__ import annotations

import asyncio
import socket
from typing import Any

# 常见服务端口映射
_SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 8888: "http-alt",
    27017: "mongodb", 5000: "http-alt", 3000: "http-alt",
    9200: "elasticsearch", 11211: "memcached",
}

_TOP_1000_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 3000, 5000, 5432, 6379,
    27017, 9200, 11211, 4444, 6666, 7777, 8000, 8008, 8081, 8888,
    9000, 9090, 10000, 10443,
]


async def _check_port(ip: str, port: int, timeout: float = 1.0) -> dict | None:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return {
            "port": port,
            "proto": "tcp",
            "state": "open",
            "service": _SERVICE_MAP.get(port, "unknown"),
            "version": "",
        }
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def _scan_host(host: str, ports: list[int], concurrency: int = 200) -> dict:
    # 解析主机名
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return {"error": f"无法解析主机: {host}"}

    # 并发扫描
    sem = asyncio.Semaphore(concurrency)

    async def bounded_check(port):
        async with sem:
            return await _check_port(ip, port)

    results = await asyncio.gather(*[bounded_check(p) for p in ports])
    open_ports = [r for r in results if r is not None]

    # 尝试 banner 抓取（对开放端口）
    for port_info in open_ports[:10]:  # 最多抓取前 10 个
        banner = await _grab_banner(ip, port_info["port"])
        if banner:
            port_info["version"] = banner[:100]

    return {
        "ip": ip,
        "hostname": host if host != ip else "",
        "state": "up",
        "ports": open_ports,
    }


async def _grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        # 对 HTTP 端口发送请求
        if port in (80, 8080, 8000, 8888, 3000, 5000):
            writer.write(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            await writer.drain()

        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return data.decode(errors="ignore").strip()
    except Exception:
        return ""


def python_port_scan(target: str, ports: str = "top1000") -> dict[str, Any]:
    """
    纯 Python 端口扫描，nmap 不可用时的 fallback。
    :param target: IP 或域名
    :param ports:  "top1000" 或 "1-1000" 或 "80,443,8080"
    """
    port_list = _parse_ports(ports)
    host = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    from tools.pure import run_async
    host_result = run_async(_scan_host(host, port_list))

    if "error" in host_result:
        return host_result

    return {
        "hosts": [host_result],
        "command": f"python_port_scan({target}, {ports})",
        "open_port_count": len(host_result.get("ports", [])),
        "tool": "python-scanner",
    }


def _parse_ports(ports_spec: str) -> list[int]:
    if ports_spec == "top1000":
        return _TOP_1000_PORTS
    result = set()
    for part in ports_spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            result.update(range(int(start), int(end) + 1))
        else:
            result.add(int(part))
    return sorted(result)
