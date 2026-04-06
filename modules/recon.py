"""
recon — 信息收集模块
整合 nmap + httpx，构建攻击面数据结构。
"""
from typing import Any

from tools.httpx_tool import httpx_probe
from tools.nmap_tool import nmap_scan


def run_recon(target: str, session) -> dict[str, Any]:
    """
    完整侦察流程：端口扫描 -> Web 服务探测 -> 构建攻击面。
    结果直接写入 session.attack_surface。
    """
    attack_surface: dict[str, Any] = {
        "target": target,
        "open_ports": [],
        "web_services": [],
        "technologies": [],
    }

    # 1. 端口扫描
    nmap_result = nmap_scan(target=target)
    if "error" not in nmap_result:
        for host in nmap_result.get("hosts", []):
            for port_info in host.get("ports", []):
                attack_surface["open_ports"].append({
                    "ip": host["ip"],
                    "port": port_info["port"],
                    "proto": port_info["proto"],
                    "service": port_info["service"],
                    "version": port_info["version"],
                })

    # 2. Web 服务探测
    # 根据开放端口构建 Web 目标列表
    web_targets = _build_web_targets(target, attack_surface["open_ports"])
    for web_target in web_targets:
        probe_result = httpx_probe(target=web_target, paths=[
            "/", "/admin", "/login", "/api", "/robots.txt", "/.git/HEAD",
            "/.env", "/phpinfo.php", "/wp-admin",
        ])
        for r in probe_result.get("results", []):
            if "error" not in r:
                attack_surface["web_services"].append(r)
                # 收集技术栈信息
                techs = r.get("technologies", r.get("tech", []))
                if isinstance(techs, list):
                    attack_surface["technologies"].extend(techs)

    # 去重技术栈
    attack_surface["technologies"] = list(set(attack_surface["technologies"]))

    # 写入 session
    session.attack_surface = attack_surface
    return attack_surface


def _build_web_targets(base_target: str, open_ports: list[dict]) -> list[str]:
    """根据开放端口生成 Web 服务 URL 列表。"""
    web_ports = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000}
    targets = set()

    # 始终包含原始目标
    targets.add(base_target if "://" in base_target else f"http://{base_target}")

    for p in open_ports:
        port = p["port"]
        ip = p.get("ip", base_target)
        if port in web_ports or p.get("service", "").lower() in ("http", "https", "http-alt"):
            scheme = "https" if port in (443, 8443) else "http"
            if port in (80, 443):
                targets.add(f"{scheme}://{ip}")
            else:
                targets.add(f"{scheme}://{ip}:{port}")

    return list(targets)
