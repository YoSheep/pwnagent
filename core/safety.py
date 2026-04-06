"""
SafetyGuard — 授权检查 + 速率限制
所有工具调用前的强制门卫，不可绕过。
"""
from __future__ import annotations

import ipaddress
import re
import socket
import time
from collections import defaultdict
from urllib.parse import urlparse


class AuthorizationError(Exception):
    pass


class SafetyGuard:
    def __init__(self, scope: list[str], rate_limit: int = 10):
        self.scope = scope
        self.rate_limit = rate_limit
        self._request_times: dict[str, list[float]] = defaultdict(list)

    # ------------------------------------------------------------------
    # 目标授权检查
    # ------------------------------------------------------------------

    def check_target(self, target: str) -> bool:
        host = self._extract_host(target)
        if host is None:
            raise AuthorizationError(f"无法解析目标主机: {target}")

        for allowed in self.scope:
            allowed = allowed.strip()
            if self._host_matches(host, allowed):
                return True

        raise AuthorizationError(
            f"\n[!] 目标 '{target}'（主机: {host}）不在授权范围内！\n"
            f"    授权范围: {self.scope}\n"
            f"    如需扩展范围，请在 config.yaml 中更新 scope 并重新确认授权。"
        )

    @staticmethod
    def _extract_host(target: str) -> str | None:
        """安全地提取主机名，防止 userinfo@ 绕过。"""
        try:
            if "://" not in target:
                target = f"http://{target}"
            parsed = urlparse(target)
            hostname = parsed.hostname

            # 防御 userinfo 绕过：http://evil.com@192.168.1.1
            # 如果原始 URL 包含 @，且 @ 不在 query/fragment 中，则拒绝
            netloc = parsed.netloc or ""
            # 去掉端口号后检查 @
            if "@" in netloc:
                raise AuthorizationError(
                    f"URL 包含 userinfo（@），可能是绕过尝试: {target}"
                )

            return hostname
        except AuthorizationError:
            raise
        except Exception:
            return None

    @staticmethod
    def _host_matches(host: str, allowed: str) -> bool:
        # 尝试 IP / CIDR 匹配
        try:
            ip = ipaddress.ip_address(host)
            network = ipaddress.ip_network(allowed, strict=False)
            return ip in network
        except ValueError:
            pass

        # 域名精确匹配
        if host == allowed:
            return True

        # 子域名匹配：allowed="example.com" 匹配 "sub.example.com"
        # 但不匹配 "notexample.com"
        if host.endswith(f".{allowed}") and not allowed.startswith("."):
            return True

        # 通配符 *.example.com
        if allowed.startswith("*."):
            base = allowed[2:]
            if host == base or host.endswith(f".{base}"):
                return True

        return False

    # ------------------------------------------------------------------
    # 速率限制
    # ------------------------------------------------------------------

    def rate_check(self, tool_name: str):
        now = time.time()
        window = 1.0
        self._request_times[tool_name] = [
            t for t in self._request_times[tool_name] if now - t < window
        ]
        if len(self._request_times[tool_name]) >= self.rate_limit:
            oldest = self._request_times[tool_name][0]
            sleep_time = window - (now - oldest)
            if sleep_time > 0:
                time.sleep(sleep_time)
        self._request_times[tool_name].append(time.time())

    # ------------------------------------------------------------------
    # 组合检查
    # ------------------------------------------------------------------

    def authorize(self, target: str, tool_name: str):
        self.check_target(target)
        self.rate_check(tool_name)
