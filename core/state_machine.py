"""
渗透测试阶段状态机
五阶段线性流程，每阶段有明确的退出条件。
"""
import json
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class Phase(Enum):
    INIT = auto()
    RECON = auto()         # 信息收集
    SCAN = auto()          # 漏洞扫描
    EXPLOIT = auto()       # 漏洞验证/利用
    POST_EXPLOIT = auto()  # 后渗透分析
    REPORT = auto()        # 报告生成
    DONE = auto()

    def label(self) -> str:
        labels = {
            Phase.INIT: "初始化",
            Phase.RECON: "信息收集",
            Phase.SCAN: "漏洞扫描",
            Phase.EXPLOIT: "漏洞验证",
            Phase.POST_EXPLOIT: "后渗透分析",
            Phase.REPORT: "报告生成",
            Phase.DONE: "完成",
        }
        return labels[self]


_TRANSITIONS: dict[Phase, Phase] = {
    Phase.INIT: Phase.RECON,
    Phase.RECON: Phase.SCAN,
    Phase.SCAN: Phase.EXPLOIT,
    Phase.EXPLOIT: Phase.POST_EXPLOIT,
    Phase.POST_EXPLOIT: Phase.REPORT,
    Phase.REPORT: Phase.DONE,
}


@dataclass
class Finding:
    title: str
    severity: str          # critical / high / medium / low / info
    target: str
    description: str
    payload: str = ""
    reproduction: str = ""
    remediation: str = ""
    cvss: float = 0.0
    thought_excerpt: str = ""  # Agent 发现此漏洞时的思维链节选


def _default_attack_surface() -> dict[str, Any]:
    return {
        "hosts": [],
        "open_ports": [],
        "web_services": [],
        "technologies": [],
        "subdomains": [],
        "endpoints": [],
        "api_candidates": [],
        "navigation_candidates": [],
        "script_sources": [],
        "forms": [],
        "admin_panels": [],
        "login_pages": [],
        "upload_paths": [],
        "jwt_tokens": [],
        "notes": [],
    }


@dataclass
class PentestSession:
    target: str
    scope: list[str]
    objective: str = ""
    phase: Phase = Phase.INIT

    # 阶段产出
    attack_surface: dict[str, Any] = field(default_factory=_default_attack_surface)
    findings: list[Finding] = field(default_factory=list)
    credentials: list[dict[str, Any]] = field(default_factory=list)
    authenticated_sessions: dict[str, dict[str, Any]] = field(default_factory=dict)
    exploit_results: list[dict] = field(default_factory=list)
    post_exploit_data: dict[str, Any] = field(default_factory=dict)

    # 完整思维链日志（每条为一个 dict，含 phase / thought / action / result）
    thought_log: list[dict] = field(default_factory=list)

    # ------------------------------------------------------------------
    # 阶段迁移
    # ------------------------------------------------------------------

    def can_advance(self) -> tuple[bool, str]:
        """返回 (是否可前进, 原因说明)"""
        if self.phase == Phase.RECON:
            if self.attack_surface_count() == 0:
                return False, "侦察阶段尚未发现任何攻击面，请继续信息收集。"
        if self.phase == Phase.SCAN:
            if not self.findings and not self.credentials:
                return False, "扫描阶段尚未发现任何漏洞，请补充扫描或手动标记为无漏洞。"
        if self.phase == Phase.DONE:
            return False, "测试已完成。"
        return True, ""

    def advance(self) -> bool:
        ok, reason = self.can_advance()
        if not ok:
            return False
        self.phase = _TRANSITIONS[self.phase]
        return True

    def force_advance(self):
        """跳过退出条件强制前进（用于用户手动干预）。"""
        if self.phase in _TRANSITIONS:
            self.phase = _TRANSITIONS[self.phase]

    # ------------------------------------------------------------------
    # 日志记录
    # ------------------------------------------------------------------

    def log_thought(self, thought: str, action: str, action_input: dict, result: Any):
        self.thought_log.append({
            "phase": self.phase.name,
            "thought": thought,
            "action": action,
            "action_input": action_input,
            "result": result,
        })

    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        # 最新思维链节选附到 finding
        if self.thought_log:
            finding.thought_excerpt = self.thought_log[-1].get("thought", "")

    def remember_attack_surface(self, section: str, item: Any):
        bucket = self.attack_surface.setdefault(section, [])
        if not isinstance(bucket, list):
            bucket = []
            self.attack_surface[section] = bucket

        marker = json.dumps(item, sort_keys=True, ensure_ascii=False, default=str)
        existing = {
            json.dumps(existing_item, sort_keys=True, ensure_ascii=False, default=str)
            for existing_item in bucket
        }
        if marker not in existing:
            bucket.append(item)

    def add_credential(self, credential: dict[str, Any]):
        marker = json.dumps(credential, sort_keys=True, ensure_ascii=False, default=str)
        existing = {
            json.dumps(item, sort_keys=True, ensure_ascii=False, default=str)
            for item in self.credentials
        }
        if marker not in existing:
            self.credentials.append(credential)

    def remember_authenticated_session(self, alias: str, metadata: dict[str, Any]):
        if not alias:
            return
        merged = dict(self.authenticated_sessions.get(alias, {}))
        merged.update(metadata)
        self.authenticated_sessions[alias] = merged

    # ------------------------------------------------------------------
    # 状态概要
    # ------------------------------------------------------------------

    def summary(self) -> dict:
        snapshot = {
            "open_ports": self.attack_surface.get("open_ports", [])[:20],
            "web_services": self.attack_surface.get("web_services", [])[:20],
            "subdomains": self.attack_surface.get("subdomains", [])[:20],
            "endpoints": self.attack_surface.get("endpoints", [])[:30],
            "api_candidates": self.attack_surface.get("api_candidates", [])[:30],
            "navigation_candidates": self.attack_surface.get("navigation_candidates", [])[:20],
            "admin_panels": self.attack_surface.get("admin_panels", [])[:10],
            "login_pages": self.attack_surface.get("login_pages", [])[:10],
            "upload_paths": self.attack_surface.get("upload_paths", [])[:10],
            "technologies": self.attack_surface.get("technologies", [])[:20],
            "script_sources": self.attack_surface.get("script_sources", [])[:20],
            "jwt_tokens": self.attack_surface.get("jwt_tokens", [])[:10],
        }
        return {
            "target": self.target,
            "objective": self.objective,
            "phase": self.phase.label(),
            "attack_surface_items": self.attack_surface_count(),
            "findings": len(self.findings),
            "findings_by_severity": self._findings_by_severity(),
            "credentials": len(self.credentials),
            "authenticated_sessions": list(self.authenticated_sessions.keys()),
            "exploit_results": len(self.exploit_results),
            "thought_steps": len(self.thought_log),
            "attack_surface_snapshot": snapshot,
            "credentials_preview": self.credentials[:10],
        }

    def attack_surface_count(self) -> int:
        total = 0
        for value in self.attack_surface.values():
            if isinstance(value, list):
                total += len(value)
        return total

    def _findings_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity.lower()] = counts.get(f.severity.lower(), 0) + 1
        return counts
