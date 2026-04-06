"""
渗透测试阶段状态机
五阶段线性流程，每阶段有明确的退出条件。
"""
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


@dataclass
class PentestSession:
    target: str
    scope: list[str]
    phase: Phase = Phase.INIT

    # 阶段产出
    attack_surface: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
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
            if not self.attack_surface:
                return False, "侦察阶段尚未发现任何攻击面，请继续信息收集。"
        if self.phase == Phase.SCAN:
            if not self.findings:
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

    # ------------------------------------------------------------------
    # 状态概要
    # ------------------------------------------------------------------

    def summary(self) -> dict:
        return {
            "target": self.target,
            "phase": self.phase.label(),
            "attack_surface_items": len(self.attack_surface),
            "findings": len(self.findings),
            "findings_by_severity": self._findings_by_severity(),
            "exploit_results": len(self.exploit_results),
            "thought_steps": len(self.thought_log),
        }

    def _findings_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity.lower()] = counts.get(f.severity.lower(), 0) + 1
        return counts
