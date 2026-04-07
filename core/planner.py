"""
Planner + Replanner — 动态任务规划
"""
from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.tree import Tree

from core.llm import complete_text, get_runtime

console = Console()

_PLAN_SYSTEM = """你是一个渗透测试规划专家。根据以下信息生成执行计划：
- 目标信息
- 当前阶段
- 上一阶段发现的结果
- 参考知识（如有）
- 可用工具列表

规划规则：
- 只能使用工具列表中真实存在的工具名，绝不允许编造工具。
- 必须遵守工具前置条件；如果缺少必填参数或缺少上游证据，就不要安排该工具。
- 优先根据当前证据推进 exploit chain，不要泛化成 OWASP 背题式大扫描。
- 对 Web 目标，优先使用 page_intel / http_request 读取页面、表单、脚本和接口线索，再决定具体漏洞类型。
- 如果页面里已经发现站内跳转链接（例如带查询参数的内容页/详情页），优先继续跟进这些真实页面，而不是重复 dirbust / subdomain_enum / SSRF 广撒网。
- 如果已经出现 SQL 注入、后台、登录页、上传点、凭据、哈希这些信号，应优先走“枚举 -> 凭据/哈希 -> 登录 -> 上传/验证”主链路。
- 当用户 objective 明确要求 SQLi 专项时，若出现 SQL 注入强信号（如 select-no-waf、API 带 id 参数、报错回显 SQL 片段），计划应收敛到同一注入点并优先安排 sqli_scan 的 detect -> enumerate -> dump。
- 只有在目标确实出现相关入口时，才安排 JWT、SSRF、XSS 等专项测试。
- 针对 challenge/靶场目标，优先收敛到最可能的利用路径，而不是广撒网。

输出严格的 JSON 格式：
{
  "phase_goal": "本阶段的核心目标",
  "parallel_groups": [
    {
      "description": "这组工具可以并行执行的原因",
      "tools": [
        {"name": "tool_name", "args": {}, "priority": "high/medium/low", "reason": "为什么要用这个工具"}
      ]
    }
  ],
  "sequential_steps": [
    {"description": "需要等前面结果后才能做的步骤", "depends_on": "parallel_group_0 的结果",
     "tools": [{"name": "tool_name", "args": {}, "reason": "为什么"}]}
  ],
  "skip_conditions": ["如果 X，则跳过 Y"],
  "risk_notes": ["注意事项"]
}"""

_REPLAN_SYSTEM = """你是一个渗透测试规划专家。之前的计划在执行时遇到了问题。
根据失败信息和已有结果，生成调整后的计划。

输出相同的 JSON 格式（parallel_groups + sequential_steps）。
重点关注：
- 失败的工具是否有替代方案
- 已有结果是否提供了新的攻击面
- 是否应该放弃某些路径，聚焦其他方向

重新规划规则：
- 如果失败原因是“参数不满足前置条件”，不要机械重试同类错误调用。
- 只能使用工具列表里真实存在的工具。
- 如果已经发现站内页面跳转或动态链接，优先继续跟进这些真实页面。
- 如果已经发现 exploit chain 线索，优先推进主链路，不要扩散到无关测试。
- 若 objective 明确为 SQLi 专项且已确认注入入口，不要重新回到 dirbust/nuclei/子域名枚举，应继续 SQLi 利用链。"""


class PhasePlan:
    """一个阶段的执行计划。"""

    def __init__(self, raw: dict):
        self.raw = raw
        self.phase_goal: str = raw.get("phase_goal", "")
        self.parallel_groups: list[dict] = self._normalize_parallel_groups(raw.get("parallel_groups", []))
        self.sequential_steps: list[dict] = self._normalize_sequential_steps(raw.get("sequential_steps", []))
        self.skip_conditions: list[str] = self._normalize_string_list(raw.get("skip_conditions", []))
        self.risk_notes: list[str] = self._normalize_string_list(raw.get("risk_notes", []))

    def get_parallel_tool_calls(self, group_index: int = 0) -> list[dict]:
        if group_index >= len(self.parallel_groups):
            return []
        group = self.parallel_groups[group_index]
        return group.get("tools", [])

    def get_sequential_tool_calls(self) -> list[list[dict]]:
        return [step.get("tools", []) for step in self.sequential_steps]

    def display(self):
        tree = Tree(f"[bold blue]{self.phase_goal}[/bold blue]")

        for i, group in enumerate(self.parallel_groups):
            branch = tree.add(f"[cyan]并行组 {i + 1}[/cyan]: {group.get('description', '')}")
            for tool in group.get("tools", []):
                priority_color = {"high": "red", "medium": "yellow", "low": "green"}.get(
                    tool.get("priority", "medium"), "white"
                )
                branch.add(f"[{priority_color}]{tool['name']}[/] — {tool.get('reason', '')}")

        for i, step in enumerate(self.sequential_steps):
            branch = tree.add(f"[magenta]顺序步骤 {i + 1}[/magenta]: {step.get('description', '')}")
            for tool in step.get("tools", []):
                branch.add(f"  {tool['name']} — {tool.get('reason', '')}")

        if self.skip_conditions:
            skip_branch = tree.add("[dim]跳过条件[/dim]")
            for cond in self.skip_conditions:
                skip_branch.add(f"[dim]• {cond}[/dim]")

        if self.risk_notes:
            risk_branch = tree.add("[red]风险提示[/red]")
            for note in self.risk_notes:
                risk_branch.add(f"[red]• {note}[/red]")

        console.print(Panel(tree, title="[bold]执行计划[/bold]", border_style="blue"))

    @staticmethod
    def _normalize_parallel_groups(value: Any) -> list[dict]:
        if not isinstance(value, list):
            return []

        groups: list[dict] = []
        for group in value:
            if not isinstance(group, dict):
                continue
            tools = PhasePlan._normalize_tools(group.get("tools", []))
            groups.append({
                "description": str(group.get("description", "") or ""),
                "tools": tools,
            })
        return groups

    @staticmethod
    def _normalize_sequential_steps(value: Any) -> list[dict]:
        if not isinstance(value, list):
            return []

        steps: list[dict] = []
        for step in value:
            if not isinstance(step, dict):
                continue
            tools = PhasePlan._normalize_tools(step.get("tools", []))
            steps.append({
                "description": str(step.get("description", "") or ""),
                "depends_on": str(step.get("depends_on", "") or ""),
                "tools": tools,
            })
        return steps

    @staticmethod
    def _normalize_tools(value: Any) -> list[dict]:
        if not isinstance(value, list):
            return []

        tools: list[dict] = []
        for tool in value:
            normalized = PhasePlan._normalize_tool(tool)
            if normalized:
                tools.append(normalized)
        return tools

    @staticmethod
    def _normalize_tool(value: Any) -> dict | None:
        if isinstance(value, str):
            name = value.strip()
            return {"name": name, "args": {}, "priority": "medium", "reason": ""} if name else None

        if not isinstance(value, dict):
            return None

        raw_name = (
            value.get("name")
            or value.get("tool")
            or value.get("tool_name")
            or value.get("action")
        )
        name = str(raw_name or "").strip()
        if not name:
            return None

        args = value.get("args", {})
        if not isinstance(args, dict):
            args = {}

        priority = str(value.get("priority", "medium") or "medium").lower()
        if priority not in {"high", "medium", "low"}:
            priority = "medium"

        return {
            "name": name,
            "args": args,
            "priority": priority,
            "reason": str(value.get("reason", "") or ""),
        }

    @staticmethod
    def _normalize_string_list(value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(item) for item in value if item]


class Planner:
    def __init__(self, model: str | None = None, provider_name: str | None = None):
        runtime = get_runtime("planner", provider_name)
        self.provider_name = provider_name
        self.model = model or runtime.model

    def plan(
        self,
        phase: str,
        target: str,
        scope: list[str],
        available_tools: list[dict],
        previous_results: dict[str, Any] | None = None,
        rag_context: str = "",
        objective: str = "",
    ) -> PhasePlan:
        tool_summary = "\n".join(
            self._format_tool_summary(t)
            for t in available_tools
        )

        prompt = (
            f"目标: {target}\n"
            f"授权范围: {', '.join(scope)}\n"
            f"当前阶段: {phase}\n\n"
            f"可用工具:\n{tool_summary}\n"
        )

        if objective:
            prompt += f"\n测试目标 / exploit chain:\n{objective}\n"

        if previous_results:
            prompt += (
                "\n上一阶段发现:\n"
                f"{json.dumps(previous_results, ensure_ascii=False, indent=2, default=str)[:2000]}\n"
            )

        if rag_context:
            prompt += f"\n参考知识:\n{rag_context[:1000]}\n"

        prompt += "\n请生成本阶段的执行计划。"

        return self._call_llm(prompt, _PLAN_SYSTEM)

    def replan(
        self,
        phase: str,
        original_plan: PhasePlan,
        available_tools: list[dict],
        failures: list[dict],
        partial_results: list[dict],
        rag_context: str = "",
        objective: str = "",
    ) -> PhasePlan:
        prompt = (
            f"当前阶段: {phase}\n\n"
            f"原始计划目标: {original_plan.phase_goal}\n\n"
            f"可用工具:\n" + "\n".join(self._format_tool_summary(tool) for tool in available_tools) + "\n\n"
            f"失败的工具:\n{json.dumps(failures, ensure_ascii=False, indent=2)}\n\n"
            f"已获得的部分结果:\n{json.dumps(partial_results, ensure_ascii=False, indent=2, default=str)[:2000]}\n"
        )

        if objective:
            prompt += f"\n测试目标 / exploit chain:\n{objective}\n"

        if rag_context:
            prompt += f"\n参考知识:\n{rag_context[:1000]}\n"

        prompt += "\n请根据失败信息调整计划。"

        return self._call_llm(prompt, _REPLAN_SYSTEM)

    def _call_llm(self, prompt: str, system: str) -> PhasePlan:
        try:
            raw = complete_text(
                role="planner",
                provider_name=self.provider_name,
                system=system,
                prompt=prompt,
                max_tokens=2048,
            )

            import re
            match = re.search(r"\{[\s\S]*\}", raw)
            if match:
                data = json.loads(match.group())
                return PhasePlan(data)
        except Exception as e:
            console.print(f"[yellow]规划器调用失败: {e}，使用默认计划[/yellow]")

        return PhasePlan({"phase_goal": "执行默认流程", "parallel_groups": [], "sequential_steps": []})

    @staticmethod
    def _format_tool_summary(tool: dict[str, Any]) -> str:
        schema = tool.get("input_schema", {}) if isinstance(tool.get("input_schema"), dict) else {}
        required = schema.get("required", []) if isinstance(schema.get("required"), list) else []
        properties = schema.get("properties", {}) if isinstance(schema.get("properties"), dict) else {}
        property_names = ", ".join(list(properties.keys())[:8])
        required_text = ", ".join(required) if required else "无"
        return (
            f"- {tool.get('name', '')}: {tool.get('description', '')}"
            f" | 必填参数: {required_text}"
            + (f" | 已知参数: {property_names}" if property_names else "")
        )
