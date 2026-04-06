"""
Planner + Replanner — 动态任务规划
参考架构图中 Planner → Supervisor → Replanner 的循环，但用单 LLM 调用实现。

职责：
1. 阶段开始前：根据 RAG 知识 + 上一阶段结果 → 生成当前阶段的执行计划
2. 阶段执行中：工具失败/信息不足时 → 动态调整计划
3. 决策时提供：该并行调用哪些工具、该跳过什么、该深入什么
"""
from __future__ import annotations

import json
from typing import Any

import anthropic
from rich.console import Console
from rich.panel import Panel
from rich.tree import Tree

console = Console()

_PLAN_SYSTEM = """你是一个渗透测试规划专家。根据以下信息生成执行计划：
- 目标信息
- 当前阶段
- 上一阶段发现的结果
- 参考知识（如有）
- 可用工具列表

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
- 是否应该放弃某些路径，聚焦其他方向"""


class PhasePlan:
    """一个阶段的执行计划。"""

    def __init__(self, raw: dict):
        self.raw = raw
        self.phase_goal: str = raw.get("phase_goal", "")
        self.parallel_groups: list[dict] = raw.get("parallel_groups", [])
        self.sequential_steps: list[dict] = raw.get("sequential_steps", [])
        self.skip_conditions: list[str] = raw.get("skip_conditions", [])
        self.risk_notes: list[str] = raw.get("risk_notes", [])

    def get_parallel_tool_calls(self, group_index: int = 0) -> list[dict]:
        """获取指定并行组的工具调用列表。"""
        if group_index >= len(self.parallel_groups):
            return []
        group = self.parallel_groups[group_index]
        return group.get("tools", [])

    def get_sequential_tool_calls(self) -> list[list[dict]]:
        """获取顺序执行步骤的工具调用。"""
        return [step.get("tools", []) for step in self.sequential_steps]

    def display(self):
        """Rich 渲染执行计划。"""
        tree = Tree(f"[bold blue]{self.phase_goal}[/bold blue]")

        for i, group in enumerate(self.parallel_groups):
            branch = tree.add(f"[cyan]并行组 {i + 1}[/cyan]: {group.get('description', '')}")
            for tool in group.get("tools", []):
                priority_color = {"high": "red", "medium": "yellow", "low": "green"}.get(
                    tool.get("priority", "medium"), "white"
                )
                branch.add(
                    f"[{priority_color}]{tool['name']}[/] — {tool.get('reason', '')}"
                )

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


class Planner:
    def __init__(self, model: str = "claude-sonnet-4-20250514"):
        """规划器用较小的模型即可，节省成本。"""
        self.client = anthropic.Anthropic()
        self.model = model

    def plan(
        self,
        phase: str,
        target: str,
        scope: list[str],
        available_tools: list[dict],
        previous_results: dict[str, Any] | None = None,
        rag_context: str = "",
    ) -> PhasePlan:
        """
        为当前阶段生成执行计划。
        :param phase:            阶段名称
        :param target:           目标
        :param scope:            授权范围
        :param available_tools:  可用工具定义列表
        :param previous_results: 上一阶段的关键发现
        :param rag_context:      RAG 检索到的知识
        """
        tool_summary = "\n".join(
            f"- {t['name']}: {t.get('description', '')}"
            for t in available_tools
        )

        prompt = (
            f"目标: {target}\n"
            f"授权范围: {', '.join(scope)}\n"
            f"当前阶段: {phase}\n\n"
            f"可用工具:\n{tool_summary}\n"
        )

        if previous_results:
            prompt += f"\n上一阶段发现:\n{json.dumps(previous_results, ensure_ascii=False, indent=2, default=str)[:2000]}\n"

        if rag_context:
            prompt += f"\n参考知识:\n{rag_context[:1000]}\n"

        prompt += "\n请生成本阶段的执行计划。"

        return self._call_llm(prompt, _PLAN_SYSTEM)

    def replan(
        self,
        phase: str,
        original_plan: PhasePlan,
        failures: list[dict],
        partial_results: list[dict],
        rag_context: str = "",
    ) -> PhasePlan:
        """
        当执行遇到问题时，生成调整后的计划。
        :param failures:       失败的工具调用 [{tool, error}, ...]
        :param partial_results: 已获得的部分结果
        """
        prompt = (
            f"当前阶段: {phase}\n\n"
            f"原始计划目标: {original_plan.phase_goal}\n\n"
            f"失败的工具:\n{json.dumps(failures, ensure_ascii=False, indent=2)}\n\n"
            f"已获得的部分结果:\n{json.dumps(partial_results, ensure_ascii=False, indent=2, default=str)[:2000]}\n"
        )

        if rag_context:
            prompt += f"\n参考知识:\n{rag_context[:1000]}\n"

        prompt += "\n请根据失败信息调整计划。"

        return self._call_llm(prompt, _REPLAN_SYSTEM)

    def _call_llm(self, prompt: str, system: str) -> PhasePlan:
        try:
            resp = self.client.messages.create(
                model=self.model,
                max_tokens=2048,
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = resp.content[0].text

            import re
            match = re.search(r'\{[\s\S]*\}', raw)
            if match:
                data = json.loads(match.group())
                return PhasePlan(data)
        except Exception as e:
            console.print(f"[yellow]规划器调用失败: {e}，使用默认计划[/yellow]")

        return PhasePlan({"phase_goal": "执行默认流程", "parallel_groups": [], "sequential_steps": []})
