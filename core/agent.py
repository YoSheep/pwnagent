"""
主 Agent 循环（ReAct + 动态规划）
架构：
  Input Router → Planner(RAG) → Agent(并行工具) → Replanner(失败时) → 下一阶段
"""
from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Confirm
from rich.table import Table

from core.brain import Brain, ThinkResult, ToolCall
from core.memory import LongTermMemory, ShortTermMemory
from core.planner import PhasePlan, Planner
from core.state_machine import Finding, PentestSession, Phase

console = Console()

MAX_STEPS = 50
PARALLEL_WORKERS = 4
MAX_REPLAN_RETRIES = 2  # 同一阶段最多 replan 次数


class PentestPilot:
    def __init__(
        self,
        session: PentestSession,
        tools: dict[str, Callable],
        tool_defs: list[dict],
        interactive: bool = True,
        verbose: bool = False,
        db_path: str = "./db/sessions.db",
        rag_retriever: Callable[[str], str] | None = None,
        use_planner: bool = True,
    ):
        self.session = session
        self.session_id = str(uuid.uuid4())[:8]
        self.tools = tools
        self.tool_defs = tool_defs
        self.interactive = interactive
        self.use_planner = use_planner

        self.brain = Brain(verbose=verbose)
        self.planner = Planner() if use_planner else None
        self.short_mem = ShortTermMemory(max_messages=40)
        self.long_mem = LongTermMemory(db_path=db_path)
        self.rag_retriever = rag_retriever

        self._persist_session()

    # ------------------------------------------------------------------
    # 主入口
    # ------------------------------------------------------------------

    def run(self):
        console.print(Panel(
            f"目标: [bold cyan]{self.session.target}[/bold cyan]\n"
            f"Session ID: [dim]{self.session_id}[/dim]\n"
            f"规划模式: {'[green]启用[/green]' if self.use_planner else '[dim]关闭[/dim]'}",
            title="[bold green]PentestPilot 启动[/bold green]",
            border_style="green",
        ))

        self.session.advance()

        try:
            while self.session.phase not in (Phase.DONE,):
                self._run_phase()
                ok, reason = self.session.can_advance()
                if not ok:
                    console.print(f"[yellow]阶段推进条件未满足: {reason}[/yellow]")
                    if self.interactive:
                        if not Confirm.ask("是否强制进入下一阶段？"):
                            continue
                        self.session.force_advance()
                    else:
                        self.session.force_advance()
                else:
                    self.session.advance()
                self._persist_session()
        finally:
            self.long_mem.close()

        console.print(Panel("[bold green]渗透测试完成！[/bold green]", border_style="green"))
        self._print_summary()

    # ------------------------------------------------------------------
    # 阶段执行（Planner → Agent → Replanner）
    # ------------------------------------------------------------------

    def _run_phase(self):
        phase_label = self.session.phase.label()
        console.rule(f"[bold blue]阶段: {phase_label}[/bold blue]")

        # ① Planner：生成执行计划
        plan = self._generate_plan(phase_label)

        # ② 构建 prompt（计划 + RAG）
        init_prompt = self._build_phase_prompt(plan)
        self.short_mem.add_message({"role": "user", "content": init_prompt})

        replan_count = 0
        failures_this_phase: list[dict] = []
        results_this_phase: list[dict] = []

        for step in range(MAX_STEPS):
            extra = self._get_rag_context(phase_label)

            result: ThinkResult = self.brain.think(
                messages=self.short_mem.get_messages(),
                tools=self.tool_defs,
                phase=phase_label,
                extra_context=extra,
            )

            if not result.has_tool_calls:
                self._log_step(result.thought, "text_only", {}, result.thought)
                break

            if result.is_phase_finish:
                finish_tc = next(tc for tc in result.tool_calls if tc.name == "phase_finish")
                tool_results = [(finish_tc.tool_use_id, {"status": "phase completed"})]
                self._append_turn(result, tool_results)
                self._log_step(result.thought, "phase_finish", finish_tc.input, "阶段完成")
                break

            # 过滤高风险
            approved, rejected = self._filter_high_risk(result.tool_calls)
            if not approved and not rejected:
                break

            # 并行执行
            tool_results = self._execute_tools_parallel(approved)
            for tc in rejected:
                tool_results.append((tc.tool_use_id, {"status": "rejected", "reason": "用户拒绝"}))

            self._append_turn(result, tool_results)

            # ③ 收集结果和失败，供 Replanner 使用
            step_failures = []
            step_successes = []
            for tc in approved:
                matching = next((r for tid, r in tool_results if tid == tc.tool_use_id), None)
                self._log_step(result.thought, tc.name, tc.input, matching)
                if isinstance(matching, dict) and "error" in matching:
                    step_failures.append({"tool": tc.name, "args": tc.input, "error": matching["error"]})
                else:
                    step_successes.append({"tool": tc.name, "result_preview": str(matching)[:200]})

            failures_this_phase.extend(step_failures)
            results_this_phase.extend(step_successes)

            # ④ Replanner：连续失败时调整策略
            if step_failures and replan_count < MAX_REPLAN_RETRIES and self.planner:
                replan_count += 1
                console.print(
                    f"[yellow]检测到 {len(step_failures)} 个工具失败，"
                    f"触发重新规划 ({replan_count}/{MAX_REPLAN_RETRIES})...[/yellow]"
                )
                new_plan = self._replan(phase_label, plan, failures_this_phase, results_this_phase)
                if new_plan.phase_goal:
                    plan = new_plan
                    # 将新计划注入对话
                    replan_msg = self._format_replan_message(new_plan, step_failures)
                    self.short_mem.add_message({"role": "user", "content": replan_msg})
        else:
            console.print(f"[yellow]阶段 {phase_label} 达到最大步数 ({MAX_STEPS})。[/yellow]")

    # ------------------------------------------------------------------
    # Planner 集成
    # ------------------------------------------------------------------

    def _generate_plan(self, phase_label: str) -> PhasePlan | None:
        if not self.planner:
            return None

        console.print("[dim]正在生成执行计划...[/dim]")

        rag_context = self._get_rag_context(phase_label)

        # 上一阶段的成果作为输入
        previous_results = {
            "attack_surface": self.session.attack_surface,
            "findings_count": len(self.session.findings),
            "findings_summary": [
                {"title": f.title, "severity": f.severity, "target": f.target}
                for f in self.session.findings[:10]
            ],
        }

        plan = self.planner.plan(
            phase=phase_label,
            target=self.session.target,
            scope=self.session.scope,
            available_tools=self.tool_defs,
            previous_results=previous_results if self.session.attack_surface else None,
            rag_context=rag_context,
        )
        plan.display()
        return plan

    def _replan(
        self, phase_label: str, original_plan: PhasePlan,
        failures: list[dict], partial_results: list[dict],
    ) -> PhasePlan:
        rag_context = self._get_rag_context(phase_label)
        new_plan = self.planner.replan(
            phase=phase_label,
            original_plan=original_plan,
            failures=failures,
            partial_results=partial_results,
            rag_context=rag_context,
        )
        console.print("[yellow]调整后的计划：[/yellow]")
        new_plan.display()
        return new_plan

    def _format_replan_message(self, plan: PhasePlan, failures: list[dict]) -> str:
        failure_summary = "\n".join(f"- {f['tool']}: {f['error']}" for f in failures)
        tool_suggestions = []
        for group in plan.parallel_groups:
            for tool in group.get("tools", []):
                tool_suggestions.append(f"- {tool['name']}: {tool.get('reason', '')}")
        for step in plan.sequential_steps:
            for tool in step.get("tools", []):
                tool_suggestions.append(f"- {tool['name']}: {tool.get('reason', '')}")

        return (
            f"[系统] 计划已调整。\n\n"
            f"失败的工具:\n{failure_summary}\n\n"
            f"新计划目标: {plan.phase_goal}\n"
            f"建议的工具调用:\n" + "\n".join(tool_suggestions) +
            "\n\n请根据调整后的计划继续执行。"
        )

    # ------------------------------------------------------------------
    # Prompt 构建（融合 Plan）
    # ------------------------------------------------------------------

    def _build_phase_prompt(self, plan: PhasePlan | None) -> str:
        phase = self.session.phase
        summary = self.session.summary()

        base = (
            f"当前目标: {self.session.target}\n"
            f"授权范围: {', '.join(self.session.scope)}\n"
            f"当前阶段: {phase.label()}\n"
            f"已发现攻击面: {summary['attack_surface_items']} 项\n"
            f"已发现漏洞: {summary['findings']} 个\n\n"
        )

        # 如果有 Plan，用 Plan 的指令而不是硬编码
        if plan and plan.phase_goal:
            plan_text = f"本阶段目标: {plan.phase_goal}\n\n"

            if plan.parallel_groups:
                plan_text += "以下工具可以并行调用（请在同一次回复中同时调用）：\n"
                for i, group in enumerate(plan.parallel_groups):
                    tools_list = ", ".join(t["name"] for t in group.get("tools", []))
                    plan_text += f"  组{i+1}: {tools_list}\n"
                plan_text += "\n"

            if plan.sequential_steps:
                plan_text += "以下步骤需要在并行组完成后顺序执行：\n"
                for step in plan.sequential_steps:
                    tools_list = ", ".join(t["name"] for t in step.get("tools", []))
                    plan_text += f"  - {step.get('description', '')}: {tools_list}\n"
                plan_text += "\n"

            if plan.skip_conditions:
                plan_text += "跳过条件：\n"
                for cond in plan.skip_conditions:
                    plan_text += f"  - {cond}\n"
                plan_text += "\n"

            if plan.risk_notes:
                plan_text += "注意事项：\n"
                for note in plan.risk_notes:
                    plan_text += f"  - {note}\n"
                plan_text += "\n"

            plan_text += "完成所有操作后调用 phase_finish。"
            return base + plan_text

        # fallback：无 Planner 时的硬编码指令
        return base + self._default_phase_instructions(phase)

    @staticmethod
    def _default_phase_instructions(phase: Phase) -> str:
        instructions = {
            Phase.RECON: (
                "执行信息收集：\n"
                "可并行: nmap_scan, httpx_probe, subdomain_enum, dirbust\n"
                "完成后调用 phase_finish。"
            ),
            Phase.SCAN: (
                "执行漏洞扫描：\n"
                "可并行: nuclei_scan, onedaypoc_scan, python_vuln_check\n"
                "按需: xss_scan, sqli_scan, ssrf_scan\n"
                "完成后调用 phase_finish。"
            ),
            Phase.EXPLOIT: "对已发现漏洞进行验证（仅验证不破坏），完成后调用 phase_finish。",
            Phase.POST_EXPLOIT: "后渗透分析（仅理论分析），完成后调用 phase_finish。",
            Phase.REPORT: "调用 generate_report 生成报告，然后调用 phase_finish。",
        }
        return instructions.get(phase, "完成后调用 phase_finish。")

    # ------------------------------------------------------------------
    # 并行工具执行
    # ------------------------------------------------------------------

    def _execute_tools_parallel(self, tool_calls: list[ToolCall]) -> list[tuple[str, Any]]:
        if len(tool_calls) == 1:
            tc = tool_calls[0]
            result = self._execute_tool(tc.name, tc.input)
            return [(tc.tool_use_id, result)]

        results: list[tuple[str, Any]] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            tasks = {}
            with ThreadPoolExecutor(max_workers=PARALLEL_WORKERS) as pool:
                for tc in tool_calls:
                    task_id = progress.add_task(f"  {tc.name}", total=None)
                    future = pool.submit(self._execute_tool, tc.name, tc.input)
                    tasks[future] = (tc.tool_use_id, tc.name, task_id)

                for future in as_completed(tasks):
                    tool_use_id, tool_name, task_id = tasks[future]
                    try:
                        result = future.result()
                    except Exception as e:
                        result = {"error": f"并行执行失败: {e}"}
                    results.append((tool_use_id, result))
                    progress.update(task_id, completed=True)
                    status = "error" if isinstance(result, dict) and "error" in result else "ok"
                    console.print(f"[{'red' if status == 'error' else 'green'}]  ✓ {tool_name}[/]")

        return results

    def _execute_tool(self, tool_name: str, action_input: dict) -> Any:
        if tool_name not in self.tools:
            return {"error": f"未知工具: {tool_name}，可用: {list(self.tools.keys())}"}

        if not isinstance(action_input, dict):
            return {"error": f"action_input 应为 dict，收到: {type(action_input).__name__}"}

        try:
            return self.tools[tool_name](**action_input)
        except TypeError as e:
            return {"error": f"参数错误: {e}"}
        except Exception as e:
            return {"error": f"执行失败 ({type(e).__name__}): {e}"}

    # ------------------------------------------------------------------
    # 高风险过滤
    # ------------------------------------------------------------------

    def _filter_high_risk(self, tool_calls: list[ToolCall]) -> tuple[list[ToolCall], list[ToolCall]]:
        if not self.interactive:
            return tool_calls, []
        approved, rejected = [], []
        for tc in tool_calls:
            if self._is_high_risk(tc.name, tc.input):
                console.print(Panel(
                    f"[bold red]高风险操作[/bold red]\n工具: {tc.name}\n参数: {tc.input}",
                    border_style="red",
                ))
                if Confirm.ask("是否允许执行此操作？"):
                    approved.append(tc)
                else:
                    rejected.append(tc)
            else:
                approved.append(tc)
        return approved, rejected

    @staticmethod
    def _is_high_risk(action: str, action_input: dict) -> bool:
        high_risk_tools = {"sqli_scan", "exploit_gen"}
        if action in high_risk_tools:
            return True
        level = action_input.get("level", 1)
        risk = action_input.get("risk", 1)
        return (isinstance(level, int) and level >= 3) or (isinstance(risk, int) and risk >= 2)

    # ------------------------------------------------------------------
    # RAG
    # ------------------------------------------------------------------

    def _get_rag_context(self, phase_label: str) -> str:
        if not self.rag_retriever:
            return ""
        try:
            return self.rag_retriever(f"{phase_label} {self.session.target}")
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # 消息历史
    # ------------------------------------------------------------------

    def _append_turn(self, result: ThinkResult, tool_results: list[tuple[str, Any]]):
        self.short_mem.add_message(self.brain.build_assistant_message(result))
        self.short_mem.add_message(self.brain.build_tool_results_message(tool_results))

    # ------------------------------------------------------------------
    # 持久化 / 输出
    # ------------------------------------------------------------------

    def _log_step(self, thought: str, action: str, action_input: dict, result: Any):
        entry = {
            "phase": self.session.phase.name,
            "thought": thought,
            "action": action,
            "action_input": action_input,
            "result": result,
        }
        self.session.thought_log.append(entry)
        self.long_mem.save_thought(self.session_id, entry)

    def _persist_session(self):
        self.long_mem.save_session(
            self.session_id, self.session.target, self.session.scope,
            self.session.phase.name, self.session.summary(),
        )

    def _print_summary(self):
        table = Table(title="测试结果摘要", show_lines=True)
        table.add_column("严重程度", style="bold")
        table.add_column("数量", justify="right")
        colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green", "info": "dim"}
        for sev, count in self.session._findings_by_severity().items():
            table.add_row(f"[{colors.get(sev, '')}]{sev.upper()}[/]", str(count))
        console.print(table)

    def register_finding(self, finding: Finding):
        self.session.add_finding(finding)
        self.long_mem.save_finding(self.session_id, finding)
        color = "red" if finding.severity in ("critical", "high") else "yellow"
        console.print(f"[bold {color}][+] 发现 {finding.severity.upper()}: {finding.title}[/]")
