"""
主 Agent 循环（ReAct + 动态规划）
架构：
  Input Router → Planner(RAG) → Agent(并行工具) → Replanner(失败时) → 下一阶段
"""
from __future__ import annotations

import json
import re
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable
from urllib.parse import parse_qsl, urlparse

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
        self.tool_def_map = {tool["name"]: tool for tool in tool_defs}
        self.interactive = interactive
        self.use_planner = use_planner

        self.brain = Brain(verbose=verbose)
        self.planner = Planner() if use_planner else None
        self.short_mem = ShortTermMemory(max_messages=40)
        self.long_mem = LongTermMemory(db_path=db_path)
        self.rag_retriever = rag_retriever
        self._risk_decisions: dict[str, bool] = {}
        self._tool_result_cache: dict[str, Any] = {}
        self._phase_tool_counts: dict[str, int] = {}
        self._web_seed_done = False

        self._initialize_tool_runtimes()
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

    def _initialize_tool_runtimes(self):
        """
        Agent 启动阶段预热关键外部工具。
        当前仅处理 sqlmap：自动拉取/更新，避免首次调用时阻塞或失败。
        """
        if "sqli_scan" not in self.tools:
            return
        try:
            from tools.sqli_tool import sqlmap_prepare

            result = sqlmap_prepare(update=True, force_clone=False)
            if result.get("ready"):
                runtime = result.get("runtime", {})
                console.print(
                    f"[dim]sqlmap runtime ready: "
                    f"{runtime.get('source', '')} -> {runtime.get('home', '')}[/dim]"
                )
            else:
                console.print(
                    f"[yellow]sqlmap 初始化未就绪: {result.get('error', 'unknown error')}[/yellow]"
                )
        except Exception as exc:
            console.print(f"[yellow]sqlmap 初始化异常，跳过预热: {exc}[/yellow]")

    # ------------------------------------------------------------------
    # 阶段执行（Planner → Agent → Replanner）
    # ------------------------------------------------------------------

    def _run_phase(self):
        phase_label = self.session.phase.label()
        console.rule(f"[bold blue]阶段: {phase_label}[/bold blue]")
        self._phase_tool_counts = {}

        # 0) 在 RECON 阶段先做一次“curl-like 页面预热”
        if self.session.phase == Phase.RECON:
            self._seed_initial_web_intel()

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
            approved, policy_skipped = self._apply_focus_policy(approved)
            if not approved and not rejected and not policy_skipped:
                break

            # 并行执行
            tool_results = self._execute_tools_parallel(approved) if approved else []
            for tc, reason in policy_skipped:
                tool_results.append((tc.tool_use_id, {"skipped": reason, "focus_policy": True}))
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

            for tc, _ in policy_skipped:
                matching = next((r for tid, r in tool_results if tid == tc.tool_use_id), None)
                self._log_step(result.thought, tc.name, tc.input, matching)

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

    def _seed_initial_web_intel(self):
        """
        RECON 阶段确定性预热：
        先读取首页并提取真实站内导航/参数线索，避免模型起手盲扫。
        """
        if self._web_seed_done:
            return

        has_page_intel = "page_intel" in self.tools
        has_http_request = "http_request" in self.tools
        if not has_page_intel and not has_http_request:
            self._web_seed_done = True
            return

        if self.session.attack_surface.get("navigation_candidates") or self.session.attack_surface.get("api_candidates"):
            self._web_seed_done = True
            return

        console.print("[dim]预热：先读取首页并提取页面里的真实链接与参数线索...[/dim]")
        seed_action_count = 0

        if has_page_intel:
            page_input = {
                "target": self.session.target,
                "path": "",
                "include_external_scripts": False,
                "max_external_scripts": 2,
            }
            page_result = self._execute_tool("page_intel", page_input)
            self._log_step(
                "系统预热：先读取首页 HTML，提取导航链接、表单和参数线索（curl-like）。",
                "page_intel",
                page_input,
                page_result,
            )
            seed_action_count += 1
        elif has_http_request:
            req_input = {
                "target": self.session.target,
                "method": "GET",
                "capture_body": True,
                "follow_redirects": True,
            }
            req_result = self._execute_tool("http_request", req_input)
            self._log_step(
                "系统预热：先请求首页并记录响应结构（curl-like）。",
                "http_request",
                req_input,
                req_result,
            )
            seed_action_count += 1

        # 跟进 1~2 个同源真实导航页面，强化动态参数线索
        if has_http_request:
            follow_count = 0
            for item in self._navigation_frontier(limit=4):
                if follow_count >= 2:
                    break
                url = str(item.get("url", "")).strip()
                req_input = self._http_request_input_from_url(url)
                if not req_input:
                    continue
                req_result = self._execute_tool("http_request", req_input)
                self._log_step(
                    "系统预热：跟进页面中真实出现的同源导航链接。",
                    "http_request",
                    req_input,
                    req_result,
                )
                follow_count += 1
                seed_action_count += 1

        nav_count = len(self.session.attack_surface.get("navigation_candidates", []))
        api_count = len(self.session.attack_surface.get("api_candidates", []))
        console.print(
            f"[dim]预热完成：执行 {seed_action_count} 个步骤，"
            f"导航候选 {nav_count}，接口候选 {api_count}。[/dim]"
        )
        self._web_seed_done = True

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
            "credentials": self.session.credentials[:10],
            "authenticated_sessions": list(self.session.authenticated_sessions.keys()),
            "navigation_candidates": self._navigation_frontier(limit=8, include_visited=True),
            "attack_path_hints": self._attack_path_hints(),
        }

        plan = self.planner.plan(
            phase=phase_label,
            target=self.session.target,
            scope=self.session.scope,
            available_tools=self.tool_defs,
            previous_results=previous_results if self.session.attack_surface_count() or self.session.findings or self.session.credentials else None,
            rag_context=rag_context,
            objective=self.session.objective,
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
            available_tools=self.tool_defs,
            failures=failures,
            partial_results=partial_results,
            rag_context=rag_context,
            objective=self.session.objective,
        )
        console.print("[yellow]调整后的计划：[/yellow]")
        new_plan.display()
        return new_plan

    def _format_replan_message(self, plan: PhasePlan, failures: list[dict]) -> str:
        failure_summary = "\n".join(f"- {f['tool']}: {f['error']}" for f in failures)
        tool_suggestions = []
        for group in plan.parallel_groups:
            for tool in group.get("tools", []):
                tool_suggestions.append(f"- {tool.get('name', 'unknown_tool')}: {tool.get('reason', '')}")
        for step in plan.sequential_steps:
            for tool in step.get("tools", []):
                tool_suggestions.append(f"- {tool.get('name', 'unknown_tool')}: {tool.get('reason', '')}")

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
        if self.session.objective:
            base += f"当前 exploit chain / 测试目标: {self.session.objective}\n"
        if self.session.credentials:
            base += f"已拿到凭据/哈希线索: {len(self.session.credentials)} 条\n"
        if self.session.authenticated_sessions:
            base += f"已建立认证会话: {', '.join(self.session.authenticated_sessions.keys())}\n"

        navigation_frontier = self._navigation_frontier(limit=6)
        if navigation_frontier:
            base += "优先跟进的页面导航候选:\n"
            for item in navigation_frontier:
                reason = item.get("reason", "")
                preview = item.get("path") or item.get("url", "")
                if item.get("param_names"):
                    preview += f" ?{','.join(item.get('param_names', [])[:4])}"
                base += f"  - {preview}"
                if reason:
                    base += f" ({reason})"
                base += "\n"
            base += "\n"

        hints = self._attack_path_hints()
        if hints:
            base += "当前攻击路径假设:\n"
            for hint in hints:
                base += f"  - {hint}\n"
            base += "\n"

        if self._is_explicit_sqli_focus_mode():
            base += (
                "SQLi 聚焦模式已启用：\n"
                "  - 优先工具: sqli_scan\n"
                "  - 执行顺序: detect -> enumerate -> dump（围绕同一 API/参数）\n"
                "  - 禁止发散到 SSRF/JWT/XSS/广域枚举，除非该链路明确失败并有新证据。\n\n"
            )

        # 如果有 Plan，用 Plan 的指令而不是硬编码
        if plan and plan.phase_goal:
            plan_text = f"本阶段目标: {plan.phase_goal}\n\n"

            if plan.parallel_groups:
                plan_text += "以下工具可以并行调用（请在同一次回复中同时调用）：\n"
                for i, group in enumerate(plan.parallel_groups):
                    tools_list = ", ".join(t.get("name", "unknown_tool") for t in group.get("tools", []))
                    plan_text += f"  组{i+1}: {tools_list}\n"
                plan_text += "\n"

            if plan.sequential_steps:
                plan_text += "以下步骤需要在并行组完成后顺序执行：\n"
                for step in plan.sequential_steps:
                    tools_list = ", ".join(t.get("name", "unknown_tool") for t in step.get("tools", []))
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
                "优先顺序: 先用 page_intel / http_request 跟进页面里真实出现的站内链接与表单，再做必要的 nmap_scan / httpx_probe / dirbust。\n"
                "可并行: nmap_scan, httpx_probe, page_intel, dirbust, http_request\n"
                "完成后调用 phase_finish。"
            ),
            Phase.SCAN: (
                "执行漏洞扫描：\n"
                "如果已发现导航候选、动态参数页、后台或登录页，优先围绕这些真实页面做 SQLi / 登录 / 上传链路，而不是继续泛化扫描。\n"
                "可并行: nuclei_scan, onedaypoc_scan, python_vuln_check\n"
                "按需: xss_scan, sqli_scan, ssrf_scan, hash_crack\n"
                "完成后调用 phase_finish。"
            ),
            Phase.EXPLOIT: (
                "对已发现漏洞进行验证/利用链推进：优先使用 http_request、login_form、upload_file、"
                "sqli_scan(mode=enumerate/dump)、hash_crack，完成后调用 phase_finish。"
            ),
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
            display_name = self._tool_display_name(tc.name, tc.input)
            console.print(f"  → 调用 1 个工具: {display_name}")
            started_at = time.perf_counter()
            result = self._execute_tool(tc.name, tc.input)
            elapsed = time.perf_counter() - started_at
            if isinstance(result, dict) and "error" in result:
                console.print(f"[red]  ✗ {display_name} ({elapsed:.1f}s)[/]")
            elif isinstance(result, dict) and result.get("skipped"):
                reason = str(result.get("skipped", ""))
                console.print(f"[yellow]  ↷ {display_name} ({elapsed:.1f}s)[/]")
                if reason:
                    console.print(f"[dim]    跳过原因: {reason}[/dim]")
            else:
                console.print(f"[green]  ✓ {display_name} ({elapsed:.1f}s)[/]")
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
                    display_name = self._tool_display_name(tc.name, tc.input)
                    task_id = progress.add_task(f"  {display_name}", total=None)
                    future = pool.submit(self._execute_tool, tc.name, tc.input)
                    tasks[future] = (tc.tool_use_id, tc.name, display_name, task_id)

                for future in as_completed(tasks):
                    tool_use_id, tool_name, display_name, task_id = tasks[future]
                    try:
                        result = future.result()
                    except Exception as e:
                        result = {"error": f"并行执行失败: {e}"}
                    results.append((tool_use_id, result))
                    progress.update(task_id, completed=True)
                    if isinstance(result, dict) and "error" in result:
                        console.print(f"[red]  ✗ {display_name}[/]")
                    elif isinstance(result, dict) and result.get("skipped"):
                        console.print(f"[yellow]  ↷ {display_name}[/]")
                    else:
                        console.print(f"[green]  ✓ {display_name}[/]")

        return results

    def _execute_tool(self, tool_name: str, action_input: dict) -> Any:
        if tool_name not in self.tools:
            return {"error": f"未知工具: {tool_name}，可用: {list(self.tools.keys())}"}

        if not isinstance(action_input, dict):
            return {"error": f"action_input 应为 dict，收到: {type(action_input).__name__}"}

        action_input = self._coerce_action_input(tool_name, action_input)

        validation_error = self._validate_tool_input(tool_name, action_input)
        if validation_error:
            return {"error": validation_error}

        cache_key = self._tool_cache_key(tool_name, action_input)
        if cache_key in self._tool_result_cache:
            return {
                "skipped": "重复调用，沿用之前的结果",
                "cached_tool": tool_name,
            }

        defer_reason = self._should_defer_broad_scan(tool_name, action_input)
        if defer_reason:
            return {
                "skipped": defer_reason,
                "deferred_tool": tool_name,
            }

        repeat_key = self._phase_repeat_key(tool_name, action_input)
        if repeat_key:
            count = self._phase_tool_counts.get(repeat_key, 0)
            threshold = self._phase_repeat_threshold(tool_name)
            if count >= threshold:
                return {
                    "skipped": f"同一阶段内重复执行 {tool_name} 已达到上限，避免无效重试",
                    "repeat_key": repeat_key,
                }
            self._phase_tool_counts[repeat_key] = count + 1

        try:
            result = self.tools[tool_name](**action_input)
        except TypeError as e:
            return {"error": f"参数错误: {e}"}
        except Exception as e:
            return {"error": f"执行失败 ({type(e).__name__}): {e}"}

        self._tool_result_cache[cache_key] = result
        self._ingest_tool_result(tool_name, action_input, result)
        return result

    def _coerce_action_input(self, tool_name: str, action_input: dict[str, Any]) -> dict[str, Any]:
        """
        按工具 schema 对模型输出做轻量类型纠正，避免 "3000"/"true" 导致执行异常。
        """
        normalized = dict(action_input)
        schema = self.tool_def_map.get(tool_name, {}).get("input_schema", {})
        properties = schema.get("properties", {}) if isinstance(schema, dict) else {}

        for key, prop in properties.items():
            if key not in normalized or not isinstance(prop, dict):
                continue
            expected = self._extract_schema_type(prop.get("type"))
            value = normalized.get(key)
            normalized[key] = self._coerce_value(value, expected)

        return normalized

    @staticmethod
    def _extract_schema_type(schema_type: Any) -> str:
        if isinstance(schema_type, str):
            return schema_type.lower()
        if isinstance(schema_type, list):
            for item in schema_type:
                if isinstance(item, str) and item.lower() != "null":
                    return item.lower()
        return ""

    @staticmethod
    def _coerce_value(value: Any, expected_type: str) -> Any:
        if expected_type == "integer":
            if isinstance(value, bool):
                return int(value)
            if isinstance(value, (int, float)):
                return int(value)
            if isinstance(value, str):
                text = value.strip()
                if re.fullmatch(r"-?\d+", text):
                    try:
                        return int(text)
                    except Exception:
                        return value
            return value

        if expected_type == "number":
            if isinstance(value, bool):
                return float(value)
            if isinstance(value, (int, float)):
                return float(value)
            if isinstance(value, str):
                text = value.strip()
                if re.fullmatch(r"-?\d+(\.\d+)?", text):
                    try:
                        return float(text)
                    except Exception:
                        return value
            return value

        if expected_type == "boolean":
            if isinstance(value, bool):
                return value
            if isinstance(value, (int, float)):
                return bool(value)
            if isinstance(value, str):
                text = value.strip().lower()
                if text in {"true", "1", "yes", "y", "on"}:
                    return True
                if text in {"false", "0", "no", "n", "off"}:
                    return False
            return value

        if expected_type == "array":
            if isinstance(value, list):
                return value
            if isinstance(value, str):
                text = value.strip()
                if not text:
                    return []
                if text.startswith("[") and text.endswith("]"):
                    try:
                        parsed = json.loads(text)
                        if isinstance(parsed, list):
                            return parsed
                    except Exception:
                        pass
                return [part.strip() for part in text.split(",") if part.strip()]
            return value

        if expected_type == "object":
            if isinstance(value, dict):
                return value
            if isinstance(value, str):
                text = value.strip()
                if text.startswith("{") and text.endswith("}"):
                    try:
                        parsed = json.loads(text)
                        if isinstance(parsed, dict):
                            return parsed
                    except Exception:
                        pass
            return value

        return value

    # ------------------------------------------------------------------
    # 高风险过滤
    # ------------------------------------------------------------------

    def _filter_high_risk(self, tool_calls: list[ToolCall]) -> tuple[list[ToolCall], list[ToolCall]]:
        if not self.interactive:
            return tool_calls, []
        approved, rejected = [], []
        for tc in tool_calls:
            if self._is_high_risk(tc.name, tc.input):
                decision_key = self._risk_decision_key(tc.name, tc.input)
                cached_decision = self._risk_decisions.get(decision_key)
                if cached_decision is not None:
                    console.print(
                        f"[dim]复用之前的高风险操作确认: {tc.name} -> "
                        f"{'允许' if cached_decision else '拒绝'}[/dim]"
                    )
                    if cached_decision:
                        approved.append(tc)
                    else:
                        rejected.append(tc)
                    continue

                console.print(Panel(
                    f"[bold red]高风险操作[/bold red]\n工具: {tc.name}\n参数: {tc.input}",
                    border_style="red",
                ))
                allowed = Confirm.ask("是否允许执行此操作？")
                self._risk_decisions[decision_key] = allowed
                if allowed:
                    approved.append(tc)
                else:
                    rejected.append(tc)
            else:
                approved.append(tc)
        return approved, rejected

    def _apply_focus_policy(self, tool_calls: list[ToolCall]) -> tuple[list[ToolCall], list[tuple[ToolCall, str]]]:
        """
        在执行层做强约束：
        当 SQLi 线索已充分时，限制无关工具，强制收敛到 SQLi 利用链。
        """
        if not tool_calls:
            return tool_calls, []
        if not self._is_explicit_sqli_focus_mode():
            return tool_calls, []

        allowed = {"sqli_scan", "http_request", "page_intel", "phase_finish"}
        deferred: list[tuple[ToolCall, str]] = []
        filtered: list[ToolCall] = []
        for tc in tool_calls:
            if tc.name not in allowed:
                deferred.append((tc, "SQLi 聚焦模式：已确认注入线索，暂缓无关工具。"))
                continue
            if tc.name == "sqli_scan":
                filtered.append(ToolCall(tc.tool_use_id, tc.name, self._normalize_sqli_call_input(tc.input)))
            elif tc.name in {"http_request", "page_intel"}:
                if self._is_focus_related_request(tc.input):
                    filtered.append(tc)
                else:
                    deferred.append((tc, "SQLi 聚焦模式：仅跟进与注入链相关的页面/API。"))
            else:
                filtered.append(tc)

        has_sqli = any(tc.name == "sqli_scan" for tc in filtered)
        if not has_sqli and "sqli_scan" in self.tools:
            targets = self._sqli_focus_targets(limit=1)
            if targets:
                forced_input: dict[str, Any] = {
                    "target": targets[0].get("target", ""),
                    "mode": "detect",
                    "level": 3,
                    "risk": 2,
                    "profile": "deep",
                    "use_common_dict": True,
                }
                if targets[0].get("data"):
                    forced_input["data"] = targets[0].get("data")

                rewriteable = {"page_intel", "httpx_probe", "dirbust", "nuclei_scan", "subdomain_enum"}
                for index, tc in enumerate(filtered):
                    if tc.name == "phase_finish" or tc.name not in rewriteable:
                        continue
                    filtered[index] = ToolCall(tc.tool_use_id, "sqli_scan", forced_input)
                    console.print("[dim]SQLi 聚焦模式：将当前步骤改写为 sqli_scan 以推进利用链。[/dim]")
                    break

        return filtered, deferred

    def _is_sqli_focus_active(self) -> bool:
        objective = (self.session.objective or "").lower()
        if any(marker in objective for marker in ("sqli", "sql", "injection", "select-no-waf")):
            return True

        for finding in self.session.findings:
            title = str(finding.title).lower()
            if "sql" in title:
                return True

        for section in ("api_candidates", "navigation_candidates", "endpoints"):
            for item in self.session.attack_surface.get(section, []):
                if not isinstance(item, dict):
                    continue
                url = str(item.get("url", "")).lower()
                path = str(item.get("path", "")).lower()
                param_names = [str(name).lower() for name in item.get("param_names", []) if str(name).strip()]
                tags = [str(tag).lower() for tag in item.get("tags", []) if str(tag).strip()]

                if "select-no-waf" in url or "select-no-waf" in path:
                    return True
                if "/api" in path and any(name in {"id", "uid", "user_id", "item_id", "cat_id"} for name in param_names):
                    return True
                if "api" in tags and any(name in {"id", "uid", "user_id", "item_id", "cat_id"} for name in param_names):
                    return True
        return False

    def _is_explicit_sqli_focus_mode(self) -> bool:
        """
        仅在用户显式要求时启用 SQLi 聚焦策略，避免把通用 agent 变成单漏洞 agent。
        可接受示例：
        - --objective "focus:sqli"
        - --objective "mode=sqli"
        - --objective "only sqli"
        """
        objective = (self.session.objective or "").strip().lower()
        if not objective:
            return False
        markers = {
            "focus:sqli",
            "focus=sqli",
            "mode:sqli",
            "mode=sqli",
            "only sqli",
            "only sqli",
            "sqli only",
            "只测 sqli",
            "只测sqli",
            "仅 sqli",
            "仅sqli",
        }
        return any(marker in objective for marker in markers)

    def _sqli_focus_targets(self, limit: int = 4) -> list[dict[str, str]]:
        candidates: list[dict[str, str]] = []

        def _append_candidate(url: str, param_names: list[str] | None = None):
            if not url:
                return
            parsed = urlparse(url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                return
            if urlparse(self.session.target).netloc != parsed.netloc:
                return
            path = parsed.path or "/"
            query = parsed.query
            param_names = [p.lower() for p in (param_names or [])]

            if not query:
                if any(name in {"id", "uid", "user_id", "item_id", "cat_id"} for name in param_names):
                    query = "id=1"
                elif "select-no-waf" in path:
                    query = "id=1"
            if not query and "/api" not in path and "select-no-waf" not in path:
                return

            get_target = f"{parsed.scheme}://{parsed.netloc}{path}"
            if query:
                get_target = f"{get_target}?{query}"

            # API 常见支持 POST，给 sqlmap 一个更稳定的数据入口
            post_data = query if query and "/api" in path else ""
            candidates.append({"target": get_target, "data": post_data})

        for section in ("api_candidates", "navigation_candidates", "endpoints"):
            for item in self.session.attack_surface.get(section, []):
                if not isinstance(item, dict):
                    continue
                url = str(item.get("url", "")).strip()
                param_names = [str(name) for name in item.get("param_names", []) if str(name).strip()]
                _append_candidate(url, param_names)

        deduped: list[dict[str, str]] = []
        seen: set[str] = set()
        for item in candidates:
            marker = json.dumps(item, sort_keys=True, ensure_ascii=False)
            if marker in seen:
                continue
            seen.add(marker)
            deduped.append(item)
        return deduped[:limit]

    def _normalize_sqli_call_input(self, action_input: dict) -> dict:
        normalized = dict(action_input)
        normalized["mode"] = str(normalized.get("mode", "detect") or "detect").lower()
        normalized["level"] = max(self._safe_int(normalized.get("level", 1), default=1), 3)
        normalized["risk"] = max(self._safe_int(normalized.get("risk", 1), default=1), 2)
        if not normalized.get("profile"):
            normalized["profile"] = "deep"
        if "use_common_dict" not in normalized:
            normalized["use_common_dict"] = True

        target = str(normalized.get("target", "") or "")
        parsed = urlparse(target)
        data = str(normalized.get("data", "") or "")
        if parsed.query and not data and "/api" in parsed.path.lower():
            normalized["data"] = parsed.query
            normalized["target"] = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return normalized

    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str):
            text = value.strip()
            if text and text.lstrip("-").isdigit():
                try:
                    return int(text)
                except Exception:
                    return default
        return default

    def _is_focus_related_request(self, action_input: dict) -> bool:
        target = str(action_input.get("target", "") or "")
        path = str(action_input.get("path", "") or "")
        parsed = urlparse(target)
        combined_path = path or (parsed.path or "/")
        url_text = f"{target} {combined_path}".lower()

        if any(marker in url_text for marker in ("select-no-waf", "/api", "id=", "user_id=")):
            return True

        focus_paths = []
        for item in self._sqli_focus_targets(limit=8):
            parsed_item = urlparse(str(item.get("target", "")))
            if parsed_item.path:
                focus_paths.append(parsed_item.path.lower())
        return any(fp and fp in url_text for fp in focus_paths)

    @staticmethod
    def _risk_decision_key(action: str, action_input: dict) -> str:
        if action == "sqli_scan":
            target = str(action_input.get("target", ""))
            parsed = urlparse(target)
            mode = action_input.get("mode", "detect")
            level = action_input.get("level", 1)
            risk = action_input.get("risk", 1)
            return (
                f"{action}:{parsed.scheme}://{parsed.netloc}"
                f"|phase=scan|mode={mode}|level={level}|risk={risk}"
            )
        return f"{action}:{json.dumps(action_input, sort_keys=True, ensure_ascii=False, default=str)}"

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
            query = f"{phase_label} {self.session.target}"
            if self.session.objective:
                query += f" {self.session.objective}"
            return self.rag_retriever(query)
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
        if any(existing.title == finding.title and existing.target == finding.target for existing in self.session.findings):
            return
        self.session.add_finding(finding)
        self.long_mem.save_finding(self.session_id, finding)
        color = "red" if finding.severity in ("critical", "high") else "yellow"
        console.print(f"[bold {color}][+] 发现 {finding.severity.upper()}: {finding.title}[/]")

    def _attack_path_hints(self) -> list[str]:
        hints: list[str] = []
        if any("sql" in finding.title.lower() for finding in self.session.findings):
            hints.append("已出现 SQL 注入线索，优先做枚举/凭据提取，不要扩散到无关 SSRF/JWT/XSS。")
        if self.session.credentials:
            hints.append("已发现凭据或哈希，优先使用 hash_crack 与 login_form 建立后台会话。")
        navigation_frontier = self._navigation_frontier(limit=4)
        if navigation_frontier:
            targets = ", ".join(item.get("path") or item.get("url", "") for item in navigation_frontier[:4])
            hints.append(f"页面已暴露真实站内跳转，优先跟进这些下一跳: {targets}。")
        if self.session.attack_surface.get("api_candidates"):
            hints.append("已从页面提取接口线索，优先围绕这些真实接口测试，而不是通用扫目录。")
        if self.session.attack_surface.get("admin_panels"):
            hints.append("已发现后台入口，优先验证认证与后台功能，而不是重复广义枚举。")
        if self.session.attack_surface.get("upload_paths"):
            hints.append("已发现上传点，建立认证会话后优先测试上传链路。")
        target_and_objective = f"{self.session.target} {self.session.objective}".lower()
        if any(marker in target_and_objective for marker in ("ctf", "challenge", "lab", "training", "sandbox")):
            hints.append("当前目标疑似靶场/挑战环境，优先完成 exploit chain，而不是大范围 OWASP 覆盖。")
        if self.session.objective:
            hints.append(f"显式目标: {self.session.objective}")
        return hints[:5]

    def _validate_tool_input(self, tool_name: str, action_input: dict) -> str | None:
        tool_def = self.tool_def_map.get(tool_name, {})
        schema = tool_def.get("input_schema", {}) if isinstance(tool_def.get("input_schema"), dict) else {}
        required = schema.get("required", []) if isinstance(schema.get("required"), list) else []
        missing = [field for field in required if field not in action_input]
        if missing:
            return f"缺少必填参数: {', '.join(missing)}"

        if tool_name == "extract_jwt_from_response":
            if "headers" not in action_input or "body" not in action_input:
                return "extract_jwt_from_response 需要上一个 HTTP 响应的 headers 和 body。"

        if tool_name == "sqli_scan":
            target = str(action_input.get("target", ""))
            parsed = urlparse(target)
            if not parsed.query and not action_input.get("data"):
                return "sqli_scan 需要带参数的 URL 或 data，当前请求没有可测试参数。"

        if tool_name == "login_form":
            if not action_input.get("username") or not action_input.get("password"):
                return "login_form 需要 username 和 password。"

        if tool_name == "upload_file":
            if not action_input.get("session_alias"):
                return "upload_file 需要已建立的 session_alias。"
            if not action_input.get("file_content") and not action_input.get("file_path"):
                return "upload_file 需要 file_content 或 file_path。"

        return None

    def _ingest_tool_result(self, tool_name: str, action_input: dict, result: Any):
        if tool_name == "extract_jwt_from_response":
            for token in result if isinstance(result, list) else []:
                self.session.remember_attack_surface("jwt_tokens", token)
            return

        if not isinstance(result, dict) or result.get("error"):
            return

        if tool_name in {"nmap_scan", "python_port_scan"}:
            for host in result.get("hosts", []):
                self.session.remember_attack_surface("hosts", {
                    "ip": host.get("ip", ""),
                    "hostname": host.get("hostname", ""),
                    "state": host.get("state", ""),
                })
                for port in host.get("ports", []):
                    self.session.remember_attack_surface("open_ports", {
                        "ip": host.get("ip", ""),
                        "port": port.get("port"),
                        "proto": port.get("proto", ""),
                        "service": port.get("service", ""),
                        "version": port.get("version", ""),
                    })
            return

        if tool_name == "httpx_probe":
            for entry in result.get("results", []):
                self._record_http_summary(entry)
            return

        if tool_name == "http_request":
            self._record_http_summary(result.get("response", {}))
            return

        if tool_name == "page_intel":
            self._record_http_summary(result.get("response", {}))
            page_summary = result.get("page_summary", {})
            for script_url in page_summary.get("script_sources", []):
                self.session.remember_attack_surface("script_sources", script_url)
            for item in page_summary.get("navigation_candidates", []):
                self._remember_navigation_candidate(item)
            for item in page_summary.get("api_candidates", []):
                self.session.remember_attack_surface("api_candidates", item)
                self.session.remember_attack_surface("endpoints", {
                    "url": item.get("url", ""),
                    "status_code": result.get("response", {}).get("status_code", 0),
                    "tags": item.get("tags", []),
                    "title": result.get("response", {}).get("title", ""),
                    "source": item.get("source", "page_intel"),
                })
            for item in page_summary.get("form_actions", []):
                self.session.remember_attack_surface("forms", item)
            for item in page_summary.get("interesting_links", []):
                self.session.remember_attack_surface("endpoints", {
                    "url": item.get("url", ""),
                    "status_code": result.get("response", {}).get("status_code", 0),
                    "tags": item.get("tags", []),
                    "title": result.get("response", {}).get("title", ""),
                    "source": item.get("source", "page_intel"),
                })
            return

        if tool_name == "dirbust":
            for key in ("high_interest", "auth_protected", "redirects"):
                for entry in result.get(key, []):
                    self.session.remember_attack_surface("endpoints", {
                        "url": entry.get("url", ""),
                        "path": entry.get("path", ""),
                        "status_code": entry.get("status", 0),
                        "source": "dirbust",
                    })
            for key, section in (("admin_panels", "admin_panels"), ("login_pages", "login_pages"), ("upload_paths", "upload_paths")):
                for entry in result.get(key, []):
                    self.session.remember_attack_surface(section, entry)
            for entry in result.get("sensitive_exposures", []):
                self._register_sensitive_path_finding(entry)
            return

        if tool_name == "subdomain_enum":
            for item in result.get("subdomains", []):
                self.session.remember_attack_surface("subdomains", item)
            return

        if tool_name == "jwt_analyze":
            token = action_input.get("token", "")
            for issue in result.get("issues", []):
                severity = str(issue.get("severity", "info")).lower()
                if severity == "info":
                    continue
                self.register_finding(Finding(
                    title=f"JWT 风险: {issue.get('type', 'issue')}",
                    severity=severity,
                    target=self.session.target,
                    description=issue.get("detail", ""),
                    payload=token[:120],
                    reproduction=issue.get("poc", ""),
                    remediation=issue.get("recommendation", "修复 JWT 签名、算法与敏感字段配置问题。"),
                    cvss={"critical": 9.1, "high": 8.0, "medium": 5.5, "low": 3.1}.get(severity, 0.0),
                ))
            return

        if tool_name == "hash_crack" and result.get("matched"):
            self.session.add_credential({
                "type": "cracked_hash",
                "hash": action_input.get("hash_value", ""),
                "plaintext": result.get("plaintext", ""),
                "algorithm": result.get("algorithm", ""),
            })
            return

        if tool_name == "login_form":
            self._record_http_summary(result.get("response", {}))
            if result.get("success"):
                self.session.remember_authenticated_session(result.get("session_alias", "default"), {
                    "login_url": result.get("login_url", ""),
                    "stored_cookies": result.get("stored_cookies", {}),
                })
            return

        if tool_name == "upload_file":
            self._record_http_summary(result.get("response", {}))
            for url in result.get("verified_urls", []):
                self.session.remember_attack_surface("upload_paths", {"url": url, "verified": True})
            if result.get("success"):
                self.session.exploit_results.append({
                    "type": "upload_attempt",
                    "upload_url": result.get("upload_url", ""),
                    "verified_urls": result.get("verified_urls", []),
                    "filename": result.get("filename", ""),
                })
            return

        if tool_name in {"nuclei_scan", "python_vuln_check"}:
            for item in result.get("findings", []):
                severity = str(item.get("severity", "info")).lower()
                self.register_finding(Finding(
                    title=item.get("name") or item.get("template_id", "漏洞发现"),
                    severity=severity,
                    target=item.get("matched_at") or item.get("target") or self.session.target,
                    description=item.get("description") or item.get("evidence", ""),
                    payload=item.get("curl_command", ""),
                    reproduction=item.get("curl_command", ""),
                    remediation="参考模板或组件官方修复建议进行修复。",
                    cvss=float(item.get("cvss_score", 0.0) or 0.0),
                ))
            return

        if tool_name == "onedaypoc_scan":
            for item in result.get("findings", []):
                severity = str(item.get("severity", "high")).lower()
                self.register_finding(Finding(
                    title=f"{item.get('cve_id', 'CVE')} {item.get('name', '')}".strip(),
                    severity=severity,
                    target=item.get("target", self.session.target),
                    description=item.get("evidence", ""),
                    remediation=item.get("remediation", ""),
                    cvss=float(item.get("cvss", 0.0) or 0.0),
                ))
            return

        if tool_name == "sqli_scan":
            for candidate in result.get("credential_candidates", []):
                self.session.add_credential({
                    "type": "database_secret",
                    "db": candidate.get("db", ""),
                    "table": candidate.get("table", ""),
                    "username": candidate.get("username", ""),
                    "secret": candidate.get("secret", ""),
                    "secret_field": candidate.get("secret_field", ""),
                })
            for hash_value in result.get("hash_candidates", []):
                self.session.add_credential({"type": "hash", "hash": hash_value})
            if result.get("vulnerable"):
                description_parts = []
                if result.get("heuristic", {}).get("indicators"):
                    indicator = result["heuristic"]["indicators"][0]
                    description_parts.append(f"启发式命中: {indicator.get('type', '')} / 参数 {indicator.get('param', '')}")
                if result.get("credential_candidates"):
                    description_parts.append(f"已提取到 {len(result['credential_candidates'])} 组凭据线索")
                if result.get("hash_candidates"):
                    description_parts.append(f"已提取到 {len(result['hash_candidates'])} 个疑似密码哈希")
                self.register_finding(Finding(
                    title="SQL 注入",
                    severity="critical",
                    target=action_input.get("target", self.session.target),
                    description="；".join(description_parts) or "检测到 SQL 注入迹象。",
                    payload=str(result.get("sqlmap", {}).get("injections", ""))[:300],
                    remediation="使用参数化查询，避免拼接用户输入。",
                    cvss=9.8,
                ))
            return

        if tool_name == "xss_scan":
            for item in result.get("reflected_xss", []):
                if item.get("reflected") or item.get("in_xss_context"):
                    self.register_finding(Finding(
                        title=f"反射型 XSS: {item.get('param', 'unknown')}",
                        severity="high",
                        target=item.get("url", self.session.target),
                        description="参数值被回显到可执行上下文，存在 XSS 风险。",
                        payload=item.get("probe", ""),
                        remediation="对输出做上下文敏感编码，并补充 CSP。",
                        cvss=7.5,
                    ))
            for item in result.get("dom_xss", []):
                self.register_finding(Finding(
                    title="DOM XSS",
                    severity="high",
                    target=item.get("url", self.session.target),
                    description="客户端脚本处理用户输入时触发 DOM XSS。",
                    payload=item.get("probe", ""),
                    remediation="避免不安全 DOM API，必要时使用 DOMPurify。",
                    cvss=7.5,
                ))
            return

        if tool_name == "ssrf_scan":
            for item in result.get("findings", []):
                self.register_finding(Finding(
                    title=f"SSRF: {item.get('param', 'unknown')}",
                    severity="high",
                    target=item.get("url", self.session.target),
                    description=f"检测到 {item.get('type', 'ssrf')} 信号。",
                    payload=item.get("probe", ""),
                    remediation="对目标地址实施白名单与内网地址阻断。",
                    cvss=8.0,
                ))

    def _record_http_summary(self, entry: dict[str, Any]):
        if not isinstance(entry, dict) or entry.get("error"):
            return
        url = entry.get("url")
        if not url:
            return

        self.session.remember_attack_surface("web_services", {
            "url": url,
            "status_code": entry.get("status_code", 0),
            "title": entry.get("title", ""),
            "server": entry.get("server", ""),
            "content_type": entry.get("content_type", ""),
        })
        self.session.remember_attack_surface("endpoints", {
            "url": url,
            "status_code": entry.get("status_code", 0),
            "tags": entry.get("endpoint_tags", []),
            "title": entry.get("title", ""),
        })

        for tech in (entry.get("server", ""), entry.get("x_powered_by", "")):
            tech = str(tech).strip()
            if tech:
                self.session.remember_attack_surface("technologies", tech)

        for form in entry.get("forms", []):
            self.session.remember_attack_surface("forms", {"url": url, **form})
        for form in entry.get("login_forms", []):
            self.session.remember_attack_surface("login_pages", {"url": url, **form})
        for form in entry.get("upload_forms", []):
            self.session.remember_attack_surface("upload_paths", {"url": url, **form})
        for item in entry.get("navigation_links", []):
            self._remember_navigation_candidate(item, source="http_response", status_code=entry.get("status_code", 0), title=entry.get("title", ""))
        for token in entry.get("jwt_tokens", []):
            self.session.remember_attack_surface("jwt_tokens", token)
        for script_url in entry.get("script_sources", []):
            self.session.remember_attack_surface("script_sources", script_url)
        if "admin" in entry.get("endpoint_tags", []):
            self.session.remember_attack_surface("admin_panels", {"url": url, "status_code": entry.get("status_code", 0)})

    def _remember_navigation_candidate(
        self,
        item: dict[str, Any],
        source: str = "",
        status_code: int = 0,
        title: str = "",
    ):
        if not isinstance(item, dict):
            return
        url = str(item.get("url", "")).strip()
        if not url:
            return
        parsed = urlparse(url)
        param_names = item.get("param_names")
        if not isinstance(param_names, list):
            param_names = [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
        candidate = {
            "url": url,
            "path": item.get("path") or (parsed.path or "/"),
            "score": int(item.get("score", 0) or 0),
            "reason": item.get("reason", ""),
            "param_names": sorted(str(name) for name in param_names if str(name).strip()),
            "source": item.get("source") or source or "navigation_link",
            "status_code": status_code,
            "title": title or item.get("title", ""),
        }
        self.session.remember_attack_surface("navigation_candidates", candidate)

    def _http_request_input_from_url(self, url: str) -> dict[str, Any] | None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return None

        target_parsed = urlparse(self.session.target)
        if target_parsed.netloc and parsed.netloc != target_parsed.netloc:
            return None

        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        return {
            "target": f"{parsed.scheme}://{parsed.netloc}",
            "path": path,
            "method": "GET",
            "capture_body": True,
            "follow_redirects": True,
        }

    def _navigation_frontier(self, limit: int = 6, include_visited: bool = False) -> list[dict[str, Any]]:
        visited_urls = {
            str(item.get("url", "")).strip()
            for item in self.session.attack_surface.get("web_services", [])
            if isinstance(item, dict) and item.get("url")
        }
        frontier: list[dict[str, Any]] = []
        for item in self.session.attack_surface.get("navigation_candidates", []):
            if not isinstance(item, dict):
                continue
            url = str(item.get("url", "")).strip()
            if not url:
                continue
            if not include_visited and url in visited_urls:
                continue
            frontier.append(item)

        frontier.sort(
            key=lambda item: (
                -int(item.get("score", 0) or 0),
                "id" not in {str(name).lower() for name in item.get("param_names", [])},
                item.get("path", ""),
                item.get("url", ""),
            )
        )
        return frontier[:limit]

    def _should_defer_broad_scan(self, tool_name: str, action_input: dict) -> str:
        if self.session.phase not in {Phase.RECON, Phase.SCAN}:
            return ""

        if self._is_explicit_sqli_focus_mode():
            if tool_name in {
                "dirbust", "subdomain_enum", "nmap_scan", "httpx_probe",
                "nuclei_scan", "onedaypoc_scan", "python_vuln_check",
                "ssrf_scan", "xss_scan", "jwt_analyze", "extract_jwt_from_response",
            }:
                return "SQLi 聚焦模式：已确认注入链路线索，暂缓无关扫描工具。"

        navigation_frontier = self._navigation_frontier(limit=3)
        if not navigation_frontier:
            return ""

        if tool_name == "subdomain_enum":
            return "已发现站内真实页面跳转，优先跟进页面导航线索而不是继续子域枚举。"

        if tool_name == "dirbust":
            path = str(action_input.get("path", "") or "/")
            if path in {"", "/"}:
                return "已发现站内真实页面跳转，优先跟进这些页面，暂缓继续对根路径做目录爆破。"

        if tool_name == "httpx_probe":
            target = str(action_input.get("target", "") or "")
            parsed = urlparse(target) if target else None
            path = str(action_input.get("path", "") or (parsed.path if parsed and parsed.path else "/"))
            paths = action_input.get("paths")
            if not paths and path in {"", "/"}:
                return "已发现站内真实页面跳转，优先跟进这些页面，暂缓继续重复基础探测。"

        return ""

    @staticmethod
    def _tool_display_name(tool_name: str, action_input: dict) -> str:
        if not isinstance(action_input, dict):
            return tool_name

        target = str(action_input.get("target", "") or "")
        parsed = urlparse(target) if target else None
        path = action_input.get("path") or (parsed.path if parsed and parsed.path else "")
        path = path or "/"
        query_params = sorted(dict(parse_qsl(parsed.query, keep_blank_values=True)).keys()) if parsed and parsed.query else []
        path_preview = path
        if query_params:
            path_preview += f"?{','.join(query_params[:4])}"

        if tool_name in {"http_request", "page_intel"}:
            method = str(action_input.get("method", "GET")).upper()
            return f"{tool_name}({method} {path_preview})"
        if tool_name == "httpx_probe":
            extra = len(action_input.get("paths", []) or [])
            return f"httpx_probe({path_preview}, +{extra} paths)" if extra else f"httpx_probe({path_preview})"
        if tool_name == "sqli_scan":
            mode = str(action_input.get("mode", "detect"))
            return f"sqli_scan({mode} {path_preview})"
        if tool_name == "login_form":
            login_path = action_input.get("login_path") or path
            return f"login_form({login_path or '/'})"
        if tool_name == "upload_file":
            upload_path = action_input.get("upload_path") or path
            return f"upload_file({upload_path or '/'})"
        if tool_name == "dirbust":
            return f"dirbust({path})"
        return tool_name

    @staticmethod
    def _tool_cache_key(tool_name: str, action_input: dict) -> str:
        normalized = dict(action_input)
        if tool_name in {"http_request", "page_intel"}:
            normalized["method"] = str(action_input.get("method", "GET")).upper()
        if tool_name in {"ssrf_scan", "xss_scan"} and "params" in normalized:
            params = normalized.get("params")
            if isinstance(params, list):
                normalized["params"] = sorted(str(item) for item in params)
            elif isinstance(params, str):
                normalized["params"] = sorted(part.strip() for part in params.split(",") if part.strip())
        if tool_name == "httpx_probe" and "paths" in normalized:
            paths = normalized.get("paths")
            if isinstance(paths, list):
                normalized["paths"] = sorted(str(item) for item in paths)
        return f"{tool_name}:{json.dumps(normalized, sort_keys=True, ensure_ascii=False, default=str)}"

    @staticmethod
    def _phase_repeat_key(tool_name: str, action_input: dict) -> str:
        target = str(action_input.get("target", "") or "")
        parsed = urlparse(target) if target else None
        path = action_input.get("path") or (parsed.path if parsed and parsed.path else "/")
        netloc = parsed.netloc if parsed else ""
        scheme = parsed.scheme if parsed else ""

        if tool_name in {"ssrf_scan", "xss_scan", "httpx_probe", "page_intel", "dirbust"}:
            return f"{tool_name}:{scheme}://{netloc}{path}"
        if tool_name == "subdomain_enum":
            return f"subdomain_enum:{scheme}://{netloc or target}"
        if tool_name == "http_request":
            method = str(action_input.get("method", "GET")).upper()
            params = action_input.get("params")
            form = action_input.get("form")
            json_body = action_input.get("json_body")
            data = str(action_input.get("data", "") or "")[:200]
            payload_sig = json.dumps(
                {"params": params, "form": form, "json_body": json_body, "data": data},
                sort_keys=True,
                ensure_ascii=False,
                default=str,
            )
            return f"http_request:{method}:{scheme}://{netloc}{path}|{payload_sig}"
        if tool_name == "sqli_scan":
            mode = str(action_input.get("mode", "detect"))
            data = str(action_input.get("data", "") or "")[:200]
            profile = str(action_input.get("profile", "") or "")
            return f"sqli_scan:{mode}:{scheme}://{netloc}{path}|profile={profile}|data={data}"
        return ""

    @staticmethod
    def _phase_repeat_threshold(tool_name: str) -> int:
        thresholds = {
            "page_intel": 2,
            "httpx_probe": 2,
            "dirbust": 2,
            "subdomain_enum": 1,
            "ssrf_scan": 2,
            "xss_scan": 2,
            "http_request": 8,
            "sqli_scan": 6,
        }
        return thresholds.get(tool_name, 4)

    def _register_sensitive_path_finding(self, entry: dict[str, Any]):
        path = str(entry.get("path", "")).lower()
        severity = "medium"
        if any(marker in path for marker in (".env", ".git", "backup", ".sql", "dump")):
            severity = "critical"
        elif any(marker in path for marker in ("config", "adminer", "phpmyadmin")):
            severity = "high"

        self.register_finding(Finding(
            title=f"敏感资源暴露: {entry.get('path', '')}",
            severity=severity,
            target=entry.get("url", self.session.target),
            description=f"敏感路径对外可访问，状态码 {entry.get('status', 0)}。",
            remediation="限制敏感文件访问，移除备份文件与调试资源。",
            cvss={"critical": 9.0, "high": 7.5, "medium": 5.0}.get(severity, 0.0),
        ))
