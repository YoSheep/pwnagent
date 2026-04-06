"""
Brain — LLM 调用 + 思维链流式输出
使用 Anthropic Claude 原生 tool_use，支持单次返回多个工具调用。
"""
import json
from dataclasses import dataclass, field
from typing import Any

import anthropic
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

console = Console()

SYSTEM_PROMPT = """你是 PwnAgent，一个专业的渗透测试 AI 助手。
你只对已获得书面授权的目标执行测试操作。

行为准则：
- 每次调用工具前，必须在文本中写出推理过程（为什么选这个操作、预期结果、风险评估）
- 高风险操作必须在推理中明确说明
- 永远不对未授权目标执行操作
- 思考方式要像一个有 10 年经验的渗透测试工程师
- 优先使用非破坏性、非干扰性的探测手段
- 发现漏洞后先记录再验证，不要盲目利用
- 当前阶段所有操作完成后，调用 phase_finish 工具
- 如果多个工具之间没有依赖关系（比如 nmap_scan 和 httpx_probe），可以在同一次回复中同时调用它们"""


@dataclass
class ToolCall:
    """一次工具调用请求。"""
    tool_use_id: str
    name: str
    input: dict = field(default_factory=dict)


@dataclass
class ThinkResult:
    """LLM 单次推理的完整结果。"""
    thought: str = ""                             # 推理文本
    tool_calls: list[ToolCall] = field(default_factory=list)  # 可能多个
    raw_content_blocks: list[dict] = field(default_factory=list)  # 原始 content blocks

    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0

    @property
    def is_phase_finish(self) -> bool:
        return any(tc.name == "phase_finish" for tc in self.tool_calls)


class Brain:
    def __init__(self, model: str = "claude-opus-4-5", verbose: bool = False):
        self.client = anthropic.Anthropic()
        self.model = model
        self.verbose = verbose

    def think(
        self,
        messages: list[dict],
        tools: list[dict],
        phase: str,
        extra_context: str = "",
    ) -> ThinkResult:
        """
        调用 LLM，返回包含零个或多个工具调用的结果。
        """
        if extra_context:
            messages = self._inject_context(messages, extra_context)

        all_tools = list(tools)
        if not any(t.get("name") == "phase_finish" for t in all_tools):
            all_tools.append({
                "name": "phase_finish",
                "description": "当前阶段所有操作完成时调用此工具，结束当前阶段。",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "summary": {"type": "string", "description": "本阶段工作总结"},
                    },
                    "required": ["summary"],
                },
            })

        try:
            return self._stream_and_parse(messages, all_tools, phase)
        except anthropic.APIError as e:
            console.print(f"[red]API 错误: {e}[/red]")
            return ThinkResult(
                thought=f"API 调用失败: {e}",
                tool_calls=[ToolCall(
                    tool_use_id="error_fallback",
                    name="phase_finish",
                    input={"summary": f"API 错误: {e}"},
                )],
            )

    # ------------------------------------------------------------------
    # 流式调用（支持多 tool_use blocks）
    # ------------------------------------------------------------------

    def _stream_and_parse(
        self, messages: list[dict], tools: list[dict], phase: str
    ) -> ThinkResult:
        text_buffer = ""
        # 追踪多个 tool_use blocks
        current_tool_id = ""
        current_tool_name = ""
        current_tool_json = ""
        tool_calls: list[ToolCall] = []
        content_blocks: list[dict] = []

        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": 4096,
            "system": SYSTEM_PROMPT,
            "messages": messages,
            "tools": tools,
        }

        with self.client.messages.stream(**kwargs) as stream:
            if self.verbose:
                with Live(console=console, refresh_per_second=15) as live:
                    for event in stream:
                        self._handle_event(
                            event, text_buffer_ref := [text_buffer],
                            current_ref := [current_tool_id, current_tool_name, current_tool_json],
                            tool_calls, content_blocks, live, phase,
                        )
                        text_buffer = text_buffer_ref[0]
                        current_tool_id, current_tool_name, current_tool_json = current_ref
            else:
                for event in stream:
                    self._handle_event(
                        event, text_buffer_ref := [text_buffer],
                        current_ref := [current_tool_id, current_tool_name, current_tool_json],
                        tool_calls, content_blocks, None, phase,
                    )
                    text_buffer = text_buffer_ref[0]
                    current_tool_id, current_tool_name, current_tool_json = current_ref

        # 非 verbose 模式显示思考摘要
        if not self.verbose and text_buffer.strip():
            preview = text_buffer.strip()[:300]
            if len(text_buffer.strip()) > 300:
                preview += "…"
            console.print(Panel(
                Text(preview, style="dim"),
                title=f"[bold purple]Agent 思考 — {phase}[/bold purple]",
                border_style="purple",
            ))

        # 显示并行工具调用数量
        if len(tool_calls) > 1:
            names = ", ".join(tc.name for tc in tool_calls)
            console.print(f"[cyan]  → 并行调用 {len(tool_calls)} 个工具: {names}[/cyan]")

        return ThinkResult(
            thought=text_buffer.strip(),
            tool_calls=tool_calls,
            raw_content_blocks=content_blocks,
        )

    def _handle_event(
        self, event,
        text_ref: list,      # [text_buffer]
        current_ref: list,   # [tool_id, tool_name, tool_json]
        tool_calls: list[ToolCall],
        content_blocks: list[dict],
        live, phase,
    ):
        event_type = getattr(event, "type", "")

        if event_type == "content_block_start":
            block = event.content_block
            if block.type == "text":
                content_blocks.append({"type": "text", "text": ""})
            elif block.type == "tool_use":
                current_ref[0] = block.id
                current_ref[1] = block.name
                current_ref[2] = ""
                content_blocks.append({
                    "type": "tool_use",
                    "id": block.id,
                    "name": block.name,
                    "input": {},
                })

        elif event_type == "content_block_delta":
            delta = event.delta
            if hasattr(delta, "text"):
                text_ref[0] += delta.text
                # 更新最后一个 text block
                for b in reversed(content_blocks):
                    if b["type"] == "text":
                        b["text"] += delta.text
                        break
                if live:
                    live.update(Panel(
                        Text(text_ref[0], style="dim"),
                        title=f"[bold purple]Agent 思考 — {phase}[/bold purple]",
                        border_style="purple",
                    ))
            elif hasattr(delta, "partial_json"):
                current_ref[2] += delta.partial_json

        elif event_type == "content_block_stop":
            # 如果当前有 tool_use 在构建，提交它
            if current_ref[1]:  # tool_name 非空
                try:
                    tool_input = json.loads(current_ref[2]) if current_ref[2] else {}
                except json.JSONDecodeError:
                    tool_input = {"raw": current_ref[2]}

                tool_calls.append(ToolCall(
                    tool_use_id=current_ref[0],
                    name=current_ref[1],
                    input=tool_input,
                ))
                # 更新 content_blocks 中对应的 tool_use
                for b in reversed(content_blocks):
                    if b["type"] == "tool_use" and b["id"] == current_ref[0]:
                        b["input"] = tool_input
                        break

                # 重置
                current_ref[0] = ""
                current_ref[1] = ""
                current_ref[2] = ""

    # ------------------------------------------------------------------
    # 消息构建（支持多工具）
    # ------------------------------------------------------------------

    @staticmethod
    def build_assistant_message(result: ThinkResult) -> dict:
        """从 ThinkResult 构建 assistant 消息。"""
        blocks = []
        if result.thought:
            blocks.append({"type": "text", "text": result.thought})
        for tc in result.tool_calls:
            blocks.append({
                "type": "tool_use",
                "id": tc.tool_use_id,
                "name": tc.name,
                "input": tc.input,
            })
        return {"role": "assistant", "content": blocks}

    @staticmethod
    def build_tool_results_message(results: list[tuple[str, Any]]) -> dict:
        """
        构建包含多个 tool_result 的 user 消息。
        :param results: [(tool_use_id, result_data), ...]
        """
        blocks = []
        for tool_use_id, result_data in results:
            content = (
                json.dumps(result_data, ensure_ascii=False, default=str)
                if not isinstance(result_data, str) else result_data
            )
            blocks.append({
                "type": "tool_result",
                "tool_use_id": tool_use_id,
                "content": content,
            })
        return {"role": "user", "content": blocks}

    @staticmethod
    def _inject_context(messages: list[dict], extra_context: str) -> list[dict]:
        messages = list(messages)
        last = messages[-1]
        if isinstance(last.get("content"), str):
            messages[-1] = {**last, "content": last["content"] + f"\n\n{extra_context}"}
        elif isinstance(last.get("content"), list):
            messages[-1] = {
                **last,
                "content": list(last["content"]) + [{"type": "text", "text": extra_context}],
            }
        return messages
