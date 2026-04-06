"""
Brain — LLM 调用 + 思维链输出
支持 Anthropic 兼容 tool_use 与 OpenAI 兼容 tool_calls。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from core.llm import LLMConfigurationError, get_runtime

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
    thought: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw_content_blocks: list[dict] = field(default_factory=list)

    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0

    @property
    def is_phase_finish(self) -> bool:
        return any(tc.name == "phase_finish" for tc in self.tool_calls)


class Brain:
    def __init__(self, model: str | None = None, verbose: bool = False, provider_name: str | None = None):
        self.runtime = get_runtime("brain", provider_name)
        self.model = model or self.runtime.model
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

        all_tools = self._with_phase_finish(tools)

        try:
            if self.runtime.api_style == "anthropic":
                return self._stream_and_parse_anthropic(messages, all_tools, phase)
            return self._chat_and_parse_openai(messages, all_tools, phase)
        except LLMConfigurationError:
            raise
        except Exception as e:
            console.print(f"[red]LLM 调用失败: {e}[/red]")
            return ThinkResult(
                thought=f"LLM 调用失败: {e}",
                tool_calls=[ToolCall(
                    tool_use_id="error_fallback",
                    name="phase_finish",
                    input={"summary": f"LLM 调用失败: {e}"},
                )],
            )

    @staticmethod
    def _with_phase_finish(tools: list[dict]) -> list[dict]:
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
        return all_tools

    # ------------------------------------------------------------------
    # Anthropic 兼容 tool_use
    # ------------------------------------------------------------------

    def _stream_and_parse_anthropic(
        self, messages: list[dict], tools: list[dict], phase: str
    ) -> ThinkResult:
        text_buffer = ""
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

        with self.runtime.client.messages.stream(**kwargs) as stream:
            if self.verbose:
                with Live(console=console, refresh_per_second=15) as live:
                    for event in stream:
                        self._handle_anthropic_event(
                            event,
                            text_buffer_ref := [text_buffer],
                            current_ref := [current_tool_id, current_tool_name, current_tool_json],
                            tool_calls,
                            content_blocks,
                            live,
                            phase,
                        )
                        text_buffer = text_buffer_ref[0]
                        current_tool_id, current_tool_name, current_tool_json = current_ref
            else:
                for event in stream:
                    self._handle_anthropic_event(
                        event,
                        text_buffer_ref := [text_buffer],
                        current_ref := [current_tool_id, current_tool_name, current_tool_json],
                        tool_calls,
                        content_blocks,
                        None,
                        phase,
                    )
                    text_buffer = text_buffer_ref[0]
                    current_tool_id, current_tool_name, current_tool_json = current_ref

        self._render_thought(text_buffer, phase)
        self._render_parallel_summary(tool_calls)

        return ThinkResult(
            thought=text_buffer.strip(),
            tool_calls=tool_calls,
            raw_content_blocks=content_blocks,
        )

    def _handle_anthropic_event(
        self,
        event: Any,
        text_ref: list,
        current_ref: list,
        tool_calls: list[ToolCall],
        content_blocks: list[dict],
        live: Live | None,
        phase: str,
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
                for block in reversed(content_blocks):
                    if block["type"] == "text":
                        block["text"] += delta.text
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
            if current_ref[1]:
                try:
                    tool_input = json.loads(current_ref[2]) if current_ref[2] else {}
                except json.JSONDecodeError:
                    tool_input = {"raw": current_ref[2]}

                tool_calls.append(ToolCall(
                    tool_use_id=current_ref[0],
                    name=current_ref[1],
                    input=tool_input,
                ))

                for block in reversed(content_blocks):
                    if block["type"] == "tool_use" and block["id"] == current_ref[0]:
                        block["input"] = tool_input
                        break

                current_ref[0] = ""
                current_ref[1] = ""
                current_ref[2] = ""

    # ------------------------------------------------------------------
    # OpenAI 兼容 tool_calls
    # ------------------------------------------------------------------

    def _chat_and_parse_openai(
        self, messages: list[dict], tools: list[dict], phase: str
    ) -> ThinkResult:
        response = self.runtime.client.chat.completions.create(
            model=self.model,
            max_completion_tokens=4096,
            tool_choice="auto",
            messages=self._to_openai_messages(messages),
            tools=self._to_openai_tools(tools),
        )

        message = response.choices[0].message
        thought = message.content or ""
        tool_calls: list[ToolCall] = []
        raw_blocks: list[dict] = []

        if thought:
            raw_blocks.append({"type": "text", "text": thought})

        for tool_call in message.tool_calls or []:
            arguments = getattr(tool_call.function, "arguments", "") or ""
            try:
                parsed_args = json.loads(arguments) if arguments else {}
            except json.JSONDecodeError:
                parsed_args = {"raw": arguments}

            tool_calls.append(ToolCall(
                tool_use_id=tool_call.id,
                name=tool_call.function.name,
                input=parsed_args,
            ))
            raw_blocks.append({
                "type": "tool_use",
                "id": tool_call.id,
                "name": tool_call.function.name,
                "input": parsed_args,
            })

        self._render_thought(thought, phase)
        self._render_parallel_summary(tool_calls)

        return ThinkResult(
            thought=thought.strip(),
            tool_calls=tool_calls,
            raw_content_blocks=raw_blocks,
        )

    @staticmethod
    def _to_openai_tools(tools: list[dict]) -> list[dict]:
        result = []
        for tool in tools:
            result.append({
                "type": "function",
                "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": tool.get("input_schema", {"type": "object", "properties": {}}),
                },
            })
        return result

    @staticmethod
    def _to_openai_messages(messages: list[dict]) -> list[dict]:
        out: list[dict] = [{"role": "system", "content": SYSTEM_PROMPT}]

        for message in messages:
            role = message.get("role")
            content = message.get("content")

            if isinstance(content, str):
                out.append({"role": role, "content": content})
                continue

            if not isinstance(content, list):
                continue

            if role == "assistant":
                text_parts: list[str] = []
                tool_calls: list[dict] = []
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "text" and block.get("text"):
                        text_parts.append(block["text"])
                    elif block.get("type") == "tool_use":
                        tool_calls.append({
                            "id": block["id"],
                            "type": "function",
                            "function": {
                                "name": block["name"],
                                "arguments": json.dumps(block.get("input", {}), ensure_ascii=False),
                            },
                        })

                assistant_msg: dict[str, Any] = {
                    "role": "assistant",
                    "content": "\n".join(text_parts) if text_parts else "",
                }
                if tool_calls:
                    assistant_msg["tool_calls"] = tool_calls
                out.append(assistant_msg)
                continue

            if role == "user":
                pending_user_text: list[str] = []
                for block in content:
                    if not isinstance(block, dict):
                        continue
                    if block.get("type") == "text" and block.get("text"):
                        pending_user_text.append(block["text"])
                        continue
                    if block.get("type") == "tool_result":
                        if pending_user_text:
                            out.append({"role": "user", "content": "\n".join(pending_user_text)})
                            pending_user_text = []
                        out.append({
                            "role": "tool",
                            "tool_call_id": block["tool_use_id"],
                            "content": block.get("content", ""),
                        })
                if pending_user_text:
                    out.append({"role": "user", "content": "\n".join(pending_user_text)})

        return out

    # ------------------------------------------------------------------
    # 消息构建（内部统一仍使用 Anthropic 风格 content blocks）
    # ------------------------------------------------------------------

    @staticmethod
    def build_assistant_message(result: ThinkResult) -> dict:
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
        if not messages:
            return [{"role": "user", "content": extra_context}]

        last = messages[-1]
        if isinstance(last.get("content"), str):
            messages[-1] = {**last, "content": last["content"] + f"\n\n{extra_context}"}
        elif isinstance(last.get("content"), list):
            messages[-1] = {
                **last,
                "content": list(last["content"]) + [{"type": "text", "text": extra_context}],
            }
        return messages

    def _render_thought(self, text_buffer: str, phase: str):
        if not text_buffer.strip():
            return
        preview = text_buffer.strip() if self.verbose else text_buffer.strip()[:300]
        if not self.verbose and len(text_buffer.strip()) > 300:
            preview += "…"
        console.print(Panel(
            Text(preview, style="dim"),
            title=f"[bold purple]Agent 思考 — {phase}[/bold purple]",
            border_style="purple",
        ))

    @staticmethod
    def _render_parallel_summary(tool_calls: list[ToolCall]):
        if len(tool_calls) > 1:
            names = ", ".join(tc.name for tc in tool_calls)
            console.print(f"[cyan]  → 并行调用 {len(tool_calls)} 个工具: {names}[/cyan]")
