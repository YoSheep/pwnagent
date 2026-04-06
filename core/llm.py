"""
统一 LLM Provider 适配层。

支持两类协议：
1. anthropic 兼容接口（Anthropic 官方、MiniMax Anthropic 兼容网关）
2. openai 兼容接口（OpenAI 及大量兼容厂商）
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Iterator

from openai import OpenAI

from core.config import get_config

try:
    import anthropic
except ImportError:  # pragma: no cover - 运行时按需安装
    anthropic = None


DEFAULT_TIMEOUT = 120.0
DEFAULT_PROVIDER = "anthropic"
DEFAULT_ANTHROPIC_MODELS = {
    "brain": "claude-opus-4-5",
    "planner": "claude-sonnet-4-20250514",
    "knowledge": "claude-sonnet-4-20250514",
    "exploit": "claude-opus-4-5",
    "post_exploit": "claude-opus-4-5",
}


class LLMConfigurationError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProviderSettings:
    name: str
    api_style: str
    api_key: str = ""
    api_key_env: str = ""
    api_key_optional: bool = False
    base_url: str = ""
    timeout: float = DEFAULT_TIMEOUT
    models: dict[str, str] = field(default_factory=dict)
    default_headers: dict[str, str] = field(default_factory=dict)

    def model_for(self, role: str) -> str:
        if role in self.models and self.models[role]:
            return self.models[role]
        if "default" in self.models and self.models["default"]:
            return self.models["default"]
        if self.api_style == "anthropic":
            return DEFAULT_ANTHROPIC_MODELS.get(role, DEFAULT_ANTHROPIC_MODELS["brain"])
        raise LLMConfigurationError(
            f"Provider '{self.name}' 未为角色 '{role}' 配置模型。"
        )

    def resolved_api_key(self) -> str | None:
        if self.api_key:
            return self.api_key
        if self.api_key_env:
            value = os.environ.get(self.api_key_env, "").strip()
            if value:
                return value
        if self.api_key_optional:
            return None
        return None


@dataclass
class LLMRuntime:
    role: str
    provider: ProviderSettings
    model: str
    _client: Any = None

    @property
    def api_style(self) -> str:
        return self.provider.api_style

    @property
    def timeout(self) -> float:
        return self.provider.timeout

    @property
    def client(self) -> Any:
        if self._client is None:
            self._client = _build_client(self.provider)
        return self._client


def _normalize_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _provider_section(provider_name: str) -> dict[str, Any]:
    cfg = get_config()
    llm_cfg = _normalize_dict(cfg.get("llm"))
    providers = _normalize_dict(llm_cfg.get("providers"))
    return _normalize_dict(providers.get(provider_name))


def get_active_provider_name(explicit: str | None = None) -> str:
    if explicit:
        return explicit
    env_provider = os.environ.get("PWNAGENT_LLM_PROVIDER", "").strip()
    if env_provider:
        return env_provider
    cfg = get_config()
    llm_cfg = _normalize_dict(cfg.get("llm"))
    return llm_cfg.get("provider", DEFAULT_PROVIDER)


def get_provider_settings(provider_name: str | None = None) -> ProviderSettings:
    selected = get_active_provider_name(provider_name)
    cfg = get_config()
    llm_cfg = _normalize_dict(cfg.get("llm"))
    provider_cfg = _provider_section(selected)
    legacy_agent_cfg = _normalize_dict(cfg.get("agent"))

    models = _normalize_dict(provider_cfg.get("models"))
    if selected == "anthropic" and legacy_agent_cfg.get("model") and "brain" not in models:
        models["brain"] = legacy_agent_cfg["model"]

    api_style = provider_cfg.get("api_style", "anthropic" if selected == "anthropic" else "openai")
    timeout = float(provider_cfg.get("timeout", llm_cfg.get("timeout", DEFAULT_TIMEOUT)))

    return ProviderSettings(
        name=selected,
        api_style=api_style,
        api_key=str(provider_cfg.get("api_key", "") or ""),
        api_key_env=str(provider_cfg.get("api_key_env", "") or ""),
        api_key_optional=bool(provider_cfg.get("api_key_optional", False)),
        base_url=str(provider_cfg.get("base_url", "") or ""),
        timeout=timeout,
        models={k: str(v) for k, v in models.items() if v},
        default_headers={k: str(v) for k, v in _normalize_dict(provider_cfg.get("default_headers")).items()},
    )


@lru_cache(maxsize=16)
def get_runtime(role: str, provider_name: str | None = None) -> LLMRuntime:
    provider = get_provider_settings(provider_name)
    return LLMRuntime(
        role=role,
        provider=provider,
        model=provider.model_for(role),
    )


def _build_client(provider: ProviderSettings) -> Any:
    api_key = provider.resolved_api_key()
    if provider.api_style == "anthropic":
        if anthropic is None:
            raise LLMConfigurationError(
                "当前环境未安装 anthropic 包，无法使用 Anthropic/MiniMax(Anthropic 兼容) provider。"
            )
        if not api_key:
            env_name = provider.api_key_env or "对应 provider 的 API key"
            raise LLMConfigurationError(
                f"Provider '{provider.name}' 缺少 API key，请设置环境变量 {env_name} 或在 config.yaml 中填写 api_key。"
            )
        kwargs: dict[str, Any] = {
            "api_key": api_key,
            "timeout": provider.timeout,
        }
        if provider.base_url:
            kwargs["base_url"] = provider.base_url
        return anthropic.Anthropic(**kwargs)

    if provider.api_style == "openai":
        if not api_key and not provider.api_key_optional:
            env_name = provider.api_key_env or "对应 provider 的 API key"
            raise LLMConfigurationError(
                f"Provider '{provider.name}' 缺少 API key，请设置环境变量 {env_name} 或在 config.yaml 中填写 api_key。"
            )
        if provider.name != "openai" and not provider.base_url:
            raise LLMConfigurationError(
                f"Provider '{provider.name}' 采用 OpenAI 兼容接口，但尚未配置 base_url。"
            )
        effective_key = api_key or "EMPTY"
        kwargs = {
            "api_key": effective_key,
            "timeout": provider.timeout,
        }
        if provider.base_url:
            kwargs["base_url"] = provider.base_url
        if provider.default_headers:
            kwargs["default_headers"] = provider.default_headers
        return OpenAI(**kwargs)

    raise LLMConfigurationError(
        f"未知 provider 协议类型: {provider.api_style}"
    )


def complete_text(
    role: str,
    system: str,
    prompt: str,
    provider_name: str | None = None,
    max_tokens: int = 2048,
) -> str:
    runtime = get_runtime(role, provider_name)

    if runtime.api_style == "anthropic":
        response = runtime.client.messages.create(
            model=runtime.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
        return _extract_anthropic_text(response)

    response = runtime.client.chat.completions.create(
        model=runtime.model,
        max_completion_tokens=max_tokens,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
    )
    message = response.choices[0].message
    return message.content or ""


def stream_text(
    role: str,
    system: str,
    prompt: str,
    provider_name: str | None = None,
    max_tokens: int = 2048,
) -> Iterator[str]:
    runtime = get_runtime(role, provider_name)

    if runtime.api_style == "anthropic":
        with runtime.client.messages.stream(
            model=runtime.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        ) as stream:
            for text in stream.text_stream:
                if text:
                    yield text
        return

    stream = runtime.client.chat.completions.create(
        model=runtime.model,
        max_completion_tokens=max_tokens,
        stream=True,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
    )
    for chunk in stream:
        for choice in getattr(chunk, "choices", []) or []:
            delta = getattr(choice, "delta", None)
            text = getattr(delta, "content", None) if delta else None
            if text:
                yield text


def _extract_anthropic_text(response: Any) -> str:
    parts: list[str] = []
    for block in getattr(response, "content", []) or []:
        if getattr(block, "type", "") == "text":
            parts.append(getattr(block, "text", ""))
    return "".join(parts)
