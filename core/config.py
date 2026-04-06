"""
配置加载工具。
优先从仓库根目录的 config.yaml 读取，并尝试加载 .env 中的密钥。
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - 可选依赖
    def load_dotenv(*args, **kwargs):  # type: ignore[override]
        return False


ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = ROOT_DIR / "config.yaml"
DEFAULT_DOTENV_PATH = ROOT_DIR / ".env"


def _load_dotenv_if_present():
    if DEFAULT_DOTENV_PATH.exists():
        load_dotenv(DEFAULT_DOTENV_PATH, override=False)


@lru_cache(maxsize=4)
def load_config(config_path: str | Path | None = None) -> dict[str, Any]:
    """加载 YAML 配置文件。缺失时返回空配置。"""
    _load_dotenv_if_present()

    raw_path = config_path or os.environ.get("PWNAGENT_CONFIG") or DEFAULT_CONFIG_PATH
    path = Path(raw_path)
    if not path.exists():
        return {}

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def get_config() -> dict[str, Any]:
    return load_config()


def reload_config() -> dict[str, Any]:
    load_config.cache_clear()
    return load_config()
