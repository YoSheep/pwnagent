"""
工具注册中心 — 支持运行时动态注册工具 + 插件加载
对应架构图中的"工具注册中心 + 动态注册"。
"""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import sys
from pathlib import Path
from typing import Any, Callable

from rich.console import Console
from rich.table import Table

console = Console()


class ToolRegistry:
    """
    集中管理所有可用工具。
    支持：
      - 内置工具自动发现（tools/ 目录）
      - 运行时动态注册自定义工具
      - 从外部 .py 文件加载插件
      - 自动生成通用工具定义（可供 Anthropic / OpenAI-compatible tool calling 使用）
    """

    def __init__(self):
        self._tools: dict[str, Callable] = {}
        self._defs: dict[str, dict] = {}
        self._meta: dict[str, dict] = {}   # 额外元数据（来源、描述等）

    # ------------------------------------------------------------------
    # 注册
    # ------------------------------------------------------------------

    def register(
        self,
        name: str,
        func: Callable,
        description: str = "",
        input_schema: dict | None = None,
        category: str = "general",
        source: str = "builtin",
    ):
        """注册一个工具。"""
        if not description:
            description = (func.__doc__ or "").strip().split("\n")[0]

        if input_schema is None:
            input_schema = self._infer_schema(func)

        self._tools[name] = func
        self._defs[name] = {
            "name": name,
            "description": description,
            "input_schema": input_schema,
        }
        self._meta[name] = {
            "category": category,
            "source": source,
            "module": func.__module__,
        }

    def unregister(self, name: str):
        self._tools.pop(name, None)
        self._defs.pop(name, None)
        self._meta.pop(name, None)

    # ------------------------------------------------------------------
    # 内置工具自动发现
    # ------------------------------------------------------------------

    def discover_builtin(self, tools_dir: str = "./tools"):
        """扫描 tools/ 目录，自动注册所有导出的工具函数。"""
        tools_path = Path(tools_dir)
        if not tools_path.exists():
            return

        # 内置工具映射：模块名 → (函数名, 类别)
        builtin_map = {
            "nmap_tool": ("nmap_scan", "recon"),
            "httpx_tool": ("httpx_probe", "recon"),
            "nuclei_tool": ("nuclei_scan", "scan"),
            "xss_tool": ("xss_scan", "scan"),
            "sqli_tool": ("sqli_scan", "scan"),
            "ssrf_tool": ("ssrf_scan", "scan"),
            "subdomain_tool": ("subdomain_enum", "recon"),
            "dirbust_tool": ("dirbust", "recon"),
            "jwt_tool": ("jwt_analyze", "analysis"),
            "browser_tool": ("browser_verify", "scan"),
        }

        # 同一模块多个导出函数
        extra_exports = {
            "jwt_tool": [("extract_jwt_from_response", "analysis")],
        }

        for module_name, (func_name, category) in builtin_map.items():
            try:
                mod = importlib.import_module(f"tools.{module_name}")
                func = getattr(mod, func_name)
                self.register(func_name, func, category=category, source="builtin")
                # 注册同模块的额外导出
                for extra_fn, extra_cat in extra_exports.get(module_name, []):
                    if hasattr(mod, extra_fn):
                        self.register(extra_fn, getattr(mod, extra_fn),
                                      category=extra_cat, source="builtin")
            except (ImportError, AttributeError) as e:
                console.print(f"[dim]跳过内置工具 {module_name}: {e}[/dim]")

        # pure/ 子目录
        pure_map = {
            "pure.port_scanner": ("python_port_scan", "recon"),
            "pure.vuln_checker": ("python_vuln_check", "scan"),
            "pure.onedaypoc": ("onedaypoc_scan", "scan"),
        }
        for module_name, (func_name, category) in pure_map.items():
            try:
                mod = importlib.import_module(f"tools.{module_name}")
                func = getattr(mod, func_name)
                self.register(func_name, func, category=category, source="builtin-pure")
            except (ImportError, AttributeError) as e:
                console.print(f"[dim]跳过纯 Python 工具 {module_name}: {e}[/dim]")

    # ------------------------------------------------------------------
    # 插件加载
    # ------------------------------------------------------------------

    def load_plugin(self, path: str):
        """
        从外部 .py 文件加载插件工具。
        插件文件需要定义 register(registry) 函数，示例：

            def my_custom_scan(target: str) -> dict:
                '''我的自定义扫描器'''
                ...

            def register(registry):
                registry.register("my_custom_scan", my_custom_scan,
                                  category="custom", source="plugin")
        """
        path = Path(path)
        if not path.exists():
            console.print(f"[red]插件不存在: {path}[/red]")
            return

        spec = importlib.util.spec_from_file_location(f"plugin_{path.stem}", path)
        if spec is None or spec.loader is None:
            console.print(f"[red]无法加载插件: {path}[/red]")
            return

        module = importlib.util.module_from_spec(spec)
        sys.modules[f"plugin_{path.stem}"] = module
        spec.loader.exec_module(module)

        if hasattr(module, "register"):
            module.register(self)
            console.print(f"[green]已加载插件: {path.name}[/green]")
        else:
            console.print(f"[yellow]插件 {path.name} 缺少 register() 函数[/yellow]")

    def load_plugins_dir(self, directory: str = "./plugins"):
        """加载目录下所有 .py 插件。"""
        plugins_dir = Path(directory)
        if not plugins_dir.exists():
            return
        for py_file in sorted(plugins_dir.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            self.load_plugin(str(py_file))

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------

    def get_tools(self) -> dict[str, Callable]:
        return dict(self._tools)

    def get_tool_defs(self) -> list[dict]:
        return list(self._defs.values())

    def get_tool(self, name: str) -> Callable | None:
        return self._tools.get(name)

    def list_tools(self, category: str | None = None) -> list[dict]:
        result = []
        for name, meta in self._meta.items():
            if category and meta["category"] != category:
                continue
            result.append({
                "name": name,
                "description": self._defs[name]["description"][:80],
                "category": meta["category"],
                "source": meta["source"],
            })
        return result

    def print_tools(self):
        table = Table(title="已注册工具", show_lines=True)
        table.add_column("工具", style="cyan")
        table.add_column("类别")
        table.add_column("来源")
        table.add_column("描述")
        for name in sorted(self._tools):
            meta = self._meta[name]
            desc = self._defs[name]["description"][:60]
            table.add_row(name, meta["category"], meta["source"], desc)
        console.print(table)

    # ------------------------------------------------------------------
    # Schema 自动推断
    # ------------------------------------------------------------------

    @staticmethod
    def _infer_schema(func: Callable) -> dict:
        """从函数签名自动生成 input_schema。"""
        sig = inspect.signature(func)
        properties = {}
        required = []

        type_map = {
            str: "string",
            int: "integer",
            float: "number",
            bool: "boolean",
            list: "array",
            dict: "object",
        }

        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls"):
                continue

            annotation = param.annotation
            json_type = "string"

            # 处理 Optional 和 Union
            origin = getattr(annotation, "__origin__", None)
            if origin is not None:
                args = getattr(annotation, "__args__", ())
                # list[str] → array
                if origin is list:
                    json_type = "array"
                else:
                    # 取第一个非 None 类型
                    for arg in args:
                        if arg is not type(None):
                            json_type = type_map.get(arg, "string")
                            break
            elif annotation != inspect.Parameter.empty:
                json_type = type_map.get(annotation, "string")

            prop: dict[str, Any] = {"type": json_type}

            # 默认值
            if param.default != inspect.Parameter.empty:
                if param.default is not None:
                    prop["default"] = param.default
            else:
                required.append(param_name)

            properties[param_name] = prop

        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }
