"""
PentestPilot — CLI 入口
架构图中的 Input Router：区分扫描任务 / 知识查询 / 工具管理
"""
from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.table import Table

from core.state_machine import PentestSession
from tools.registry import ToolRegistry

app = typer.Typer(add_completion=False)
console = Console()

BANNER = """
██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗████████╗██████╗ ██╗██╗      ██████╗ ████████╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔══██╗██║██║     ██╔═══██╗╚══██╔══╝
██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗   ██║   ██████╔╝██║██║     ██║   ██║   ██║
██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║   ██║   ██╔═══╝ ██║██║     ██║   ██║   ██║
██║     ███████╗██║ ╚████║   ██║   ███████╗███████║   ██║   ██║     ██║███████╗╚██████╔╝   ██║
╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚═╝     ╚═╝╚══════╝ ╚═════╝    ╚═╝
"""


def _print_banner():
    console.print(f"[bold red]{BANNER}[/bold red]")
    console.print(Panel(
        "[bold red]警告：本工具仅限经书面授权的渗透测试使用。\n"
        "对未授权目标使用本工具违反法律，使用者需自行承担全部法律责任。[/bold red]",
        title="[bold white]PentestPilot v2.0 — AI 驱动渗透测试框架[/bold white]",
        border_style="red",
    ))


def _build_registry(extra_plugins: str | None = None) -> ToolRegistry:
    """构建工具注册中心，自动发现内置 + 加载插件。"""
    registry = ToolRegistry()
    registry.discover_builtin("./tools")
    if extra_plugins:
        registry.load_plugins_dir(extra_plugins)
    # 默认插件目录
    registry.load_plugins_dir("./plugins")
    return registry


# ==================================================================
# 命令：scan — 完整渗透测试（主入口）
# ==================================================================

@app.command()
def scan(
    target: str = typer.Argument(..., help="目标 URL 或 IP"),
    scope: str = typer.Option("", "--scope", "-s",
                              help="可选：在 session / report 中记录测试范围，逗号分隔"),
    objective: str = typer.Option("", "--objective", help="可选：告诉 agent 当前 exploit chain 或测试目标"),
    output: str = typer.Option("./reports", "--output", "-o", help="报告输出目录"),
    interactive: bool = typer.Option(True, "--interactive/--no-interactive",
                                     help="交互模式：高风险操作前暂停确认"),
    verbose: bool = typer.Option(False, "--verbose", "-v",
                                 help="显示完整思维链"),
    planner: bool = typer.Option(True, "--planner/--no-planner",
                                 help="启用动态规划器（Planner + Replanner）"),
    plugins: str = typer.Option(None, "--plugins", help="额外插件目录路径"),
):
    """执行完整的 AI 驱动渗透测试。"""
    _print_banner()

    confirmed = Confirm.ask(
        f"[bold]确认你已获得对 [cyan]{target}[/cyan] 的书面测试授权？[/bold]"
    )
    if not confirmed:
        console.print("[red]已取消。[/red]")
        raise typer.Exit(1)

    scope_list = [s.strip() for s in scope.split(",") if s.strip()]

    Path(output).mkdir(parents=True, exist_ok=True)

    _run_agent(target, scope_list, objective, output, interactive, verbose, planner, plugins)


def _run_agent(
    target: str, scope: list[str], objective: str, output_dir: str,
    interactive: bool, verbose: bool, use_planner: bool,
    plugins: str | None,
):
    from core.agent import PentestPilot
    from core.llm import LLMConfigurationError
    from modules.reporter import generate_report

    # 工具注册中心
    registry = _build_registry(plugins)

    # 注册 generate_report（需要 session 和 output_dir，延迟绑定）
    session = PentestSession(target=target, scope=scope, objective=objective)

    registry.register(
        "generate_report",
        lambda title="渗透测试报告", tester="PentestPilot", **kw: generate_report(
            session=session, output_dir=output_dir, title=title, tester=tester,
        ),
        description="生成渗透测试报告（Markdown + HTML）。",
        input_schema={
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "报告标题"},
                "tester": {"type": "string", "description": "测试人员"},
            },
            "required": [],
        },
        category="report",
        source="builtin",
    )

    # 展示已注册工具
    registry.print_tools()

    # RAG 检索器
    rag_retriever = None
    try:
        from knowledge.retriever import retrieve_context
        rag_retriever = retrieve_context
    except ImportError:
        pass

    try:
        agent = PentestPilot(
            session=session,
            tools=registry.get_tools(),
            tool_defs=registry.get_tool_defs(),
            interactive=interactive,
            verbose=verbose,
            rag_retriever=rag_retriever,
            use_planner=use_planner,
        )
        agent.run()
    except LLMConfigurationError as e:
        console.print(f"[red]LLM 配置错误: {e}[/red]")
        raise typer.Exit(1)


# ==================================================================
# 命令：ask — 知识查询（架构图中的 Knowledge Agent 路径）
# ==================================================================

@app.command()
def ask(
    question: str = typer.Argument(..., help="安全相关问题"),
):
    """向 PentestPilot 知识库提问（不执行扫描）。"""
    from core.llm import LLMConfigurationError
    from knowledge.retriever import retrieve_context
    from core.llm import stream_text

    rag_context = retrieve_context(question, n_results=5)

    system = (
        "你是 PentestPilot 知识助手，擅长网络安全、渗透测试、漏洞分析。\n"
        "根据知识库内容和你的专业知识回答用户问题。\n"
        "如果知识库无相关内容，用你自己的知识回答，但标注'以下来自通用知识'。"
    )
    prompt = question
    if rag_context:
        prompt = f"{question}\n\n{rag_context}"

    try:
        console.print()
        for text in stream_text(
            role="knowledge",
            system=system,
            prompt=prompt,
            max_tokens=2048,
        ):
            console.print(text, end="")
        console.print()
    except LLMConfigurationError as e:
        console.print(f"[red]LLM 配置错误: {e}[/red]")
        raise typer.Exit(1)


# ==================================================================
# 命令：tools — 工具管理（架构图中的工具注册中心）
# ==================================================================

@app.command()
def tools(
    category: str = typer.Option(None, "--category", "-c",
                                 help="按类别过滤: recon/scan/analysis/report"),
    plugins: str = typer.Option(None, "--plugins", help="额外插件目录"),
):
    """列出所有已注册的工具。"""
    registry = _build_registry(plugins)
    if category:
        filtered = registry.list_tools(category=category)
        table = Table(title=f"工具列表 — {category}", show_lines=True)
        table.add_column("工具", style="cyan")
        table.add_column("来源")
        table.add_column("描述")
        for t in filtered:
            table.add_row(t["name"], t["source"], t["description"])
        console.print(table)
    else:
        registry.print_tools()


# ==================================================================
# 命令：report — 从历史 session 重新生成报告
# ==================================================================

@app.command()
def report(
    session_id: str = typer.Argument(..., help="Session ID"),
    output: str = typer.Option("./reports", help="报告输出目录"),
):
    """从已保存的 session 重新生成报告。"""
    from core.memory import LongTermMemory
    from modules.reporter import generate_report_from_db

    mem = LongTermMemory()
    try:
        session_data = mem.load_session(session_id)
        if not session_data:
            console.print(f"[red]Session {session_id} 不存在。[/red]")
            raise typer.Exit(1)
        result = generate_report_from_db(session_id, session_data, mem, output)
        console.print(f"[green]报告已生成: {result}[/green]")
    finally:
        mem.close()


# ==================================================================
# 命令：sessions — 列出历史 session
# ==================================================================

@app.command()
def sessions():
    """列出历史测试 session。"""
    from core.memory import LongTermMemory

    mem = LongTermMemory()
    try:
        cur = mem.conn.execute(
            "SELECT id, target, phase, created_at, summary "
            "FROM sessions ORDER BY created_at DESC LIMIT 20"
        )
        rows = cur.fetchall()
        if not rows:
            console.print("[dim]暂无历史 session。[/dim]")
            return
        table = Table(title="历史测试 Session", show_lines=True)
        table.add_column("ID", style="cyan")
        table.add_column("目标")
        table.add_column("阶段")
        table.add_column("时间")
        for row in rows:
            table.add_row(row[0], row[1], row[2], row[3][:19])
        console.print(table)
    finally:
        mem.close()


# ==================================================================
# 命令：ingest — 知识库管理
# ==================================================================

@app.command()
def ingest(
    path: str = typer.Argument(None, help="要导入的文件路径（JSON/Markdown）"),
    owasp: bool = typer.Option(False, "--owasp", help="导入内置 OWASP Top 10"),
):
    """向知识库导入知识文档。"""
    from knowledge.ingest import ingest_cve_json, ingest_markdown, ingest_owasp_top10

    if owasp:
        ingest_owasp_top10()
    if path:
        p = Path(path)
        if p.suffix == ".json":
            ingest_cve_json(str(p))
        elif p.suffix in (".md", ".txt"):
            ingest_markdown(str(p))
        else:
            console.print(f"[red]不支持的文件格式: {p.suffix}[/red]")
    if not owasp and not path:
        console.print("[yellow]请指定文件路径或使用 --owasp[/yellow]")


if __name__ == "__main__":
    app()
