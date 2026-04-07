"""
dirbust_tool — 目录/文件爆破

支持两种引擎：
1) dirsearch（优先，支持自动 clone/pull）
2) 纯 Python asyncio fallback（无外部依赖）
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from core.config import get_config
from tools.web_utils import normalize_int_list, normalize_string_list

_UA = "Mozilla/5.0 (PentestPilot/1.0)"

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DIRSEARCH_REPO = "https://github.com/maurosoria/dirsearch.git"
AUTO_DIRSEARCH_DIR = ROOT_DIR / "third_party" / "dirsearch"
AUTO_DIRSEARCH_MAIN = AUTO_DIRSEARCH_DIR / "dirsearch.py"
AUTO_UPDATE_STAMP = AUTO_DIRSEARCH_DIR / ".pentestpilot_last_update"
_AUTO_BOOTSTRAP_ATTEMPTED = False

# 精选路径字典（Python fallback 与自定义 wordlist 复用）
_WORDLIST = {
    "admin": [
        "/admin", "/admin/", "/admin/login", "/admin/index.php",
        "/administrator/", "/administrator/index.php",
        "/wp-admin/", "/wp-login.php",
        "/cpanel", "/cpanel/", "/whm", "/webmail",
        "/manager/", "/manager/html",
        "/phpmyadmin/", "/phpmyadmin/index.php",
        "/adminer.php", "/adminer/",
        "/dashboard/", "/panel/", "/control/",
        "/user/login", "/users/sign_in",
    ],
    "api": [
        "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
        "/api/swagger.json", "/api/openapi.json",
        "/swagger-ui.html", "/swagger-ui/", "/swagger/",
        "/openapi.json", "/openapi.yaml",
        "/graphql", "/graphiql", "/playground",
        "/rest/", "/rest/api/",
        "/api/users", "/api/admin", "/api/config",
    ],
    "sensitive": [
        "/.env", "/.env.local", "/.env.production", "/.env.backup",
        "/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
        "/.svn/entries", "/.svn/wc.db",
        "/.DS_Store",
        "/config.php", "/config.yml", "/config.yaml", "/config.json",
        "/configuration.php",
        "/settings.py", "/settings.php",
        "/web.config", "/applicationHost.config",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt",
    ],
    "backup": [
        "/backup/", "/backup.zip", "/backup.tar.gz", "/backup.sql",
        "/backup.bak", "/db.sql", "/database.sql", "/dump.sql",
        "/site.zip", "/www.zip", "/html.zip",
        "/old/", "/bak/", "/archive/",
        "/wp-backup.zip",
    ],
    "logs": [
        "/logs/", "/log/", "/log.txt", "/error.log", "/access.log",
        "/debug.log", "/app.log", "/application.log",
        "/var/log/", "/tmp/",
    ],
    "common": [
        "/info.php", "/phpinfo.php", "/test.php", "/test.html",
        "/upload/", "/uploads/", "/files/", "/file/",
        "/download/", "/downloads/",
        "/static/", "/assets/", "/public/",
        "/src/", "/source/",
        "/shell.php", "/cmd.php", "/webshell.php",
        "/healthz", "/health", "/ping", "/status",
        "/metrics",
        "/actuator",
        "/console",
    ],
    "auth_bypass": [
        "/admin%20/", "/admin%2f/", "/ADMIN/",
        "/..", "/./admin",
        "/admin;/", "/admin?",
    ],
}
_ALL_PATHS = [p for paths in _WORDLIST.values() for p in paths]

_DIRSEARCH_CATEGORY_MAP = {
    "admin": ["common", "web"],
    "api": ["web", "common"],
    "sensitive": ["conf", "vcs", "keys", "db", "logs", "backups"],
    "backup": ["backups"],
    "logs": ["logs"],
    "common": ["common", "web"],
    "auth_bypass": ["common"],
}


# ---------------------------------------------------------------------
# 对外接口
# ---------------------------------------------------------------------

def dirsearch_init(update: bool = True, force_clone: bool = False) -> dict[str, Any]:
    """
    初始化 dirsearch 运行时（自动 clone/pull）。
    """
    bootstrap = _bootstrap_dirsearch_repo(update=update, force_clone=force_clone)
    runtime = _resolve_dirsearch_runtime(allow_bootstrap=False)
    if runtime.get("error"):
        return {
            "ready": False,
            "status": bootstrap.get("status", "error"),
            "error": runtime.get("error", "dirsearch runtime not found"),
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


def dirbust(
    target: str,
    categories: list[str] | str | None = None,
    extra_paths: list[str] | str | None = None,
    interesting_codes: list[int] | str | None = None,
    headers: dict[str, str] | None = None,
    engine: str = "auto",
    threads: int = 25,
    recursive: bool = False,
    extensions: list[str] | str | None = None,
    include_status: list[int] | str | None = None,
    exclude_status: list[int] | str | None = None,
    wordlist_categories: list[str] | str | None = None,
    max_time: int = 0,
    cookie: str = "",
    user_agent: str = "",
    proxy: str = "",
    timeout: float = 10.0,
) -> dict[str, Any]:
    """
    目录/文件爆破入口。

    Args:
        target: 目标 URL
        categories: 内置分类（admin/api/sensitive/backup/logs/common/auth_bypass）
        extra_paths: 额外路径
        interesting_codes: Python fallback 的感兴趣状态码
        headers: 自定义请求头
        engine: auto / dirsearch / python
        threads: 并发线程（dirsearch）或并发协程（python fallback）
        recursive: 是否递归扫描（dirsearch）
        extensions: 扩展名列表（dirsearch 的 -e）
        include_status: dirsearch include-status
        exclude_status: dirsearch exclude-status
        wordlist_categories: dirsearch 内置词典分类
        max_time: dirsearch 最大扫描时长（秒）
    """
    selected_engine = str(engine or "auto").strip().lower()
    if selected_engine not in {"auto", "dirsearch", "python"}:
        return {
            "error": f"不支持的 engine: {engine}",
            "available_engines": ["auto", "dirsearch", "python"],
        }

    codes = set(normalize_int_list(interesting_codes) or [200, 204, 301, 302, 401, 403, 500])
    normalized_categories = normalize_string_list(categories)
    normalized_extra_paths = normalize_string_list(extra_paths)
    normalized_ext = [item.lstrip(".") for item in normalize_string_list(extensions)]
    normalized_include = normalize_int_list(include_status)
    normalized_exclude = normalize_int_list(exclude_status)
    normalized_wordlist_categories = normalize_string_list(wordlist_categories)

    threads_value = _to_int(threads, default=25, minimum=1, maximum=200)
    max_time_value = _to_int(max_time, default=0, minimum=0, maximum=86400)
    timeout_value = _to_float(timeout, default=10.0, minimum=3.0, maximum=60.0)
    recursive_value = _to_bool(recursive, default=False)

    if selected_engine in {"auto", "dirsearch"}:
        ds_result = _run_dirsearch_scan(
            target=target,
            categories=normalized_categories,
            extra_paths=normalized_extra_paths,
            headers=headers or {},
            threads=threads_value,
            recursive=recursive_value,
            extensions=normalized_ext,
            include_status=normalized_include,
            exclude_status=normalized_exclude,
            wordlist_categories=normalized_wordlist_categories,
            max_time=max_time_value,
            cookie=str(cookie or "").strip(),
            user_agent=str(user_agent or "").strip(),
            proxy=str(proxy or "").strip(),
        )
        if not ds_result.get("error"):
            return ds_result
        if selected_engine == "dirsearch":
            return ds_result

        python_result = _run_python_dirbust(
            target=target,
            categories=normalized_categories,
            extra_paths=normalized_extra_paths,
            interesting_codes=codes,
            headers=headers,
            concurrency=threads_value,
            timeout=timeout_value,
        )
        python_result["engine"] = "python"
        python_result["fallback_from"] = "dirsearch"
        python_result["fallback_reason"] = ds_result.get("error", "dirsearch 不可用")
        return python_result

    python_result = _run_python_dirbust(
        target=target,
        categories=normalized_categories,
        extra_paths=normalized_extra_paths,
        interesting_codes=codes,
        headers=headers,
        concurrency=threads_value,
        timeout=timeout_value,
    )
    python_result["engine"] = "python"
    return python_result


# ---------------------------------------------------------------------
# dirsearch 引擎
# ---------------------------------------------------------------------

def _run_dirsearch_scan(
    target: str,
    categories: list[str],
    extra_paths: list[str],
    headers: dict[str, str],
    threads: int,
    recursive: bool,
    extensions: list[str],
    include_status: list[int],
    exclude_status: list[int],
    wordlist_categories: list[str],
    max_time: int,
    cookie: str,
    user_agent: str,
    proxy: str,
) -> dict[str, Any]:
    runtime = _resolve_dirsearch_runtime(allow_bootstrap=True)
    if runtime.get("error"):
        return {"error": runtime.get("error", "未找到可用 dirsearch")}

    # 若传入 categories/extra_paths，构建定制词典，避免语义丢失
    custom_paths = _build_paths(categories, extra_paths)
    custom_wordlist_file: Path | None = None
    if custom_paths:
        custom_wordlist_file = _write_temp_wordlist(custom_paths)

    merged_wordlist_categories = list(wordlist_categories)
    if categories:
        mapped: list[str] = []
        for category in categories:
            mapped.extend(_DIRSEARCH_CATEGORY_MAP.get(category, []))
        merged_wordlist_categories.extend(mapped)
    merged_wordlist_categories = sorted(set(item for item in merged_wordlist_categories if item))

    report_fd, report_path = tempfile.mkstemp(prefix="pentestpilot_dirsearch_", suffix=".json")
    os.close(report_fd)
    cmd = list(runtime["command"]) + [
        "-u",
        target,
        "-O",
        "json",
        "-o",
        report_path,
        "--quiet-mode",
        "--full-url",
        "--disable-cli",
        "-t",
        str(threads),
    ]
    if recursive:
        cmd.append("-r")
    if max_time > 0:
        cmd.extend(["--max-time", str(max_time)])

    if merged_wordlist_categories:
        cmd.extend(["--wordlist-categories", ",".join(merged_wordlist_categories)])
    if include_status:
        cmd.extend(["--include-status", ",".join(str(code) for code in sorted(set(include_status)))])
    if exclude_status:
        cmd.extend(["--exclude-status", ",".join(str(code) for code in sorted(set(exclude_status)))])

    if custom_wordlist_file is not None:
        cmd.extend(["-w", str(custom_wordlist_file)])
    if extensions:
        cmd.extend(["-e", ",".join(sorted(set(extensions)))])

    if cookie:
        cmd.extend(["--cookie", cookie])
    if user_agent:
        cmd.extend(["--user-agent", user_agent])
    if proxy:
        cmd.extend(["--proxy", proxy])
    if headers:
        for key, value in headers.items():
            cmd.extend(["-H", f"{key}: {value}"])

    timeout_seconds = max(120, max_time + 90) if max_time > 0 else 420
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=str(runtime["home"]),
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        _cleanup_temp_files(report_path, custom_wordlist_file)
        return {"error": f"dirsearch 扫描超时（{timeout_seconds}s）"}
    except Exception as exc:
        _cleanup_temp_files(report_path, custom_wordlist_file)
        return {"error": f"dirsearch 执行失败: {exc}"}

    findings: list[dict[str, Any]] = []
    parse_error = ""
    if Path(report_path).exists():
        try:
            data = json.loads(Path(report_path).read_text(encoding="utf-8", errors="ignore") or "{}")
            findings = _parse_dirsearch_results(data)
        except Exception as exc:
            parse_error = str(exc)

    _cleanup_temp_files(report_path, custom_wordlist_file)

    if proc.returncode != 0 and not findings:
        stderr_tail = (proc.stderr or "").strip()[-1200:]
        stdout_tail = (proc.stdout or "").strip()[-1200:]
        return {
            "error": "dirsearch 返回非 0 退出码",
            "exit_code": proc.returncode,
            "stderr_tail": stderr_tail,
            "stdout_tail": stdout_tail,
            "command": _mask_command_for_display(cmd),
        }

    classified = _classify_findings(findings)
    result = {
        "target": target,
        "engine": "dirsearch",
        "scanner": "dirsearch",
        "runtime_source": runtime.get("source", ""),
        "paths_tested": len(custom_paths) if custom_paths else len(findings),
        "findings": findings,
        "total": len(findings),
        "command": _mask_command_for_display(cmd),
        "exit_code": proc.returncode,
    }
    result.update(classified)
    if parse_error:
        result["parse_warning"] = f"dirsearch JSON 解析异常: {parse_error}"
    if proc.stderr.strip():
        result["stderr_tail"] = proc.stderr.strip()[-1200:]
    return result


def _parse_dirsearch_results(data: dict[str, Any]) -> list[dict[str, Any]]:
    raw_results = data.get("results", [])
    if not isinstance(raw_results, list):
        return []

    findings: list[dict[str, Any]] = []
    for item in raw_results:
        if not isinstance(item, dict):
            continue
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        try:
            status = int(item.get("status", 0) or 0)
        except Exception:
            status = 0
        findings.append(
            {
                "path": path,
                "url": url,
                "status": status,
                "size": int(item.get("contentLength", 0) or 0),
                "content_type": str(item.get("contentType", "") or ""),
                "server": "",
                "redirect": str(item.get("redirect", "") or "") or None,
                "title": "",
            }
        )
    return findings


# ---------------------------------------------------------------------
# Python fallback 引擎
# ---------------------------------------------------------------------

async def _probe_path(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    interesting_codes: set[int],
    timeout: float,
) -> dict[str, Any] | None:
    url = base_url.rstrip("/") + path
    try:
        resp = await client.head(url, timeout=timeout)
        if resp.status_code in interesting_codes:
            try:
                get_resp = await client.get(url, timeout=timeout + 2.0)
                return {
                    "path": path,
                    "url": url,
                    "status": get_resp.status_code,
                    "size": len(get_resp.content),
                    "content_type": get_resp.headers.get("content-type", ""),
                    "server": get_resp.headers.get("server", ""),
                    "redirect": str(get_resp.url) if get_resp.history else None,
                    "title": _extract_title(get_resp.text),
                }
            except Exception:
                return {"path": path, "url": url, "status": resp.status_code}
    except Exception:
        pass
    return None


async def _async_dirbust(
    base_url: str,
    paths: list[str],
    interesting_codes: set[int],
    headers: dict[str, str] | None = None,
    concurrency: int = 30,
    timeout: float = 10.0,
) -> list[dict[str, Any]]:
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(
        follow_redirects=False,
        verify=False,
        headers={"User-Agent": _UA, **(headers or {})},
        timeout=max(3.0, timeout),
    ) as client:
        async def bounded_probe(path: str):
            async with sem:
                return await _probe_path(client, base_url, path, interesting_codes, timeout)

        raw = await asyncio.gather(*[bounded_probe(path) for path in paths])
    return [item for item in raw if item is not None]


def _run_python_dirbust(
    target: str,
    categories: list[str],
    extra_paths: list[str],
    interesting_codes: set[int],
    headers: dict[str, str] | None,
    concurrency: int,
    timeout: float,
) -> dict[str, Any]:
    paths = _build_paths(categories, extra_paths)

    from tools.pure import run_async

    findings = run_async(
        _async_dirbust(
            target,
            paths,
            interesting_codes,
            headers=headers,
            concurrency=concurrency,
            timeout=timeout,
        )
    )
    result = {
        "target": target,
        "paths_tested": len(paths),
        "findings": findings,
        "total": len(findings),
    }
    result.update(_classify_findings(findings))
    return result


# ---------------------------------------------------------------------
# 结果分类 / 辅助
# ---------------------------------------------------------------------

def _build_paths(categories: list[str], extra_paths: list[str]) -> list[str]:
    if categories:
        paths: list[str] = []
        for category in categories:
            paths.extend(_WORDLIST.get(category, []))
    else:
        paths = list(_ALL_PATHS)
    if extra_paths:
        paths.extend(extra_paths)
    return list(dict.fromkeys(paths))


def _classify_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    high_interest = [item for item in findings if item.get("status") in (200, 204)]
    auth_protected = [item for item in findings if item.get("status") in (401, 403)]
    redirects = [item for item in findings if item.get("status") in (301, 302, 307, 308)]
    admin_panels = [item for item in high_interest if "/admin" in str(item.get("path", "")).lower()]
    login_pages = [item for item in high_interest if "login" in str(item.get("path", "")).lower()]
    upload_paths = [item for item in high_interest if "upload" in str(item.get("path", "")).lower()]
    sensitive_exposures = [
        item
        for item in high_interest
        if any(marker in str(item.get("path", "")).lower() for marker in (".env", ".git", "backup", ".sql", "config"))
    ]
    return {
        "high_interest": high_interest,
        "auth_protected": auth_protected,
        "redirects": redirects,
        "admin_panels": admin_panels,
        "login_pages": login_pages,
        "upload_paths": upload_paths,
        "sensitive_exposures": sensitive_exposures,
    }


def _extract_title(html: str) -> str:
    import re

    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return match.group(1).strip()[:100] if match else ""


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


def _to_float(value: Any, default: float, minimum: float | None = None, maximum: float | None = None) -> float:
    result = default
    if isinstance(value, bool):
        result = float(int(value))
    elif isinstance(value, (int, float)):
        result = float(value)
    elif isinstance(value, str):
        text = value.strip()
        try:
            result = float(text)
        except Exception:
            result = default
    if minimum is not None and result < minimum:
        result = minimum
    if maximum is not None and result > maximum:
        result = maximum
    return result


def _write_temp_wordlist(paths: list[str]) -> Path:
    handle, file_path = tempfile.mkstemp(prefix="pentestpilot_dirsearch_wordlist_", suffix=".txt")
    os.close(handle)
    normalized = []
    for path in paths:
        text = str(path or "").strip()
        if not text:
            continue
        normalized.append(text.lstrip("/"))
    Path(file_path).write_text("\n".join(dict.fromkeys(normalized)) + "\n", encoding="utf-8")
    return Path(file_path)


def _cleanup_temp_files(report_path: str, custom_wordlist_file: Path | None) -> None:
    try:
        if report_path and Path(report_path).exists():
            Path(report_path).unlink()
    except Exception:
        pass
    try:
        if custom_wordlist_file and custom_wordlist_file.exists():
            custom_wordlist_file.unlink()
    except Exception:
        pass


def _mask_command_for_display(command: list[str]) -> str:
    safe = list(command)
    for index, token in enumerate(safe):
        if token in {"--cookie", "--auth", "--proxy-auth"} and index + 1 < len(safe):
            safe[index + 1] = "***"
    return " ".join(safe)


# ---------------------------------------------------------------------
# runtime 发现 + 自动初始化
# ---------------------------------------------------------------------

def _resolve_dirsearch_runtime(allow_bootstrap: bool = True) -> dict[str, Any]:
    cfg = get_config() or {}
    tools_cfg = cfg.get("tools", {}) if isinstance(cfg.get("tools"), dict) else {}
    configured = str(tools_cfg.get("dirsearch", "") or "").strip()

    candidates: list[tuple[str, str]] = []
    if configured:
        candidates.append((configured, "config.tools.dirsearch"))
    candidates.append((str(AUTO_DIRSEARCH_MAIN), "auto_repo"))
    candidates.append((str(Path.cwd() / "third_party" / "dirsearch" / "dirsearch.py"), "cwd_auto_repo"))

    for raw_path, source in candidates:
        resolved = _resolve_dirsearch_path(raw_path)
        if resolved:
            command, home = resolved
            return {"command": command, "home": str(home), "source": source}

    if shutil.which("dirsearch"):
        return {"command": ["dirsearch"], "home": str(ROOT_DIR), "source": "PATH:dirsearch"}
    if shutil.which("dirsearch.py"):
        return {"command": ["dirsearch.py"], "home": str(ROOT_DIR), "source": "PATH:dirsearch.py"}

    global _AUTO_BOOTSTRAP_ATTEMPTED
    if allow_bootstrap and not _AUTO_BOOTSTRAP_ATTEMPTED:
        _AUTO_BOOTSTRAP_ATTEMPTED = True
        _bootstrap_dirsearch_repo(update=False, force_clone=False)
        return _resolve_dirsearch_runtime(allow_bootstrap=False)

    return {
        "error": (
            "未找到可用的 dirsearch（config/tools.dirsearch、自动仓库、PATH 均不可用）。"
            "可启用 tools.dirsearch_auto_init 自动拉取。"
        )
    }


def _resolve_dirsearch_path(raw_path: str) -> tuple[list[str], Path] | None:
    text = str(raw_path or "").strip()
    if not text:
        return None

    if shutil.which(text):
        return [text], ROOT_DIR

    input_path = Path(text).expanduser()
    candidates = [input_path]
    if not input_path.is_absolute():
        candidates.append((ROOT_DIR / input_path).resolve())

    seen: set[str] = set()
    for path in candidates:
        path = path.resolve() if not path.is_absolute() else path
        key = str(path)
        if key in seen:
            continue
        seen.add(key)

        if path.is_dir():
            entry = path / "dirsearch.py"
            if entry.exists():
                return [sys.executable, str(entry)], path
            continue

        if path.is_file():
            if path.suffix.lower() == ".py" or path.name == "dirsearch.py":
                return [sys.executable, str(path)], path.parent
            if os.access(path, os.X_OK):
                return [str(path)], path.parent
    return None


def _bootstrap_dirsearch_repo(update: bool, force_clone: bool) -> dict[str, Any]:
    cfg = get_config() or {}
    tools_cfg = cfg.get("tools", {}) if isinstance(cfg.get("tools"), dict) else {}

    local_dir_raw = str(tools_cfg.get("dirsearch_local_dir", "./third_party/dirsearch") or "./third_party/dirsearch").strip()
    local_dir = Path(local_dir_raw).expanduser()
    if not local_dir.is_absolute():
        local_dir = (ROOT_DIR / local_dir).resolve()

    configured = str(tools_cfg.get("dirsearch", "") or "").strip()
    if configured:
        configured_runtime = _resolve_dirsearch_path(configured)
        if configured_runtime:
            _, configured_home = configured_runtime
            if configured_home.resolve() != local_dir.resolve():
                return {
                    "status": "configured",
                    "path": str(configured_home),
                    "reason": "tools.dirsearch 已可用，跳过自动拉取",
                }

    auto_init = bool(tools_cfg.get("dirsearch_auto_init", True))
    repo_url = str(tools_cfg.get("dirsearch_repo", DEFAULT_DIRSEARCH_REPO) or DEFAULT_DIRSEARCH_REPO).strip()
    repo_ref = str(tools_cfg.get("dirsearch_ref", "") or "").strip()

    if not auto_init:
        return {"status": "skipped", "reason": "tools.dirsearch_auto_init=false", "path": str(local_dir)}

    git_bin = shutil.which("git")
    if not git_bin:
        return {"status": "error", "error": "未找到 git，无法自动拉取 dirsearch", "path": str(local_dir)}

    entry = local_dir / "dirsearch.py"
    if entry.exists():
        if update and _should_auto_update(local_dir, tools_cfg):
            pull_result = _git_update_repo(git_bin, local_dir, repo_ref)
            if pull_result.get("error"):
                return {"status": "error", "error": pull_result["error"], "path": str(local_dir)}
            _touch_update_stamp(local_dir)
            return {"status": "updated", "path": str(local_dir), "repo": repo_url, "ref": repo_ref}
        return {"status": "ready", "path": str(local_dir), "repo": repo_url, "ref": repo_ref}

    if local_dir.exists() and not (local_dir / ".git").exists():
        if not force_clone:
            return {
                "status": "error",
                "error": (
                    f"目录已存在但不包含 dirsearch 仓库: {local_dir}。"
                    "可手动清理后重试，或设置 tools.dirsearch 指向已有 dirsearch.py。"
                ),
                "path": str(local_dir),
            }
        return {"status": "error", "error": f"force_clone=true 但目录不可安全覆盖: {local_dir}", "path": str(local_dir)}

    clone_result = _git_clone_repo(git_bin, repo_url, local_dir, repo_ref)
    if clone_result.get("error"):
        return {"status": "error", "error": clone_result["error"], "path": str(local_dir), "repo": repo_url}
    if not entry.exists():
        return {"status": "error", "error": f"自动拉取后未找到 dirsearch.py: {entry}", "path": str(local_dir)}

    _touch_update_stamp(local_dir)
    return {"status": "installed", "path": str(local_dir), "repo": repo_url, "ref": repo_ref}


def _should_auto_update(local_dir: Path, tools_cfg: dict[str, Any]) -> bool:
    interval_hours_raw = tools_cfg.get("dirsearch_auto_update_interval_hours", 24)
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
        pull = _run_cmd([git_bin, "-C", str(local_dir), "pull", "--ff-only", "origin", repo_ref], cwd=str(ROOT_DIR), timeout=120)
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
        error_text = (proc.stderr or proc.stdout or "").strip()
        return {"error": error_text[-800:] if error_text else f"exit code {proc.returncode}"}
    return {"ok": True}
