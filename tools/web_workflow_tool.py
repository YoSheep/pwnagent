"""
有状态 Web 工作流工具：通用请求、登录、上传。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx

from tools.web_utils import normalize_string_list, summarize_http_response

_UA = "Mozilla/5.0 (PentestPilot/2.0)"


@dataclass
class _WorkflowState:
    cookies: dict[str, str] = field(default_factory=dict)
    base_url: str = ""
    last_response: dict[str, Any] = field(default_factory=dict)


class _WebWorkflowManager:
    def __init__(self):
        self._sessions: dict[str, _WorkflowState] = {}

    def _state(self, alias: str) -> _WorkflowState:
        alias = alias or "default"
        if alias not in self._sessions:
            self._sessions[alias] = _WorkflowState()
        return self._sessions[alias]

    def _build_client(
        self,
        session_alias: str,
        follow_redirects: bool,
        headers: dict[str, str] | None = None,
    ) -> httpx.Client:
        state = self._state(session_alias)
        merged_headers = {"User-Agent": _UA}
        if headers:
            merged_headers.update(headers)

        return httpx.Client(
            follow_redirects=follow_redirects,
            timeout=20.0,
            verify=False,
            headers=merged_headers,
            cookies=state.cookies,
        )

    def request(
        self,
        target: str,
        path: str = "",
        method: str = "GET",
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        data: str = "",
        form: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        session_alias: str = "",
        capture_body: bool = True,
        max_body_chars: int = 1500,
        follow_redirects: bool = True,
    ) -> dict[str, Any]:
        state = self._state(session_alias)
        url = urljoin(target.rstrip("/") + "/", path.lstrip("/")) if path else target

        method = method.upper().strip() or "GET"
        capture_body = _to_bool(capture_body, default=True)
        follow_redirects = _to_bool(follow_redirects, default=True)
        max_body_chars = _to_int(max_body_chars, default=1500, minimum=200, maximum=12000)
        request_kwargs: dict[str, Any] = {"params": params or None}
        if form:
            request_kwargs["data"] = form
        elif data:
            request_kwargs["content"] = data
        if json_body:
            request_kwargs["json"] = json_body

        with self._build_client(session_alias, follow_redirects, headers) as client:
            response = client.request(method, url, **request_kwargs)
            state.cookies = dict(client.cookies)
            state.base_url = target
            state.last_response = summarize_http_response(
                response,
                include_body=capture_body,
                max_body_chars=max_body_chars,
            )

        return {
            "target": target,
            "session_alias": session_alias or "default",
            "requested_url": url,
            "method": method,
            "response": state.last_response,
            "stored_cookies": state.cookies,
        }

    def login(
        self,
        target: str,
        username: str,
        password: str,
        login_path: str = "",
        session_alias: str = "default",
        username_field: str = "",
        password_field: str = "",
        extra_fields: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        landing = self.request(
            target=target,
            path=login_path,
            method="GET",
            headers=headers,
            session_alias=session_alias,
            capture_body=True,
            follow_redirects=True,
        )
        response = landing.get("response", {})
        forms = response.get("login_forms") or response.get("forms") or []
        if not forms:
            return {
                "success": False,
                "error": "未发现可提交的登录表单",
                "session_alias": session_alias,
                "landing": response,
            }

        form = forms[0]
        payload = {}
        for item in form.get("inputs", []):
            name = item.get("name", "")
            if name:
                payload[name] = item.get("value", "")

        input_names = {item.get("name", "").lower(): item.get("name", "") for item in form.get("inputs", [])}
        user_field = username_field or input_names.get("username") or input_names.get("email") or input_names.get("login") or "username"
        pass_field = password_field or input_names.get("password") or input_names.get("passwd") or input_names.get("pass") or "password"
        payload[user_field] = username
        payload[pass_field] = password
        if extra_fields:
            payload.update(extra_fields)

        submit_result = self.request(
            target=form.get("action") or target,
            method=form.get("method", "POST"),
            form=payload,
            headers=headers,
            session_alias=session_alias,
            capture_body=True,
            follow_redirects=True,
        )
        submit_response = submit_result.get("response", {})
        body_preview = (submit_response.get("body") or submit_response.get("body_preview") or "").lower()
        success = (
            submit_response.get("status_code", 0) < 400
            and bool(self._state(session_alias).cookies)
            and "login" not in body_preview
        )
        if submit_response.get("login_forms"):
            success = False

        return {
            "success": success,
            "session_alias": session_alias,
            "login_url": form.get("action") or target,
            "submitted_fields": sorted(payload.keys()),
            "response": submit_response,
            "stored_cookies": self._state(session_alias).cookies,
        }

    def upload(
        self,
        target: str,
        session_alias: str,
        upload_path: str = "",
        file_content: str = "",
        file_path: str = "",
        filename: str = "shell.php",
        field_name: str = "file",
        extra_fields: dict[str, Any] | None = None,
        content_type: str = "application/octet-stream",
        verify_paths: list[str] | str | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        if not file_content and not file_path:
            return {"success": False, "error": "file_content 与 file_path 至少提供一个", "session_alias": session_alias}

        if file_path:
            path_obj = Path(file_path)
            if not path_obj.exists():
                return {"success": False, "error": f"文件不存在: {file_path}", "session_alias": session_alias}
            body_bytes = path_obj.read_bytes()
            filename = path_obj.name
        else:
            body_bytes = file_content.encode()

        state = self._state(session_alias)
        url = urljoin(target.rstrip("/") + "/", upload_path.lstrip("/")) if upload_path else target
        files = {field_name: (filename, body_bytes, content_type)}
        data = extra_fields or {}

        with self._build_client(session_alias, True, headers) as client:
            response = client.post(url, files=files, data=data)
            state.cookies = dict(client.cookies)
            response_summary = summarize_http_response(response, include_body=True, max_body_chars=1800)
            state.last_response = response_summary

        verified_urls = []
        for candidate in normalize_string_list(verify_paths):
            full_url = urljoin(target.rstrip("/") + "/", candidate.lstrip("/"))
            try:
                with self._build_client(session_alias, True, headers) as client:
                    probe = client.get(full_url)
                if probe.status_code < 400:
                    verified_urls.append(full_url)
            except Exception:
                continue

        success = response_summary.get("status_code", 0) < 400
        if verified_urls:
            success = True

        return {
            "success": success,
            "session_alias": session_alias,
            "upload_url": url,
            "filename": filename,
            "response": response_summary,
            "stored_cookies": state.cookies,
            "verified_urls": verified_urls,
        }


_MANAGER = _WebWorkflowManager()


def http_request(
    target: str,
    path: str = "",
    method: str = "GET",
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    data: str = "",
    form: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
    session_alias: str = "",
    capture_body: bool = True,
    max_body_chars: int = 1500,
    follow_redirects: bool = True,
) -> dict[str, Any]:
    """发送通用 HTTP 请求并返回结构化响应，可复用会话 Cookie。"""
    return _MANAGER.request(
        target=target,
        path=path,
        method=method,
        params=params,
        headers=headers,
        data=data,
        form=form,
        json_body=json_body,
        session_alias=session_alias,
        capture_body=capture_body,
        max_body_chars=max_body_chars,
        follow_redirects=follow_redirects,
    )


def login_form(
    target: str,
    username: str,
    password: str,
    login_path: str = "",
    session_alias: str = "default",
    username_field: str = "",
    password_field: str = "",
    extra_fields: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    """抓取登录页、自动识别表单并保持认证会话。"""
    return _MANAGER.login(
        target=target,
        username=username,
        password=password,
        login_path=login_path,
        session_alias=session_alias,
        username_field=username_field,
        password_field=password_field,
        extra_fields=extra_fields,
        headers=headers,
    )


def upload_file(
    target: str,
    session_alias: str,
    upload_path: str = "",
    file_content: str = "",
    file_path: str = "",
    filename: str = "shell.php",
    field_name: str = "file",
    extra_fields: dict[str, Any] | None = None,
    content_type: str = "application/octet-stream",
    verify_paths: list[str] | str | None = None,
    headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
    """使用已建立的认证会话上传文件，并可选验证落地路径。"""
    return _MANAGER.upload(
        target=target,
        session_alias=session_alias,
        upload_path=upload_path,
        file_content=file_content,
        file_path=file_path,
        filename=filename,
        field_name=field_name,
        extra_fields=extra_fields,
        content_type=content_type,
        verify_paths=verify_paths,
        headers=headers,
    )


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
