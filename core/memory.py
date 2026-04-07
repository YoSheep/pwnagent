"""
Memory — 短期上下文 + 长期结果持久化（SQLite WAL 模式）
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path


class ShortTermMemory:
    """消息历史管理（PentestPilot 内部统一消息格式）。"""

    def __init__(self, max_messages: int = 40):
        self.max_messages = max_messages
        self._messages: list[dict] = []

    def add_message(self, message: dict):
        """添加完整消息 dict（保留 role + content 结构）。"""
        self._messages.append(message)
        self._trim()

    def get_messages(self) -> list[dict]:
        return list(self._messages)

    def clear(self):
        self._messages.clear()

    def _trim(self):
        """保留最新消息，但确保：
        1. 不从对话中间截断 assistant+tool_result 配对
        2. 第一条消息始终保留
        """
        if len(self._messages) <= self.max_messages:
            return
        first = self._messages[0]
        tail = self._messages[-(self.max_messages - 1):]

        # 确保 tail 不以 tool_result 开头（tool_result 必须跟在 assistant 后面）
        while tail and self._is_tool_result(tail[0]):
            tail = self._messages[-(self.max_messages - 1 + 1):]
            if len(tail) >= len(self._messages):
                break

        self._messages = [first] + tail

    @staticmethod
    def _is_tool_result(msg: dict) -> bool:
        content = msg.get("content")
        if isinstance(content, list):
            return any(
                isinstance(b, dict) and b.get("type") == "tool_result"
                for b in content
            )
        return False


class LongTermMemory:
    """SQLite 持久化（WAL 模式，支持并发读）。"""

    def __init__(self, db_path: str = "./db/sessions.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self._init_schema()

    def _init_schema(self):
        with self._lock:
            cur = self.conn.cursor()
            cur.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id          TEXT PRIMARY KEY,
                    target      TEXT NOT NULL,
                    scope       TEXT NOT NULL,
                    phase       TEXT NOT NULL,
                    created_at  TEXT NOT NULL,
                    updated_at  TEXT NOT NULL,
                    summary     TEXT DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  TEXT NOT NULL,
                    title       TEXT NOT NULL,
                    severity    TEXT NOT NULL,
                    target      TEXT NOT NULL,
                    description TEXT,
                    payload     TEXT,
                    reproduction TEXT,
                    remediation TEXT,
                    cvss        REAL DEFAULT 0.0,
                    thought_excerpt TEXT,
                    created_at  TEXT NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES sessions(id)
                );
                CREATE TABLE IF NOT EXISTS thought_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  TEXT NOT NULL,
                    phase       TEXT NOT NULL,
                    thought     TEXT,
                    action      TEXT,
                    action_input TEXT,
                    result      TEXT,
                    created_at  TEXT NOT NULL,
                    FOREIGN KEY(session_id) REFERENCES sessions(id)
                );
            """)
            self.conn.commit()

    def save_session(self, session_id: str, target: str, scope: list[str],
                     phase: str, summary: dict):
        now = datetime.utcnow().isoformat()
        with self._lock:
            self.conn.execute(
                """INSERT INTO sessions(id, target, scope, phase, created_at, updated_at, summary)
                   VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                     phase=excluded.phase,
                     updated_at=excluded.updated_at,
                     summary=excluded.summary""",
                (session_id, target, json.dumps(scope), phase, now, now,
                 json.dumps(summary, ensure_ascii=False))
            )
            self.conn.commit()

    def load_session(self, session_id: str) -> dict | None:
        with self._lock:
            cur = self.conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,))
            row = cur.fetchone()
            if row:
                cols = [d[0] for d in cur.description]
                return dict(zip(cols, row))
            return None

    def save_finding(self, session_id: str, finding) -> int:
        now = datetime.utcnow().isoformat()
        with self._lock:
            cur = self.conn.execute(
                """INSERT INTO findings
                   (session_id, title, severity, target, description, payload,
                    reproduction, remediation, cvss, thought_excerpt, created_at)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (session_id, finding.title, finding.severity, finding.target,
                 finding.description, finding.payload, finding.reproduction,
                 finding.remediation, finding.cvss, finding.thought_excerpt, now)
            )
            self.conn.commit()
            return cur.lastrowid

    def get_findings(self, session_id: str) -> list[dict]:
        with self._lock:
            cur = self.conn.execute(
                "SELECT * FROM findings WHERE session_id=? ORDER BY cvss DESC",
                (session_id,)
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def save_thought(self, session_id: str, entry: dict):
        now = datetime.utcnow().isoformat()
        with self._lock:
            self.conn.execute(
                """INSERT INTO thought_log
                   (session_id, phase, thought, action, action_input, result, created_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (session_id, entry.get("phase", ""), entry.get("thought", ""),
                 entry.get("action", ""),
                 json.dumps(entry.get("action_input", {}), ensure_ascii=False),
                 json.dumps(entry.get("result", ""), ensure_ascii=False, default=str),
                 now)
            )
            self.conn.commit()

    def get_thought_log(self, session_id: str) -> list[dict]:
        with self._lock:
            cur = self.conn.execute(
                "SELECT * FROM thought_log WHERE session_id=? ORDER BY id",
                (session_id,)
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def close(self):
        with self._lock:
            self.conn.close()
