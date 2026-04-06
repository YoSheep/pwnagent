"""
knowledge/retriever — RAG 检索接口
"""
from __future__ import annotations

from pathlib import Path

import chromadb

_DB_PATH = str(Path(__file__).parent / "db")

_client: chromadb.PersistentClient | None = None
_collection = None


def _get_collection():
    global _client, _collection
    if _collection is None:
        _client = chromadb.PersistentClient(path=_DB_PATH)
        _collection = _client.get_or_create_collection("pentest_knowledge")
    return _collection


def retrieve_context(query: str, n_results: int = 3) -> str:
    """
    根据查询语句检索最相关的知识条目，返回拼接后的上下文字符串。
    若知识库为空或检索失败，返回空字符串。
    """
    try:
        from knowledge.ingest import ensure_default_knowledge

        ensure_default_knowledge()
        col = _get_collection()
        count = col.count()
        if count == 0:
            return ""

        results = col.query(
            query_texts=[query],
            n_results=min(n_results, count),
        )
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]

        if not docs:
            return ""

        parts = []
        for doc, meta in zip(docs, metas):
            source = meta.get("title") or meta.get("cve_id") or meta.get("source", "")
            parts.append(f"[参考知识 — {source}]\n{doc}")

        return "\n\n".join(parts)

    except Exception:
        return ""


def retrieve_for_finding(title: str, description: str) -> str:
    """针对已发现的漏洞检索相关知识，辅助报告生成。"""
    query = f"{title} {description}"
    return retrieve_context(query, n_results=2)
