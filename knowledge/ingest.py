"""
knowledge/ingest — CVE/OWASP/Writeup 文档入库
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import chromadb
import yaml

from core.config import get_config

_BASE_DIR = Path(__file__).resolve().parent
_DB_PATH = str(_BASE_DIR / "db")
_SEEDS_DIR = _BASE_DIR / "seeds"
_MANIFEST_PATH = _SEEDS_DIR / "manifest.yaml"
_AUTO_BOOTSTRAPPED = False

_client = chromadb.PersistentClient(path=_DB_PATH)
_collection = _client.get_or_create_collection(
    "pentest_knowledge",
    metadata={"hnsw:space": "cosine"},
)


def ingest_cve_json(filepath: str):
    """导入 CVE JSON 文件（NVD 格式）。"""
    with open(filepath, encoding="utf-8") as f:
        data = json.load(f)

    items = data.get("CVE_Items", data.get("vulnerabilities", []))
    docs, ids, metas = [], [], []

    for i, item in enumerate(items):
        cve_id = _extract_cve_id(item)
        description = _extract_description(item)
        if not description:
            continue

        docs.append(description)
        ids.append(f"cve_{cve_id}_{i}")
        metas.append({"type": "cve", "cve_id": cve_id, "source": filepath})

    if docs:
        _batch_upsert(docs, ids, metas)
        print(f"[+] 导入 {len(docs)} 条 CVE 记录")


def ingest_markdown(filepath: str, doc_type: str = "writeup"):
    """导入 Markdown 文档（writeup、OWASP 条目等），按段落切分。"""
    content = Path(filepath).read_text(encoding="utf-8")
    import re

    sections = re.split(r"\n#{1,3} ", content)
    sections = [s.strip() for s in sections if len(s.strip()) > 100]

    docs = sections
    ids = [f"{doc_type}_{Path(filepath).stem}_{i}" for i in range(len(sections))]
    metas = [{"type": doc_type, "source": str(filepath)} for _ in sections]

    if docs:
        _batch_upsert(docs, ids, metas)
        print(f"[+] 导入 {len(docs)} 段文档 ({doc_type}): {filepath}")


def ingest_owasp_top10():
    """从外部 seed bundle 导入内置 OWASP 知识。"""
    ingest_seed_bundle("owasp")


def ingest_seed_bundle(bundle_name: str) -> int:
    """
    导入内置 seed bundle。
    seed 数据位于 knowledge/seeds/，通过 manifest.yaml 组织，避免把知识内容硬编码进 Python。
    """
    manifest = _load_seed_manifest()
    bundles = manifest.get("bundles", {})
    bundle = bundles.get(bundle_name)
    if not isinstance(bundle, dict):
        raise ValueError(f"未知 seed bundle: {bundle_name}")

    seed_glob = str(bundle.get("seed_glob", "") or "")
    doc_type = str(bundle.get("doc_type", bundle_name) or bundle_name)
    if not seed_glob:
        raise ValueError(f"seed bundle '{bundle_name}' 缺少 seed_glob 配置")

    seed_files = sorted(_SEEDS_DIR.glob(seed_glob))
    if not seed_files:
        print(f"[!] seed bundle '{bundle_name}' 未找到任何 seed 文件")
        return 0

    docs: list[str] = []
    ids: list[str] = []
    metas: list[dict[str, Any]] = []

    for seed_file in seed_files:
        metadata, body = _load_seed_document(seed_file)
        if not body:
            continue

        seed_id = str(metadata.get("id") or seed_file.stem)
        docs.append(body)
        ids.append(f"{bundle_name}_{seed_id}")
        metas.append({
            "type": doc_type,
            "bundle": bundle_name,
            "title": str(metadata.get("title") or seed_file.stem),
            "source": str(metadata.get("source") or bundle.get("title", bundle_name)),
            "source_url": str(metadata.get("source_url", "") or ""),
            "version": str(metadata.get("version") or bundle.get("version", "")),
            "tags": _normalize_tags(metadata.get("tags")),
        })

    if docs:
        _batch_upsert(docs, ids, metas)
        print(f"[+] 导入 {len(docs)} 条 seed 知识 ({bundle_name})")

    return len(docs)


def ensure_default_knowledge():
    """
    首次使用知识库时自动导入默认 seed。
    当前使用 config.yaml 的 knowledge.auto_ingest_owasp 开关。
    """
    global _AUTO_BOOTSTRAPPED
    if _AUTO_BOOTSTRAPPED:
        return

    _AUTO_BOOTSTRAPPED = True

    try:
        cfg = get_config()
        knowledge_cfg = cfg.get("knowledge", {}) if isinstance(cfg, dict) else {}
        should_ingest = bool(knowledge_cfg.get("auto_ingest_owasp", False))
        if not should_ingest:
            return

        if _collection.count() == 0:
            ingest_owasp_top10()
    except Exception:
        # 自动初始化失败时不阻塞主流程，用户仍可手动执行 ingest --owasp。
        return


# ------------------------------------------------------------------
# 内部工具
# ------------------------------------------------------------------


def _load_seed_manifest() -> dict[str, Any]:
    if not _MANIFEST_PATH.exists():
        raise FileNotFoundError(f"seed manifest 不存在: {_MANIFEST_PATH}")

    data = yaml.safe_load(_MANIFEST_PATH.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("seed manifest 格式错误，顶层必须是对象")
    return data


def _load_seed_document(path: Path) -> tuple[dict[str, Any], str]:
    text = path.read_text(encoding="utf-8").strip()
    metadata, body = _split_front_matter(text)
    if "title" not in metadata:
        metadata["title"] = path.stem.replace("_", " ")
    return metadata, body.strip()


def _split_front_matter(text: str) -> tuple[dict[str, Any], str]:
    if not text.startswith("---\n"):
        return {}, text

    lines = text.splitlines()
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            raw_meta = "\n".join(lines[1:idx])
            raw_body = "\n".join(lines[idx + 1:])
            meta = yaml.safe_load(raw_meta) or {}
            return (meta if isinstance(meta, dict) else {}), raw_body

    return {}, text


def _normalize_tags(value: Any) -> str:
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    if isinstance(value, str):
        return value
    return ""


def _batch_upsert(docs: list, ids: list, metas: list, batch_size: int = 100):
    for i in range(0, len(docs), batch_size):
        _collection.upsert(
            documents=docs[i:i + batch_size],
            ids=ids[i:i + batch_size],
            metadatas=metas[i:i + batch_size],
        )


def _extract_cve_id(item: dict) -> str:
    try:
        return item["cve"]["CVE_data_meta"]["ID"]
    except (KeyError, TypeError):
        try:
            return item["cve"]["id"]
        except (KeyError, TypeError):
            return "unknown"


def _extract_description(item: dict) -> str:
    try:
        descs = item["cve"]["description"]["description_data"]
        return " ".join(d["value"] for d in descs if d.get("lang") == "en")
    except (KeyError, TypeError):
        try:
            descs = item["cve"]["descriptions"]
            return " ".join(d["value"] for d in descs if d.get("lang") == "en")
        except (KeyError, TypeError):
            return ""


if __name__ == "__main__":
    import sys

    ingest_owasp_top10()
    for path in sys.argv[1:]:
        p = Path(path)
        if p.suffix == ".json":
            ingest_cve_json(str(p))
        elif p.suffix in (".md", ".txt"):
            ingest_markdown(str(p))
    print("知识库入库完成。")
