"""
knowledge/ingest — CVE/OWASP/Writeup 文档入库
"""
import json
from pathlib import Path

import chromadb

_DB_PATH = str(Path(__file__).parent / "db")
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
    # 按 ## 标题切分
    import re
    sections = re.split(r'\n#{1,3} ', content)
    sections = [s.strip() for s in sections if len(s.strip()) > 100]

    docs = sections
    ids = [f"{doc_type}_{Path(filepath).stem}_{i}" for i in range(len(sections))]
    metas = [{"type": doc_type, "source": str(filepath)} for _ in sections]

    if docs:
        _batch_upsert(docs, ids, metas)
        print(f"[+] 导入 {len(docs)} 段文档 ({doc_type}): {filepath}")


def ingest_owasp_top10():
    """内置 OWASP Top 10 知识。"""
    owasp_entries = [
        {
            "id": "A01_broken_access_control",
            "title": "A01:2021 – 访问控制失效",
            "content": (
                "访问控制失效是最常见的 Web 安全漏洞。\n"
                "常见场景：IDOR（直接对象引用）、越权访问、目录遍历、CORS 配置错误、\n"
                "以 URL 参数更改其他用户 ID、强制浏览未授权页面。\n"
                "测试方法：修改 URL 参数（user_id）、越权访问其他账户数据、\n"
                "访问 /admin 路径、测试 HTTP 方法（PUT/DELETE）。\n"
                "修复：服务端实施访问控制、默认拒绝、记录访问失败。"
            ),
        },
        {
            "id": "A02_cryptographic_failures",
            "title": "A02:2021 – 加密失败",
            "content": (
                "敏感数据明文传输或存储，或使用弱加密算法。\n"
                "常见场景：HTTP 传输密码、MD5/SHA1 存储密码、弱 TLS 配置、\n"
                "硬编码密钥、未加密数据库字段。\n"
                "测试方法：抓包检查是否 HTTPS、检查响应头（HSTS）、\n"
                "查找硬编码凭证（git 历史、.env 文件）。"
            ),
        },
        {
            "id": "A03_injection",
            "title": "A03:2021 – 注入",
            "content": (
                "SQL 注入、NoSQL 注入、OS 命令注入、LDAP 注入。\n"
                "SQL 注入 Payload：' OR '1'='1、1; DROP TABLE users--、\n"
                "UNION SELECT 1,2,3--\n"
                "检测方法：在参数末尾加单引号看是否报错、使用 sqlmap、\n"
                "检查错误信息是否暴露数据库类型。\n"
                "修复：参数化查询、ORM、输入验证。"
            ),
        },
        {
            "id": "A07_xss",
            "title": "A07:2021 – 跨站脚本 (XSS)",
            "content": (
                "反射型 XSS：用户输入直接回显到页面。\n"
                "存储型 XSS：恶意脚本存入数据库，所有访问用户受影响。\n"
                "DOM 型 XSS：JavaScript 直接处理用户可控数据写入 DOM。\n"
                "Payload：<script>alert(1)</script>、\n"
                "<img src=x onerror=alert(1)>、\n"
                "javascript:alert(document.cookie)\n"
                "修复：HTML 实体编码、CSP、DOMPurify。"
            ),
        },
        {
            "id": "A08_ssrf",
            "title": "A08:2021 – SSRF",
            "content": (
                "服务端请求伪造，攻击者控制服务器发出的请求。\n"
                "常见入口：URL 参数（url=、callback=、redirect=）、Webhook、\n"
                "图片/文件 URL 导入。\n"
                "测试 Payload：http://169.254.169.254/latest/meta-data/（AWS）\n"
                "http://127.0.0.1:22/、http://internal-service/\n"
                "修复：白名单验证 URL、禁止访问内网地址、DNS 重绑定防护。"
            ),
        },
    ]

    docs = [e["content"] for e in owasp_entries]
    ids = [e["id"] for e in owasp_entries]
    metas = [{"type": "owasp", "title": e["title"]} for e in owasp_entries]

    _batch_upsert(docs, ids, metas)
    print(f"[+] 导入 {len(docs)} 条 OWASP Top 10 条目")


# ------------------------------------------------------------------
# 内部工具
# ------------------------------------------------------------------

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
