"""
reporter — 渗透测试报告生成（Markdown + HTML）
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, BaseLoader


# ------------------------------------------------------------------
# Markdown 模板
# ------------------------------------------------------------------

_MD_TEMPLATE = """\
# PwnAgent 渗透测试报告

**生成时间**: {{ now }}
**测试目标**: {{ target }}
**授权范围**: {{ scope | join(', ') }}
**测试人员**: {{ tester }}
**报告标题**: {{ title }}

---

## 执行摘要

本次渗透测试对目标 `{{ target }}` 进行了系统性安全评估，历经信息收集、漏洞扫描、
漏洞验证和后渗透分析四个阶段。

| 严重程度 | 数量 |
|---------|------|
{% for sev, count in severity_counts.items() -%}
| {{ sev.upper() }} | {{ count }} |
{% endfor %}

---

## 目标信息

- **目标**: `{{ target }}`
- **开放端口**: {{ open_ports | length }} 个
{% for p in open_ports -%}
  - `{{ p.port }}/{{ p.proto }}` — {{ p.service }} {{ p.version }}
{% endfor %}

---

## 发现漏洞（按 CVSS 排序）

{% for f in findings -%}
### [{{ f.severity | upper }}] {{ f.title }}

- **目标**: `{{ f.target }}`
- **CVSS**: {{ f.cvss }}
- **描述**: {{ f.description }}

**复现步骤**:
```
{{ f.reproduction or '暂无' }}
```

**利用 Payload**:
```
{{ f.payload or '暂无' }}
```

**修复建议**: {{ f.remediation or '参考 OWASP 对应类型漏洞修复建议。' }}

{% if f.thought_excerpt %}
**Agent 发现过程（思维链节选）**:
> {{ f.thought_excerpt[:500] }}
{% endif %}

---
{% endfor %}

## 技术附录

### 完整思维链日志

{% for entry in thought_log -%}
**步骤 {{ loop.index }}** [{{ entry.phase }}] — 操作: `{{ entry.action }}`

> {{ entry.thought[:300] }}{% if entry.thought | length > 300 %}...{% endif %}

{% endfor %}
"""

# ------------------------------------------------------------------
# HTML 模板
# ------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ title }} — PwnAgent 报告</title>
<style>
  :root { --critical: #dc3545; --high: #fd7e14; --medium: #ffc107; --low: #28a745; --info: #6c757d; }
  body { font-family: 'Segoe UI', sans-serif; margin: 0; padding: 0; background: #f8f9fa; color: #212529; }
  .header { background: linear-gradient(135deg, #1a1a2e, #16213e); color: white; padding: 40px; }
  .header h1 { margin: 0 0 10px; font-size: 2em; }
  .header p { margin: 4px 0; opacity: 0.8; }
  .container { max-width: 1100px; margin: 0 auto; padding: 30px 20px; }
  .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 20px 0; }
  .summary-card { border-radius: 8px; padding: 20px; text-align: center; color: white; }
  .summary-card .count { font-size: 2.5em; font-weight: bold; }
  .summary-card .label { font-size: 0.85em; opacity: 0.9; }
  .card-critical { background: var(--critical); }
  .card-high { background: var(--high); }
  .card-medium { background: var(--medium); color: #212529; }
  .card-low { background: var(--low); }
  .card-info { background: var(--info); }
  .finding { background: white; border-radius: 8px; padding: 25px; margin: 15px 0; box-shadow: 0 2px 8px rgba(0,0,0,.08); border-left: 5px solid #dee2e6; }
  .finding.critical { border-left-color: var(--critical); }
  .finding.high { border-left-color: var(--high); }
  .finding.medium { border-left-color: var(--medium); }
  .finding.low { border-left-color: var(--low); }
  .finding-header { display: flex; align-items: center; gap: 12px; margin-bottom: 15px; }
  .severity-badge { padding: 3px 10px; border-radius: 12px; font-size: 0.75em; font-weight: bold; color: white; }
  .badge-critical { background: var(--critical); }
  .badge-high { background: var(--high); }
  .badge-medium { background: var(--medium); color: #212529; }
  .badge-low { background: var(--low); }
  .badge-info { background: var(--info); }
  .finding h3 { margin: 0; font-size: 1.1em; }
  pre { background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 6px; overflow-x: auto; font-size: 0.85em; }
  .thought-box { background: #f3e8ff; border: 1px solid #c4b5fd; border-radius: 6px; padding: 15px; margin-top: 15px; }
  .thought-box h4 { margin: 0 0 8px; color: #7c3aed; font-size: 0.9em; }
  .thought-box p { margin: 0; font-size: 0.85em; color: #4c1d95; font-style: italic; }
  .timeline { margin: 30px 0; }
  .timeline-item { display: flex; gap: 15px; margin-bottom: 20px; }
  .timeline-dot { width: 12px; height: 12px; border-radius: 50%; background: #6c757d; margin-top: 5px; flex-shrink: 0; }
  .timeline-content { flex: 1; }
  .timeline-phase { font-size: 0.75em; color: #6c757d; margin-bottom: 4px; }
  .timeline-action { font-weight: bold; font-size: 0.9em; }
  .timeline-thought { font-size: 0.85em; color: #495057; margin-top: 6px; }
  section { margin: 30px 0; }
  h2 { color: #1a1a2e; border-bottom: 2px solid #dee2e6; padding-bottom: 8px; }
</style>
</head>
<body>
<div class="header">
  <h1>{{ title }}</h1>
  <p>目标: <strong>{{ target }}</strong></p>
  <p>测试人员: {{ tester }} &nbsp;|&nbsp; 生成时间: {{ now }}</p>
</div>
<div class="container">
  <section>
    <h2>漏洞摘要</h2>
    <div class="summary-grid">
      {% for sev in ['critical', 'high', 'medium', 'low', 'info'] -%}
      <div class="summary-card card-{{ sev }}">
        <div class="count">{{ severity_counts.get(sev, 0) }}</div>
        <div class="label">{{ sev.upper() }}</div>
      </div>
      {% endfor %}
    </div>
  </section>

  <section>
    <h2>发现漏洞</h2>
    {% for f in findings -%}
    <div class="finding {{ f.severity }}">
      <div class="finding-header">
        <span class="severity-badge badge-{{ f.severity }}">{{ f.severity.upper() }}</span>
        <h3>{{ f.title }}</h3>
        <span style="margin-left:auto;color:#6c757d;font-size:.85em">CVSS {{ f.cvss }}</span>
      </div>
      <p><strong>目标:</strong> <code>{{ f.target }}</code></p>
      <p>{{ f.description }}</p>
      {% if f.reproduction %}
      <p><strong>复现步骤:</strong></p>
      <pre>{{ f.reproduction }}</pre>
      {% endif %}
      {% if f.payload %}
      <p><strong>Payload:</strong></p>
      <pre>{{ f.payload }}</pre>
      {% endif %}
      <p><strong>修复建议:</strong> {{ f.remediation or 'N/A' }}</p>
      {% if f.thought_excerpt %}
      <div class="thought-box">
        <h4>AI 发现过程（思维链节选）</h4>
        <p>{{ f.thought_excerpt[:400] }}</p>
      </div>
      {% endif %}
    </div>
    {% endfor %}
  </section>

  <section>
    <h2>Agent 决策时间线</h2>
    <div class="timeline">
      {% for entry in thought_log -%}
      <div class="timeline-item">
        <div class="timeline-dot"></div>
        <div class="timeline-content">
          <div class="timeline-phase">{{ entry.phase }}</div>
          <div class="timeline-action">{{ entry.action }}</div>
          <div class="timeline-thought">{{ entry.thought[:200] }}{% if entry.thought|length > 200 %}...{% endif %}</div>
        </div>
      </div>
      {% endfor %}
    </div>
  </section>
</div>
</body>
</html>
"""


# ------------------------------------------------------------------
# 主接口
# ------------------------------------------------------------------

def generate_report(
    session,
    output_dir: str = "./reports",
    title: str = "渗透测试报告",
    tester: str = "PwnAgent",
) -> dict[str, str]:
    """生成 Markdown 和 HTML 报告，返回文件路径字典。"""
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    ctx = _build_context(session, title, tester)
    env = Environment(loader=BaseLoader())

    # Markdown
    md_content = env.from_string(_MD_TEMPLATE).render(**ctx)
    md_path = Path(output_dir) / f"report_{session.target.replace('://', '_').replace('/', '_')}.md"
    md_path.write_text(md_content, encoding="utf-8")

    # HTML
    html_content = env.from_string(_HTML_TEMPLATE).render(**ctx)
    html_path = md_path.with_suffix(".html")
    html_path.write_text(html_content, encoding="utf-8")

    return {"markdown": str(md_path), "html": str(html_path)}


def generate_report_from_db(
    session_id: str,
    session_data: dict,
    mem,
    output_dir: str = "./reports",
) -> dict[str, str]:
    """从数据库数据重建报告（用于 `pwn report` 命令）。"""
    from core.state_machine import Finding, PentestSession

    scope = json.loads(session_data.get("scope", "[]"))
    session = PentestSession(
        target=session_data["target"],
        scope=scope,
    )
    # 加载 findings
    for row in mem.get_findings(session_id):
        f = Finding(
            title=row["title"],
            severity=row["severity"],
            target=row["target"],
            description=row.get("description", ""),
            payload=row.get("payload", ""),
            reproduction=row.get("reproduction", ""),
            remediation=row.get("remediation", ""),
            cvss=row.get("cvss", 0.0),
            thought_excerpt=row.get("thought_excerpt", ""),
        )
        session.findings.append(f)
    # 加载思维链
    session.thought_log = mem.get_thought_log(session_id)

    return generate_report(session, output_dir)


# ------------------------------------------------------------------
# 内部工具
# ------------------------------------------------------------------

def _build_context(session, title: str, tester: str) -> dict[str, Any]:
    findings_sorted = sorted(
        session.findings,
        key=lambda f: f.cvss,
        reverse=True,
    )
    severity_counts = session._findings_by_severity()
    open_ports = session.attack_surface.get("open_ports", [])

    return {
        "now": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": session.target,
        "scope": session.scope,
        "title": title,
        "tester": tester,
        "severity_counts": severity_counts,
        "findings": findings_sorted,
        "open_ports": open_ports,
        "thought_log": session.thought_log,
    }
