"""Markdown report."""

from __future__ import annotations

import re
from typing import Any

from scanner.report.jsonout import SEVERITIES

_SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}


def md_cell(text: object) -> str:
    """Make ``text`` safe for a single-line Markdown table cell."""
    out = " ".join(str(text).split())
    for ch in ("\\", "|", "`", "<", ">", "*", "_", "[", "]"):
        out = out.replace(ch, "\\" + ch)
    return out


def md_code_block(text: str) -> str:
    """Fence ``text`` so that nothing inside can close the fence early."""
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{text}\n{fence}"


def render_markdown(report: dict[str, Any]) -> str:
    """Render a schema-v1 report dict as Markdown."""
    s = report["summary"]
    lines = [
        "# LLM Red Team Report",
        "",
        f"- **Target:** {md_cell(report['target'])}",
        f"- **Started:** {md_cell(report['started_at'])}",
        f"- **Mode:** {md_cell(', '.join(f'{k}={v}' for k, v in report['mode'].items()) or 'n/a')}",
        f"- **Result:** {s['vulnerable']} vulnerable of {s['total']} attacks",
        "",
        "## Severity summary (vulnerable attacks)",
        "",
        "| Severity | Count |",
        "|---|---|",
        *[f"| {sev} | {s['vulnerable_by_severity'][sev]} |" for sev in SEVERITIES],
        "",
        "## Category summary",
        "",
        "| Category | Attacks | Vulnerable |",
        "|---|---|---|",
        *[
            f"| {md_cell(cat)} | {c['total']} | {c['vulnerable']} |"
            for cat, c in s["by_category"].items()
        ],
        "",
        "## Findings",
        "",
    ]
    findings = sorted(
        (r for r in report["results"] if r["status"] == "vulnerable"),
        key=lambda r: (_SEVERITY_ORDER[r["severity"]], r["attack_id"]),
    )
    if not findings:
        lines += ["No vulnerable attacks.", ""]
    for r in findings:
        lines += [
            f"### {md_cell(r['attack_id'])} - {md_cell(r['title'])}",
            "",
            f"- **Severity:** {r['severity']}",
            f"- **Payload:** {md_cell(r.get('payload') or '-')}",
            f"- **Confidence:** {r.get('confidence', 0):.2f}",
            f"- **Remediation:** {md_cell(r.get('remediation') or '-')}",
            "",
            "Evidence:",
            "",
            md_code_block(r.get("evidence") or ""),
            "",
        ]
    others = [r for r in report["results"] if r["status"] != "vulnerable"]
    lines += ["## Other results", ""]
    if others:
        lines += ["| Attack | Severity | Status | Note |", "|---|---|---|---|"]
        lines += [
            f"| {md_cell(r['attack_id'])} | {r['severity']} | {r['status']} "
            f"| {md_cell(r.get('error') or r.get('evidence') or '')} |"
            for r in others
        ]
    else:
        lines.append("None.")
    return "\n".join(lines) + "\n"
