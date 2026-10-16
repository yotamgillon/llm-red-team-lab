"""Diff two JSON results (before/after)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from scanner.report.jsonout import SEVERITIES
from scanner.report.markdown import md_cell

FIXED = "fixed"
STILL = "still vulnerable"
REGRESSED = "regressed"
NEW = "new"
REMOVED = "removed"
UNCHANGED = "unchanged"


@dataclass
class Comparison:
    """Per-attack change statuses plus severity totals before and after."""

    entries: list[dict[str, Any]] = field(default_factory=list)
    severity_before: dict[str, int] = field(default_factory=dict)
    severity_after: dict[str, int] = field(default_factory=dict)

    def with_status(self, status: str) -> list[dict[str, Any]]:
        """Entries having ``status``."""
        return [e for e in self.entries if e["change"] == status]

    @property
    def has_regression(self) -> bool:
        """True if an attack became vulnerable or a vulnerable attack is new."""
        return bool(self.with_status(REGRESSED)) or any(
            e["after"] == "vulnerable" for e in self.with_status(NEW)
        )

    def to_dict(self) -> dict[str, Any]:
        """JSON-friendly form."""
        return {
            "entries": self.entries,
            "severity_before": self.severity_before,
            "severity_after": self.severity_after,
            "has_regression": self.has_regression,
        }


def _classify(before: str | None, after: str | None) -> str:
    if before is None:
        return NEW
    if after is None:
        return REMOVED
    if before == "vulnerable":
        return STILL if after == "vulnerable" else FIXED
    return REGRESSED if after == "vulnerable" else UNCHANGED


def compare_reports(before: dict[str, Any], after: dict[str, Any]) -> Comparison:
    """Compare two loaded reports attack by attack (matched on ``attack_id``)."""
    b = {r["attack_id"]: r for r in before["results"]}
    a = {r["attack_id"]: r for r in after["results"]}
    entries = []
    for attack_id in sorted(b.keys() | a.keys()):
        rb, ra = b.get(attack_id), a.get(attack_id)
        ref = ra or rb
        assert ref is not None
        entries.append(
            {
                "attack_id": attack_id,
                "title": ref["title"],
                "severity": ref["severity"],
                "before": rb["status"] if rb else None,
                "after": ra["status"] if ra else None,
                "change": _classify(rb["status"] if rb else None, ra["status"] if ra else None),
            }
        )
    return Comparison(
        entries=entries,
        severity_before=dict(before["summary"]["vulnerable_by_severity"]),
        severity_after=dict(after["summary"]["vulnerable_by_severity"]),
    )


def render_comparison_markdown(cmp: Comparison) -> str:
    """Render a comparison as Markdown tables."""
    counts = {s: len(cmp.with_status(s)) for s in (FIXED, STILL, REGRESSED, NEW, REMOVED)}
    lines = [
        "# Before / after comparison",
        "",
        "| Change | Attacks |",
        "|---|---|",
        *[f"| {k} | {v} |" for k, v in counts.items()],
        "",
        "## Vulnerable attacks by severity",
        "",
        "| Severity | Before | After | Delta |",
        "|---|---|---|---|",
    ]
    for sev in SEVERITIES:
        b, a = cmp.severity_before.get(sev, 0), cmp.severity_after.get(sev, 0)
        lines.append(f"| {sev} | {b} | {a} | {a - b:+d} |")
    lines += ["", "## Per attack", "", "| Attack | Title | Severity | Before | After | Change |"]
    lines.append("|---|---|---|---|---|---|")
    for e in cmp.entries:
        if e["change"] == UNCHANGED:
            continue
        lines.append(
            f"| {md_cell(e['attack_id'])} | {md_cell(e['title'])} | {e['severity']} "
            f"| {e['before'] or '-'} | {e['after'] or '-'} | {e['change']} |"
        )
    return "\n".join(lines) + "\n"
