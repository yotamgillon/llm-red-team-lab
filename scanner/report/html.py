"""Single-file HTML report.

The page is self-contained (inline CSS and an inline SVG chart, no scripts, no external
requests) and every value goes through Jinja2 autoescaping, because evidence is untrusted
target output that may contain HTML or script.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from scanner.report.jsonout import SEVERITIES

TEMPLATES_DIR = Path(__file__).parent / "templates"
CHART_WIDTH = 480
BAR_HEIGHT = 22
BAR_GAP = 8
LABEL_WIDTH = 70
COUNT_WIDTH = 40

_env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=select_autoescape(default=True, default_for_string=True),
)


def severity_chart_rows(counts: dict[str, int]) -> list[dict[str, Any]]:
    """Geometry for the SVG bar chart. Only numbers and fixed severity names are used."""
    peak = max(counts.values(), default=0) or 1
    span = CHART_WIDTH - LABEL_WIDTH - COUNT_WIDTH
    return [
        {
            "severity": sev,
            "count": counts.get(sev, 0),
            "y": i * (BAR_HEIGHT + BAR_GAP),
            "width": round(span * counts.get(sev, 0) / peak),
        }
        for i, sev in enumerate(SEVERITIES)
    ]


def render_html(report: dict[str, Any]) -> str:
    """Render a schema-v1 report dict as one self-contained HTML document."""
    rows = severity_chart_rows(report["summary"]["vulnerable_by_severity"])
    return _env.get_template("report.html.j2").render(
        report=report,
        summary=report["summary"],
        chart_rows=rows,
        chart_width=CHART_WIDTH,
        chart_height=len(rows) * (BAR_HEIGHT + BAR_GAP),
        bar_height=BAR_HEIGHT,
        label_width=LABEL_WIDTH,
        findings=[r for r in report["results"] if r["status"] == "vulnerable"],
        others=[r for r in report["results"] if r["status"] != "vulnerable"],
    )
