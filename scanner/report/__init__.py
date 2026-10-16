"""Reporting: versioned JSON results, Markdown and HTML reports, and result comparison."""

from scanner.report.compare import Comparison, compare_reports, render_comparison_markdown
from scanner.report.html import render_html
from scanner.report.jsonout import (
    SCHEMA_VERSION,
    ReportError,
    build_report,
    dump_report,
    load_report,
)
from scanner.report.markdown import render_markdown

__all__ = [
    "SCHEMA_VERSION",
    "Comparison",
    "ReportError",
    "build_report",
    "compare_reports",
    "dump_report",
    "load_report",
    "render_comparison_markdown",
    "render_html",
    "render_markdown",
]
