"""Reproduce the committed results: ``python scripts/run_scans.py`` (MOCK mode, no key, no network).

Runs the full attack library in-process against three configurations of the same target app
and writes ``results/<name>.json|md|html``, then ``results/compare.md`` (before vs after) and
``results/compare-ablation.md`` (before vs the ablation). Attacks and mitigations are untouched.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

import target.main as main_module
import target.prompts as prompts_module
from scanner.client import TargetClient
from scanner.loader import load_attacks
from scanner.report import (
    build_report,
    compare_reports,
    dump_report,
    render_comparison_markdown,
    render_html,
    render_markdown,
)
from scanner.runner import run_scan
from target.config import Settings
from target.guardrails import InputVerdict
from target.main import create_app

RESULTS = Path("results")
STAFF_TOKEN = "staff-test-token"  # synthetic, lab only


@contextmanager
def naive_model_no_soft_layers() -> Iterator[None]:
    """Secure target minus the heuristic / prompt-level layers (same as the ablation test)."""
    naive = prompts_module.SECURE_PROMPT.replace(prompts_module.HARDENED_MARKER, "")
    with (
        mock.patch.object(main_module, "SECURE_PROMPT", naive),
        mock.patch.object(main_module, "check_input", lambda *a, **k: InputVerdict(None)),
        mock.patch.object(prompts_module, "sanitize_untrusted", lambda body: body),
        mock.patch.object(prompts_module, "UNTRUSTED_OPEN", ""),
        mock.patch.object(prompts_module, "UNTRUSTED_CLOSE", ""),
    ):
        yield


def scan_to_files(name: str, secure: bool) -> dict:
    """Scan one configuration and write its json/md/html reports. Returns the report dict."""
    app = create_app(Settings(mock_mode=True, secure_mode=secure, staff_token=STAFF_TOKEN))
    with TestClient(app, base_url="http://localhost") as http:
        client = TargetClient("http://localhost", http=http)
        report = build_report(run_scan(client, load_attacks()))
    RESULTS.mkdir(exist_ok=True)
    dump_report(report, RESULTS / f"{name}.json")
    (RESULTS / f"{name}.md").write_text(render_markdown(report), encoding="utf-8")
    (RESULTS / f"{name}.html").write_text(render_html(report), encoding="utf-8")
    return report


def main() -> int:
    """Write all results; returns a process exit code."""
    before = scan_to_files("before", secure=False)
    after = scan_to_files("after", secure=True)
    with naive_model_no_soft_layers():
        ablation = scan_to_files("secure-naive-model", secure=True)
    for fname, other in (("compare.md", after), ("compare-ablation.md", ablation)):
        text = render_comparison_markdown(compare_reports(before, other))
        (RESULTS / fname).write_text(text, encoding="utf-8")
    print("wrote results/ (before, after, secure-naive-model, compare*.md)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
