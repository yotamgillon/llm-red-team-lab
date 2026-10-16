from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from scanner.cli import app
from scanner.report import (
    build_report,
    compare_reports,
    dump_report,
    render_comparison_markdown,
)
from tests.report_helpers import result, scan

runner = CliRunner()


def _cmp(before, after):
    return compare_reports(build_report(scan(*before)), build_report(scan(*after)))


def _changes(c) -> dict[str, str]:
    return {e["attack_id"]: e["change"] for e in c.entries}


def test_every_status() -> None:
    c = _cmp(
        [
            result("LLM01-001"),
            result("LLM01-002"),
            result("LLM02-001", status="not_vulnerable"),
            result("LLM02-002", status="not_vulnerable"),
            result("LLM05-001"),
        ],
        [
            result("LLM01-001", status="not_vulnerable"),
            result("LLM01-002"),
            result("LLM02-001"),
            result("LLM02-002", status="not_vulnerable"),
            result("LLM06-001"),
        ],
    )
    assert _changes(c) == {
        "LLM01-001": "fixed",
        "LLM01-002": "still vulnerable",
        "LLM02-001": "regressed",
        "LLM02-002": "unchanged",
        "LLM05-001": "removed",
        "LLM06-001": "new",
    }
    assert c.has_regression


def test_new_non_vulnerable_is_not_a_regression() -> None:
    c = _cmp([result("LLM01-001")], [result("LLM01-001"), result("LLM06-001", "not_vulnerable")])
    assert _changes(c)["LLM06-001"] == "new" and not c.has_regression


def test_severity_totals_delta_in_markdown() -> None:
    before = [result("LLM01-001", severity="critical"), result("LLM01-002", severity="high")]
    after = [
        result("LLM01-001", "not_vulnerable", "critical"),
        result("LLM01-002", severity="high"),
    ]
    md = render_comparison_markdown(_cmp(before, after))
    assert "| critical | 1 | 0 | -1 |" in md
    assert "| high | 1 | 1 | +0 |" in md
    assert "| fixed | 1 |" in md and "| LLM01-001 |" in md


def _write(tmp_path: Path, name: str, *results) -> Path:
    path = tmp_path / name
    dump_report(build_report(scan(*results)), path)
    return path


def test_cli_compare_table_and_fail_on_regression(tmp_path: Path) -> None:
    before = _write(
        tmp_path, "before.json", result("LLM01-001"), result("LLM02-001", "not_vulnerable")
    )
    after = _write(
        tmp_path, "after.json", result("LLM01-001", "not_vulnerable"), result("LLM02-001")
    )
    out = runner.invoke(app, ["compare", str(before), str(after)])
    assert out.exit_code == 0
    assert "| LLM01-001 |" in out.output and "fixed" in out.output and "regressed" in out.output
    failing = runner.invoke(app, ["compare", str(before), str(after), "--fail-on-regression"])
    assert failing.exit_code == 1
    as_json = runner.invoke(app, ["compare", str(before), str(after), "--format", "json"])
    assert json.loads(as_json.output)["has_regression"] is True


def test_cli_compare_clean_run_passes(tmp_path: Path) -> None:
    before = _write(tmp_path, "b.json", result("LLM01-001"))
    after = _write(tmp_path, "a.json", result("LLM01-001", "not_vulnerable"))
    assert (
        runner.invoke(app, ["compare", str(before), str(after), "--fail-on-regression"]).exit_code
        == 0
    )


def test_cli_compare_rejects_wrong_schema_version(tmp_path: Path) -> None:
    good = _write(tmp_path, "g.json", result("LLM01-001"))
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema_version": 99, "results": []}))
    out = runner.invoke(app, ["compare", str(good), str(bad)])
    assert out.exit_code == 2 and "unsupported schema_version" in out.output


@pytest.mark.parametrize("fmt", ["xml", ""])
def test_cli_compare_rejects_bad_format(tmp_path: Path, fmt: str) -> None:
    f = _write(tmp_path, "f.json", result("LLM01-001"))
    assert runner.invoke(app, ["compare", str(f), str(f), "--format", fmt]).exit_code == 2
