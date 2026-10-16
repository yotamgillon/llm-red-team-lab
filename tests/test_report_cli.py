from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

import scanner.cli as cli
from scanner.client import TargetClient
from scanner.report import build_report, dump_report
from target.config import Settings
from target.main import create_app
from tests.report_helpers import result, scan

runner = CliRunner()


@pytest.fixture
def in_process_target(monkeypatch: pytest.MonkeyPatch):
    """Make `redteam scan` talk to an in-process vulnerable MOCK target (no sockets)."""
    with TestClient(
        create_app(Settings(mock_mode=True, secure_mode=False)), base_url="http://localhost"
    ) as http:
        monkeypatch.setattr(cli, "TargetClient", lambda url, **kw: TargetClient(url, http=http))
        yield


def test_scan_writes_all_three_reports(in_process_target, tmp_path: Path) -> None:
    out = runner.invoke(
        cli.app,
        ["scan", "--target", "http://localhost:8000", "--categories", "LLM05",
         "--out", str(tmp_path), "--name", "run"],
    )  # fmt: skip
    assert out.exit_code == 1  # findings present
    assert sorted(p.name for p in tmp_path.iterdir()) == ["run.html", "run.json", "run.md"]
    data = json.loads((tmp_path / "run.json").read_text())
    assert data["schema_version"] == 1 and data["summary"]["vulnerable"] == 4
    html = (tmp_path / "run.html").read_text()
    assert "<script" not in html.lower()  # LLM05 attacks echo <script>/<img onerror> payloads


def test_scan_rejects_unknown_format_before_network(tmp_path: Path) -> None:
    out = runner.invoke(cli.app, ["scan", "--format", "pdf", "--out", str(tmp_path)])
    assert out.exit_code == 2 and "unknown format" in out.output


def test_scan_rejects_path_in_name(in_process_target, tmp_path: Path) -> None:
    out = runner.invoke(
        cli.app,
        ["scan", "--categories", "LLM05", "--out", str(tmp_path), "--name", "../evil"],
    )
    assert out.exit_code == 2 and not (tmp_path.parent / "evil.json").exists()


def test_report_command_renders_from_json(tmp_path: Path) -> None:
    src = tmp_path / "in.json"
    dump_report(build_report(scan(result("LLM01-001"))), src)
    out = runner.invoke(cli.app, ["report", str(src), "--out", str(tmp_path / "o")])
    assert out.exit_code == 0
    assert (tmp_path / "o" / "in.md").exists() and (tmp_path / "o" / "in.html").exists()
