from __future__ import annotations

import httpx
import pytest
from typer.testing import CliRunner

from scanner.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Any real HTTP request during these tests is a failure."""

    def boom(*a: object, **k: object) -> None:
        raise AssertionError("network I/O attempted")

    monkeypatch.setattr(httpx.Client, "send", boom)
    monkeypatch.setattr(httpx.Client, "request", boom)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com",
        "http://localhost.evil.com",
        "http://localhost@evil.com",
        "http://127.0.0.1.evil.com",
    ],
)
def test_scan_refuses_non_localhost_before_any_network_io(url: str) -> None:
    result = runner.invoke(app, ["scan", "--target", url])
    assert result.exit_code == 2
    assert "refusing target" in result.output


def test_scan_rejects_unknown_category() -> None:
    result = runner.invoke(app, ["scan", "--categories", "LLM99"])
    assert result.exit_code == 2 and "unknown categories" in result.output


def test_scan_unreachable_target_is_usage_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.undo()  # allow the real (failing) connection to a closed local port
    result = runner.invoke(app, ["scan", "--target", "http://127.0.0.1:1", "--timeout", "1"])
    assert result.exit_code == 2 and "cannot reach target" in result.output


def test_judge_flag_without_key_is_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = runner.invoke(app, ["scan", "--judge"])
    assert result.exit_code == 2 and "ANTHROPIC_API_KEY" in result.output


def test_list_attacks_and_validate() -> None:
    listed = runner.invoke(app, ["list-attacks"])
    assert (
        listed.exit_code == 0 and "LLM07-001" in listed.output and "10 attack(s)" in listed.output
    )
    only = runner.invoke(app, ["list-attacks", "--category", "LLM05"])
    assert "LLM05-001" in only.output and "LLM07-001" not in only.output
    assert "OK: 10 attacks valid" in runner.invoke(app, ["validate"]).output


def test_validate_reports_bad_library(tmp_path) -> None:
    (tmp_path / "bad.yaml").write_text("- id: x\n", encoding="utf-8")
    result = runner.invoke(app, ["validate", "--attacks-dir", str(tmp_path)])
    assert result.exit_code == 2 and "bad.yaml" in result.output
