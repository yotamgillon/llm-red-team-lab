"""End-to-end: before/after/ablation scans of scripts/run_scans.py on the in-process target."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import run_scans  # noqa: E402


def test_before_after_ablation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(run_scans, "RESULTS", tmp_path)
    assert run_scans.main() == 0
    names = {p.name for p in tmp_path.iterdir()}
    for stem in ("before", "after", "secure-naive-model"):
        assert {f"{stem}.json", f"{stem}.md", f"{stem}.html"} <= names
    assert {"compare.md", "compare-ablation.md"} <= names

    import json

    def summary(stem: str) -> dict:
        return json.loads((tmp_path / f"{stem}.json").read_text())["summary"]

    assert summary("before")["vulnerable"] == summary("before")["total"] == 33
    after = summary("after")
    assert after["vulnerable"] == 0
    assert summary("secure-naive-model")["vulnerable"] == 8
    assert "| fixed | 33 |" in (tmp_path / "compare.md").read_text()
