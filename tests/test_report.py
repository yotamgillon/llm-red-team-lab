from __future__ import annotations

import json
from html.parser import HTMLParser
from pathlib import Path

import pytest

from scanner.detectors.html_script import HtmlScriptDetector
from scanner.report import (
    ReportError,
    build_report,
    dump_report,
    load_report,
    render_html,
    render_markdown,
)
from scanner.report.jsonout import MAX_EVIDENCE_CHARS, clean_evidence
from tests.report_helpers import result, scan
from tests.scanner_helpers import PAYLOAD, make_attack, resp

EVIL = '<script>alert("xss")</script><img src=x onerror=alert(1)>'


def sample():
    return scan(
        result("LLM01-001", severity="critical", evidence="said NOVA-CANARY-7"),
        result("LLM07-001", severity="high"),
        result("LLM05-001", status="not_vulnerable", severity="medium"),
        result("LLM10-001", status="error", severity="low", error="timeout"),
    )


def test_json_schema_and_summary(tmp_path: Path) -> None:
    report = build_report(sample())
    assert report["schema_version"] == 1
    assert report["summary"]["total"] == 4
    assert report["summary"]["vulnerable"] == 2
    assert report["summary"]["vulnerable_by_severity"]["critical"] == 1
    assert report["summary"]["by_category"]["LLM01"] == {"total": 1, "vulnerable": 1}
    assert report["started_at"] == "2026-01-02T03:04:05+00:00"
    path = tmp_path / "r.json"
    dump_report(report, path)
    assert load_report(path) == report


def test_load_rejects_other_schema_versions(tmp_path: Path) -> None:
    path = tmp_path / "r.json"
    path.write_text(json.dumps({"schema_version": 2, "results": []}))
    with pytest.raises(ReportError, match="unsupported schema_version"):
        load_report(path)


@pytest.mark.parametrize(
    "content", ["not json", "[]", '{"schema_version": 1}', '{"schema_version": 1, "results": [{}]}']
)
def test_load_rejects_malformed(tmp_path: Path, content: str) -> None:
    path = tmp_path / "r.json"
    path.write_text(content)
    with pytest.raises(ReportError):
        load_report(path)


def test_evidence_is_redacted_and_truncated() -> None:
    text = "key sk-LAB-abcdef123456 ssn 900-12-3456 card 4111 1111 1111 1111 ok"
    cleaned = clean_evidence(text)
    assert "abcdef123456" not in cleaned and "900-12-3456" not in cleaned
    assert "4111" not in cleaned and "ok" in cleaned
    assert len(clean_evidence("x" * 5000)) == MAX_EVIDENCE_CHARS


def test_markdown_golden() -> None:
    md = render_markdown(build_report(sample()))
    assert md == (Path(__file__).parent / "fixtures" / "report_golden.md").read_text()


def test_json_golden() -> None:
    got = json.dumps(build_report(sample()), indent=2, ensure_ascii=False) + "\n"
    assert got == (Path(__file__).parent / "fixtures" / "report_golden.json").read_text()


def test_markdown_evidence_cannot_break_out() -> None:
    report = build_report(scan(result("LLM05-001", evidence="``` | <b>x</b>\n# heading")))
    md = render_markdown(report)
    assert "````text" in md  # fence longer than the backtick run in the evidence


class _Tags(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.event_attrs: list[str] = []
        self.urls: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)
        for name, value in attrs:
            if name.startswith("on"):
                self.event_attrs.append(name)
            if value and ("http://" in value or "https://" in value):
                self.urls.append(value)


def test_html_escapes_script_in_evidence_and_never_executes() -> None:
    hostile = result(
        "LLM05-001",
        title=EVIL,
        evidence=EVIL,
        remediation=EVIL,
    )
    html = render_html(build_report(scan(hostile, target=f"http://localhost:8000/{EVIL}")))
    assert "<script" not in html.lower()
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "&lt;script&gt;" in html
    parser = _Tags()
    parser.feed(html)
    assert "script" not in parser.tags and "img" not in parser.tags
    assert parser.event_attrs == []
    # The project's own active-content detector finds nothing in the rendered page.
    verdict = HtmlScriptDetector({}).evaluate(
        make_attack("html_script"), PAYLOAD, resp(reply_html=html)
    )
    assert not verdict.fired, verdict.evidence


def test_html_is_self_contained() -> None:
    html = render_html(build_report(sample()))
    parser = _Tags()
    parser.feed(html)
    assert parser.urls == []
    assert not {"script", "link", "img", "iframe", "object", "embed"} & set(parser.tags)
    assert "@import" not in html and "url(" not in html
    assert "default-src 'none'" in html
    assert "<svg" in html and "Category summary" in html and "LLM01" in html


def test_html_chart_scales_with_counts() -> None:
    from scanner.report.html import severity_chart_rows

    rows = {r["severity"]: r for r in severity_chart_rows({"critical": 4, "high": 2})}
    assert rows["critical"]["width"] == 2 * rows["high"]["width"] > 0
    assert rows["low"]["width"] == 0
