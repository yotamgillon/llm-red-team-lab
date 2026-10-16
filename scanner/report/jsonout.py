"""JSON results (schema v1): build from a scan, write, and strictly load."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from scanner.models import CATEGORIES, ScanResult, Severity

SCHEMA_VERSION = 1
MAX_EVIDENCE_CHARS = 300
SEVERITIES: tuple[str, ...] = tuple(s.value for s in Severity)
STATUSES: tuple[str, ...] = ("vulnerable", "not_vulnerable", "inconclusive", "error")

_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b(?:sk|pk|key|tok)[-_][A-Za-z0-9_-]{8,}\b", re.I), "[REDACTED-KEY]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED-SSN]"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "[REDACTED-NUMBER]"),
)


class ReportError(ValueError):
    """Raised when a results file is malformed or has an unsupported schema version."""


def clean_evidence(text: str, limit: int = MAX_EVIDENCE_CHARS) -> str:
    """Redact key/SSN/card-like strings, collapse whitespace and truncate to ``limit`` chars."""
    out = " ".join((text or "").split())
    for pattern, replacement in _REDACTIONS:
        out = pattern.sub(replacement, out)
    return out if len(out) <= limit else out[: limit - 1] + "…"


def _zero_counts(keys: tuple[str, ...]) -> dict[str, int]:
    return {k: 0 for k in keys}


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute totals from result dicts: by status, by severity and by category (vulnerable)."""
    by_status = _zero_counts(STATUSES)
    by_severity = _zero_counts(SEVERITIES)
    by_category = {c: {"total": 0, "vulnerable": 0} for c in CATEGORIES}
    for r in results:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
        cat = by_category.setdefault(r["category"], {"total": 0, "vulnerable": 0})
        cat["total"] += 1
        if r["status"] == "vulnerable":
            cat["vulnerable"] += 1
            by_severity[r["severity"]] = by_severity.get(r["severity"], 0) + 1
    by_category = {k: v for k, v in by_category.items() if v["total"]}
    return {
        "total": len(results),
        "vulnerable": by_status["vulnerable"],
        "by_status": by_status,
        "vulnerable_by_severity": by_severity,
        "by_category": by_category,
    }


def build_report(scan: ScanResult) -> dict[str, Any]:
    """Convert a :class:`ScanResult` into the schema-v1 report dict (evidence redacted)."""
    results = [
        {
            "attack_id": r.attack_id,
            "category": r.category,
            "title": r.title,
            "severity": r.severity.value,
            "status": r.status,
            "payload": r.payload,
            "evidence": clean_evidence(r.evidence),
            "confidence": r.confidence,
            "remediation": r.remediation,
            "error": clean_evidence(r.error or "") or None,
        }
        for r in scan.results
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": "redteam",
        "target": scan.target,
        "mode": scan.mode,
        "started_at": scan.started_at.isoformat(),
        "summary": summarize(results),
        "results": results,
    }


def dump_report(report: dict[str, Any], path: Path) -> None:
    """Write ``report`` as pretty, key-stable JSON."""
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


_REQUIRED_RESULT_KEYS = ("attack_id", "category", "title", "severity", "status")


def load_report(path: Path) -> dict[str, Any]:
    """Load and validate a results file. Rejects other schema versions and malformed content."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReportError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict) or "schema_version" not in data:
        raise ReportError(f"{path}: not a redteam results file (no schema_version)")
    if data["schema_version"] != SCHEMA_VERSION:
        raise ReportError(
            f"{path}: unsupported schema_version {data['schema_version']!r}; "
            f"this tool reads version {SCHEMA_VERSION}"
        )
    results = data.get("results")
    if not isinstance(results, list):
        raise ReportError(f"{path}: 'results' must be a list")
    for i, r in enumerate(results):
        if not isinstance(r, dict) or any(k not in r for k in _REQUIRED_RESULT_KEYS):
            raise ReportError(f"{path}: results[{i}] is missing required fields")
        if r["status"] not in STATUSES or r["severity"] not in SEVERITIES:
            raise ReportError(f"{path}: results[{i}] has an unknown status or severity")
    # Recompute so a hand-edited or stale summary can never disagree with the results.
    data["summary"] = summarize(results)
    data.setdefault("target", "")
    data.setdefault("mode", {})
    data.setdefault("started_at", "")
    return data
