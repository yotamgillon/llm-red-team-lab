"""Builders for report tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from scanner.models import AttackResult, ScanResult, Severity

STARTED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def result(
    attack_id: str, status: str = "vulnerable", severity: str = "high", **kw: Any
) -> AttackResult:
    """One attack result; the category is derived from the id."""
    return AttackResult(
        attack_id=attack_id,
        category=attack_id.split("-")[0],
        title=kw.pop("title", f"Title {attack_id}"),
        severity=Severity(severity),
        status=status,  # type: ignore[arg-type]
        payload="plain" if status == "vulnerable" else None,
        evidence=kw.pop("evidence", "leaked NOVA-CANARY" if status == "vulnerable" else ""),
        confidence=1.0 if status == "vulnerable" else 0.0,
        remediation=kw.pop("remediation", "Fix it."),
        **kw,
    )


def scan(*results: AttackResult, target: str = "http://localhost:8000") -> ScanResult:
    """A ScanResult with a fixed start time."""
    return ScanResult(
        target=target,
        started_at=STARTED,
        mode={"mock": True, "secure": False},
        results=list(results),
    )
