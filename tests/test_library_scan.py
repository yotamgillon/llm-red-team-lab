"""Scan the whole library against the in-process vulnerable MOCK target.

Each attack must fire through the real HTTP path (not only on its canned example), for every
payload it defines, so no attack is flagged by luck.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from scanner.client import TargetClient
from scanner.detectors import build_detector, load_canaries
from scanner.loader import load_attacks
from scanner.models import CATEGORIES, Attack, Payload
from scanner.runner import filter_attacks, run_scan
from target.config import Settings
from target.main import create_app

ATTACKS = load_attacks()
CANARIES = load_canaries()
CASES = [(a, p) for a in ATTACKS for p in a.payloads]


@pytest.fixture
def target() -> Iterator[TargetClient]:
    """Scanner client wired to an in-process vulnerable MOCK target."""
    app = create_app(Settings(mock_mode=True, secure_mode=False))
    with TestClient(app, base_url="http://localhost") as http:
        yield TargetClient("http://localhost", http=http)


@pytest.mark.parametrize("category", CATEGORIES)
def test_category_scan_flags_every_attack(target: TargetClient, category: str) -> None:
    attacks = filter_attacks(ATTACKS, [category])
    assert attacks, f"no attacks for {category}"
    result = run_scan(target, attacks)
    statuses = {r.attack_id: r.status for r in result.results}
    assert all(s == "vulnerable" for s in statuses.values()), statuses


@pytest.mark.parametrize(
    ("attack", "payload"), CASES, ids=lambda x: getattr(x, "id", None) or x.name
)
def test_every_payload_fires_against_the_vulnerable_target(
    target: TargetClient, attack: Attack, payload: Payload
) -> None:
    target.reset()
    response = target.send(payload)
    verdict = build_detector(attack.detector, CANARIES).evaluate(attack, payload, response)
    assert verdict.fired, f"{attack.id}/{payload.name} did not fire; reply={response.reply[:200]!r}"
