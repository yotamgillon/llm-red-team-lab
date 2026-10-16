from __future__ import annotations

from collections.abc import Iterator

import httpx
import pytest
from fastapi.testclient import TestClient

from scanner.allowlist import TargetNotAllowedError
from scanner.client import TargetClient, TargetError
from scanner.detectors import load_canaries
from scanner.loader import load_attacks
from scanner.runner import filter_attacks, run_attack, run_scan
from target.config import Settings
from target.main import create_app
from tests.scanner_helpers import make_attack


@pytest.fixture
def target() -> Iterator[TargetClient]:
    """Scanner client wired to an in-process vulnerable MOCK target on a localhost base URL."""
    app = create_app(Settings(mock_mode=True, secure_mode=False))
    with TestClient(app, base_url="http://localhost") as http:
        yield TargetClient("http://localhost", http=http)


# -- client ---------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url", ["http://example.com", "http://localhost.evil.com", "http://localhost@evil.com"]
)
def test_client_refuses_bad_target_before_any_io(url: str) -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise AssertionError("network I/O attempted")

    http = httpx.Client(transport=httpx.MockTransport(boom))
    with pytest.raises(TargetNotAllowedError):
        TargetClient(url, http=http)


def test_client_rechecks_allowlist_on_every_request(target: TargetClient) -> None:
    assert target.health()["status"] == "ok"
    target.base_url = "http://localhost.evil.com"  # tampering after construction
    with pytest.raises(TargetNotAllowedError):
        target.health()
    with pytest.raises(TargetNotAllowedError):
        target.chat(["hi"])


def test_client_never_follows_redirects() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://evil.com/x"})

    client = TargetClient(
        "http://localhost:8000", http=httpx.Client(transport=httpx.MockTransport(handler))
    )
    with pytest.raises(TargetError, match="redirect"):
        client.chat(["hi"])
    assert seen == ["http://localhost:8000/api/chat"]


def test_client_wraps_transport_errors() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    client = TargetClient(
        "http://localhost:1", http=httpx.Client(transport=httpx.MockTransport(handler))
    )
    with pytest.raises(TargetError, match="refused"):
        client.health()


def test_chat_multi_turn_replays_history() -> None:
    bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat":
            import json

            bodies.append(json.loads(request.content))
            return httpx.Response(200, json={"reply": f"r{len(bodies)}"})
        return httpx.Response(404)

    client = TargetClient(
        "http://localhost", http=httpx.Client(transport=httpx.MockTransport(handler))
    )
    out = client.chat(["a", "b"], {"X-Session-Token": "t"})
    assert out.reply == "r2" and out.lab_refunds is None
    assert bodies[1]["history"] == [
        {"role": "user", "content": "a"},
        {"role": "assistant", "content": "r1"},
    ]


def test_chat_attaches_ledger(target: TargetClient) -> None:
    out = target.chat(["Refund $20 to ACC-1001 for a double charge"])
    assert out.lab_refunds and out.lab_refunds[0]["account_id"] == "ACC-1001"
    assert target.reset() is True
    assert target.lab_refunds() == []


# -- runner ---------------------------------------------------------------------------------
def test_filter_attacks_by_category() -> None:
    attacks = load_attacks()
    assert len(filter_attacks(attacks, ["all"])) == len(attacks)
    assert len(filter_attacks(attacks, None)) == len(attacks)
    assert {a.category for a in filter_attacks(attacks, ["llm07", "LLM05"])} == {"LLM07", "LLM05"}
    assert filter_attacks(attacks, ["LLM10"]) == []


def test_full_scan_flags_every_first_ten_attack(target: TargetClient) -> None:
    attacks = load_attacks()
    result = run_scan(target, attacks)
    by_id = {r.attack_id: r for r in result.results}
    assert {r.attack_id for r in result.findings} == {a.id for a in attacks}, by_id
    assert result.mode == {"mock": True, "secure": False}
    one = by_id["LLM06-001"]
    assert one.severity.value == "critical" and one.evidence and one.remediation


def test_runner_resets_state_between_attacks(target: TargetClient) -> None:
    run_scan(target, filter_attacks(load_attacks(), ["LLM06"]))
    run_scan(target, filter_attacks(load_attacks(), ["LLM07"]))
    assert target.lab_refunds() == [] or len(target.lab_refunds() or []) <= 1


def test_runner_captures_errors() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    client = TargetClient(
        "http://localhost", http=httpx.Client(transport=httpx.MockTransport(handler))
    )
    result, _ = run_attack(load_attacks()[0], client, load_canaries())
    assert result.status == "error" and "slow" in (result.error or "")


def test_runner_inconclusive_without_judge(target: TargetClient) -> None:
    attack = make_attack("llm_judge", {"criteria": "anything"})
    result, _ = run_attack(attack, target, load_canaries())
    assert result.status == "inconclusive"
    judged, _ = run_attack(attack, target, load_canaries(), judge=lambda c, t: "vulnerable")
    assert judged.status == "vulnerable"


def test_remediation_falls_back_to_category_default(target: TargetClient) -> None:
    attack = make_attack("canary", {"canaries": ["fake_api_key"]}).model_copy(
        update={"remediation": ""}
    )
    result, _ = run_attack(attack, target, load_canaries())
    assert "secrets" in result.remediation.lower()
