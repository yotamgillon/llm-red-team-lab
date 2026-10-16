"""Generated-load helpers on Payload (pad_to, history, repeat) and TargetClient.send."""

from __future__ import annotations

import json

import httpx
import pytest
from pydantic import ValidationError

from scanner.client import TargetClient
from scanner.models import MAX_PAD_CHARS, MAX_REPEAT, Payload


def test_pad_to_grows_last_message_to_exact_length() -> None:
    p = Payload(name="p", messages=["first", "summarize my account"], pad_to=5_000)
    msgs = p.expanded_messages()
    assert msgs[0] == "first" and len(msgs[1]) == 5_000
    assert msgs[1].startswith("summarize my account ")


def test_pad_to_never_shrinks_a_longer_message() -> None:
    p = Payload(name="p", messages=["x" * 50], pad_to=10)
    assert p.expanded_messages() == ["x" * 50]


def test_history_alternates_roles_and_sizes_turns() -> None:
    p = Payload(name="p", messages=["hi"], history_turns=4, history_chars=120)
    h = p.history()
    assert [t["role"] for t in h] == ["user", "assistant", "user", "assistant"]
    assert all(len(t["content"]) == 120 for t in h)
    assert p.sent_chars() == len("hi") + 4 * 120


def test_defaults_add_nothing() -> None:
    p = Payload(name="p", messages=["hi"])
    assert p.expanded_messages() == ["hi"] and p.history() == [] and p.repeat == 1


@pytest.mark.parametrize(
    "bad",
    [{"repeat": 0}, {"repeat": MAX_REPEAT + 1}, {"pad_to": MAX_PAD_CHARS + 1}, {"pad_to": 0}],
)
def test_helper_limits_are_enforced(bad: dict) -> None:
    with pytest.raises(ValidationError):
        Payload(name="p", messages=["hi"], **bad)


def test_send_bursts_pads_and_collects_every_status_code() -> None:
    bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path != "/api/chat":
            return httpx.Response(404)
        bodies.append(json.loads(request.content))
        return httpx.Response(429 if len(bodies) > 3 else 200, json={"reply": "ok"})

    client = TargetClient(
        "http://localhost", http=httpx.Client(transport=httpx.MockTransport(handler))
    )
    payload = Payload(
        name="burst", messages=["ping"], repeat=5, pad_to=300, history_turns=2, history_chars=40
    )
    out = client.send(payload)
    assert out.status_codes == [200, 200, 200, 429, 429]
    assert len(bodies) == 5
    assert len(bodies[0]["message"]) == 300 and len(bodies[0]["history"]) == 2
    assert out.lab_refunds is None
