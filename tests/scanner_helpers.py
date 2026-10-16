"""Small builders shared by scanner tests."""

from __future__ import annotations

from typing import Any

from scanner.models import Attack, Payload, TargetResponse

PAYLOAD = Payload(name="p", messages=["hello"])


def make_attack(detector_type: str = "canary", params: dict[str, Any] | None = None) -> Attack:
    """A minimal valid attack wrapping the given detector."""
    ok = {"reply": "fine"}
    return Attack.model_validate(
        {
            "id": "LLM07-900",
            "category": "LLM07",
            "title": "t",
            "description": "d",
            "severity": "low",
            "payloads": [{"name": "p", "messages": ["hello"]}],
            "detector": {"type": detector_type, "params": params or {}},
            "remediation": "r",
            "examples": {"vulnerable": ok, "safe": ok},
        }
    )


def resp(reply: str = "", **kw: Any) -> TargetResponse:
    """Build a TargetResponse from keyword fields."""
    return TargetResponse.model_validate({"reply": reply, **kw})
