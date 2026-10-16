"""Detector protocol and the shared canary table."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

import yaml

from scanner.models import Attack, Payload, TargetResponse, Verdict

CANARIES_PATH = Path(__file__).resolve().parent.parent / "canaries.yaml"


class Detector(Protocol):
    """Judges one target response for one payload of one attack."""

    def evaluate(self, attack: Attack, payload: Payload, response: TargetResponse) -> Verdict:
        """Return a :class:`Verdict`; ``fired`` means the target is vulnerable."""
        ...


@dataclass(frozen=True)
class Canaries:
    """Parsed ``canaries.yaml``."""

    prompt: dict[str, str] = field(default_factory=dict)
    markers: dict[str, tuple[str, str]] = field(default_factory=dict)
    pii: dict[str, dict[str, str]] = field(default_factory=dict)
    docs: dict[str, str] = field(default_factory=dict)

    def value(self, name: str) -> str:
        """Resolve a canary name (plain value or assembled marker) to the string to look for."""
        if name in self.prompt:
            return self.prompt[name]
        if name in self.docs:
            return self.docs[name]
        if name in self.markers:
            return "".join(self.markers[name])
        raise KeyError(f"unknown canary {name!r}")


def load_canaries(path: Path = CANARIES_PATH) -> Canaries:
    """Load the canary table from YAML."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    markers = {k: (str(v[0]), str(v[1])) for k, v in (raw.get("markers") or {}).items()}
    pii = {
        cid: {k: str(v) for k, v in fields.items()}
        for cid, fields in (raw.get("pii") or {}).items()
    }
    prompt = {k: str(v) for k, v in (raw.get("prompt") or {}).items()}
    docs = {k: str(v) for k, v in (raw.get("docs") or {}).items()}
    return Canaries(prompt=prompt, markers=markers, pii=pii, docs=docs)


def normalize(text: str) -> str:
    """Lowercase and collapse whitespace so matching ignores case and line wrapping."""
    return " ".join(text.lower().split())
