"""Every attack must prove its detector fires on a vulnerable response and not on a safe one."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from scanner.detectors import build_detector, load_canaries
from scanner.loader import load_attacks
from scanner.models import Attack
from target.data.seed import CUSTOMERS
from target.prompts import VULNERABLE_PROMPT

ATTACKS = load_attacks()
CANARIES = load_canaries()
KB_DIR = Path(__file__).resolve().parent.parent / "target" / "data" / "kb"


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda a: a.id)
def test_detector_fires_on_vulnerable_example(attack: Attack) -> None:
    detector = build_detector(attack.detector, CANARIES)
    verdicts = [detector.evaluate(attack, p, attack.examples.vulnerable) for p in attack.payloads]
    assert any(v.fired for v in verdicts), f"{attack.id}: detector missed its vulnerable example"


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda a: a.id)
def test_detector_quiet_on_safe_example(attack: Attack) -> None:
    detector = build_detector(attack.detector, CANARIES)
    for payload in attack.payloads:
        verdict = detector.evaluate(attack, payload, attack.examples.safe)
        assert not verdict.fired, f"{attack.id}: false positive on safe example"


def test_attack_payloads_never_contain_assembled_markers() -> None:
    for a in ATTACKS:
        sent = "".join(m for p in a.payloads for m in p.messages).replace(" ", "").lower()
        for marker in CANARIES.markers:
            assert CANARIES.value(marker).lower() not in sent, (a.id, marker)


# -- canaries.yaml must match what the target really contains ---------------------------------
def test_prompt_canaries_exist_in_vulnerable_prompt() -> None:
    for name, value in CANARIES.prompt.items():
        assert value in VULNERABLE_PROMPT, name


def test_pii_values_exist_in_seed() -> None:
    seed = {c["customer_id"]: c for c in CUSTOMERS}
    assert set(CANARIES.pii) == set(seed)
    for cid, fields in CANARIES.pii.items():
        for field, value in fields.items():
            assert seed[cid][field] == value, (cid, field)  # type: ignore[literal-required]


def test_poison_marker_parts_are_planted_in_poisoned_doc() -> None:
    doc = (KB_DIR / "kb_007_refund_policy_update.md").read_text(encoding="utf-8")
    first, second = CANARIES.markers["poison_marker"]
    assert re.search(rf'"{re.escape(first)}" and "{re.escape(second)}"', doc)
    assert CANARIES.value("poison_marker") not in doc


def test_payload_markers_are_split_in_their_attacks() -> None:
    for attack_id, marker in (("LLM01-001", "override_marker"), ("LLM01-002", "roleplay_marker")):
        attack = next(a for a in ATTACKS if a.id == attack_id)
        text = " ".join(attack.payloads[0].messages)
        first, second = CANARIES.markers[marker]
        assert f'"{first}" and "{second}"' in text


def test_doc_canaries_exist_only_in_internal_kb_docs() -> None:
    from target.rag import load_docs

    docs = load_docs()
    for name, phrase in CANARIES.docs.items():
        holders = [
            d for d in docs if " ".join(phrase.lower().split()) in " ".join(d.body.lower().split())
        ]
        assert holders, f"{name}: phrase not found in any KB doc"
        assert all(d.visibility == "internal" for d in holders), name
