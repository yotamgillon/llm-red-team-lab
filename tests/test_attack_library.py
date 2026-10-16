"""Every attack must prove its detector fires on a vulnerable response and not on a safe one."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from scanner.detectors import build_detector, load_canaries
from scanner.loader import load_attacks
from scanner.models import CATEGORIES, Attack
from target.data.seed import CUSTOMERS
from target.llm.mock_client import decode_base64_segments
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
        sent = _payload_text(a).replace(" ", "").lower()
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


def _payload_text(attack: Attack) -> str:
    """Everything an attack sends, plus the decoded form of any base64 segment in it."""
    sent = " ".join(m for p in attack.payloads for m in p.messages)
    return " ".join([sent, *decode_base64_segments(sent)])


def test_every_marker_attack_sends_its_marker_in_two_parts() -> None:
    for attack in ATTACKS:
        for name in attack.detector.params.get("canaries", []):
            if name not in CANARIES.markers or name == "poison_marker":
                continue  # poison_marker is planted in the KB, not sent by the scanner
            first, second = CANARIES.markers[name]
            assert f'"{first}" and "{second}"' in _payload_text(attack), (attack.id, name)


def test_doc_canaries_exist_only_in_internal_kb_docs() -> None:
    from target.rag import load_docs

    docs = load_docs()
    for name, phrase in CANARIES.docs.items():
        holders = [
            d for d in docs if " ".join(phrase.lower().split()) in " ".join(d.body.lower().split())
        ]
        assert holders, f"{name}: phrase not found in any KB doc"
        assert all(d.visibility == "internal" for d in holders), name


# -- library coverage (milestone 3) -----------------------------------------------------------
EXPECTED_COUNTS = {
    "LLM01": 8,
    "LLM02": 5,
    "LLM05": 4,
    "LLM06": 5,
    "LLM07": 4,
    "LLM08": 3,
    "LLM10": 4,
}


def test_library_has_30_plus_attacks_across_all_seven_categories() -> None:
    assert len(ATTACKS) >= 30
    counts: dict[str, int] = {}
    for a in ATTACKS:
        counts[a.category] = counts.get(a.category, 0) + 1
    assert counts == EXPECTED_COUNTS
    assert set(counts) == set(CATEGORIES)


def test_attack_ids_are_unique_and_numbered_from_001() -> None:
    ids = [a.id for a in ATTACKS]
    assert len(ids) == len(set(ids))
    for cat, n in EXPECTED_COUNTS.items():
        assert [i for i in ids if i.startswith(cat)] == [f"{cat}-{k:03d}" for k in range(1, n + 1)]


def test_every_attack_has_both_examples_title_and_remediation() -> None:
    for a in ATTACKS:
        assert a.examples.vulnerable is not None and a.examples.safe is not None, a.id
        assert a.title and a.description and a.remediation and a.references, a.id


def test_library_covers_the_requested_techniques() -> None:
    text = " ".join(f"{a.title} {a.description}".lower() for a in ATTACKS)
    for needle in ("role-play", "base64", "multilingual", "split across turns", "indirect"):
        assert needle in text or needle.replace("-", " ") in text, needle
    assert any(len(p.messages) > 1 for a in ATTACKS for p in a.payloads)  # multi-turn
    assert any(p.headers for a in ATTACKS for p in a.payloads)  # acts as a signed-in customer
    assert any(p.repeat > 1 for a in ATTACKS for p in a.payloads)  # burst
    assert any(p.pad_to for a in ATTACKS for p in a.payloads)  # generated large payload
