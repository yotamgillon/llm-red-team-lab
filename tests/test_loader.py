from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from scanner.loader import ATTACKS_DIR, AttackLoadError, load_attacks

VALID = {
    "id": "LLM07-901",
    "category": "LLM07",
    "title": "t",
    "description": "d",
    "severity": "high",
    "payloads": [{"name": "p", "messages": ["hi"]}],
    "detector": {"type": "canary", "params": {"canaries": ["fake_api_key"]}},
    "remediation": "r",
    "examples": {"vulnerable": {"reply": "x"}, "safe": {"reply": "y"}},
}


def write(tmp_path: Path, items: list, name: str = "a.yaml") -> Path:
    (tmp_path / name).write_text(yaml.safe_dump(items), encoding="utf-8")
    return tmp_path


def test_valid_attack_loads(tmp_path: Path) -> None:
    attacks = load_attacks(write(tmp_path, [VALID]))
    assert [a.id for a in attacks] == ["LLM07-901"]


def test_shipped_library_loads() -> None:
    assert len(load_attacks(ATTACKS_DIR)) >= 10


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"category": "LLM99", "id": "LLM99-1"}, "unknown category"),
        ({"id": "LLM01-001"}, "must start with LLM07"),
        ({"severity": "bad"}, "severity"),
        ({"payloads": []}, "payloads"),
        ({"detector": {"type": "nope"}}, "unknown detector"),
        ({"detector": {"type": "canary", "params": {}}}, "params.canaries"),
        ({"detector": {"type": "canary", "params": {"canaries": ["ghost"]}}}, "canary"),
        ({"surprise": 1}, "surprise"),
    ],
)
def test_invalid_attacks_rejected(tmp_path: Path, change: dict, message: str) -> None:
    with pytest.raises(AttackLoadError, match=message):
        load_attacks(write(tmp_path, [{**VALID, **change}]))


@pytest.mark.parametrize("missing", ["vulnerable", "safe"])
def test_missing_example_rejected(tmp_path: Path, missing: str) -> None:
    examples = {k: v for k, v in VALID["examples"].items() if k != missing}
    with pytest.raises(AttackLoadError, match=missing):
        load_attacks(write(tmp_path, [{**VALID, "examples": examples}]))


def test_missing_examples_block_rejected(tmp_path: Path) -> None:
    item = {k: v for k, v in VALID.items() if k != "examples"}
    with pytest.raises(AttackLoadError, match="examples"):
        load_attacks(write(tmp_path, [item]))


def test_duplicate_ids_rejected_across_files(tmp_path: Path) -> None:
    write(tmp_path, [VALID], "a.yaml")
    write(tmp_path, [VALID], "b.yaml")
    with pytest.raises(AttackLoadError, match="duplicate attack id LLM07-901"):
        load_attacks(tmp_path)


def test_invalid_yaml_and_wrong_shape(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").write_text("- [unclosed", encoding="utf-8")
    with pytest.raises(AttackLoadError, match="invalid YAML"):
        load_attacks(tmp_path)
    (tmp_path / "a.yaml").write_text("id: x", encoding="utf-8")
    with pytest.raises(AttackLoadError, match="list"):
        load_attacks(tmp_path)
