"""Load and validate the YAML attack library."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from scanner.detectors import Canaries, build_detector, load_canaries
from scanner.models import Attack

ATTACKS_DIR = Path(__file__).resolve().parent / "attacks"


class AttackLoadError(ValueError):
    """Raised when an attack file is malformed, inconsistent or duplicates an id."""


def load_attacks(directory: Path = ATTACKS_DIR, canaries: Canaries | None = None) -> list[Attack]:
    """Load every ``*.yaml`` in ``directory`` into validated :class:`Attack` models.

    Fails on invalid YAML, schema violations (including unknown categories and missing
    examples), unknown detector types or params, and duplicate ids.
    """
    canaries = canaries or load_canaries()
    attacks: list[Attack] = []
    seen: dict[str, Path] = {}
    for path in sorted(directory.glob("*.yaml")):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise AttackLoadError(f"{path.name}: invalid YAML: {exc}") from exc
        if not isinstance(raw, list):
            raise AttackLoadError(f"{path.name}: top level must be a list of attacks")
        for index, item in enumerate(raw):
            try:
                attack = Attack.model_validate(item)
                build_detector(attack.detector, canaries)
            except (ValidationError, ValueError) as exc:
                raise AttackLoadError(f"{path.name} item {index}: {exc}") from exc
            if attack.id in seen:
                raise AttackLoadError(
                    f"{path.name}: duplicate attack id {attack.id} (also in {seen[attack.id].name})"
                )
            seen[attack.id] = path
            attacks.append(attack)
    return sorted(attacks, key=lambda a: a.id)
