"""Run attacks against a target and assemble results."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from scanner.client import TargetClient, TargetError
from scanner.detectors import Canaries, Judge, build_detector, load_canaries
from scanner.models import Attack, AttackResult, ScanResult, Verdict
from scanner.remediation import remediation_for


def filter_attacks(attacks: Iterable[Attack], categories: Iterable[str] | None) -> list[Attack]:
    """Keep attacks whose category is listed. ``None``, empty or ``["all"]`` keeps everything."""
    wanted = {c.strip().upper() for c in categories or [] if c.strip()}
    if not wanted or "ALL" in wanted:
        return list(attacks)
    return [a for a in attacks if a.category in wanted]


def run_attack(
    attack: Attack, client: TargetClient, canaries: Canaries, judge: Judge | None = None
) -> tuple[AttackResult, dict[str, bool]]:
    """Run one attack (all payloads, resetting the target before each) and judge it."""
    base = AttackResult(
        attack_id=attack.id,
        category=attack.category,
        title=attack.title,
        severity=attack.severity,
        status="not_vulnerable",
        remediation=remediation_for(attack.category, attack.remediation),
    )
    detector = build_detector(attack.detector, canaries, judge)
    mode: dict[str, bool] = {}
    inconclusive: Verdict | None = None
    for payload in attack.payloads:
        try:
            client.reset()
            response = client.chat(payload.messages, payload.headers)
        except TargetError as exc:
            return base.model_copy(update={"status": "error", "error": str(exc)}), mode
        mode = response.mode or mode
        verdict = detector.evaluate(attack, payload, response)
        if verdict.fired:
            return (
                base.model_copy(
                    update={
                        "status": "vulnerable",
                        "payload": payload.name,
                        "evidence": verdict.evidence,
                        "confidence": verdict.confidence,
                    }
                ),
                mode,
            )
        if verdict.inconclusive:
            inconclusive = verdict
    if inconclusive is not None:
        return base.model_copy(
            update={"status": "inconclusive", "evidence": inconclusive.evidence}
        ), mode
    return base, mode


def run_scan(
    client: TargetClient,
    attacks: Iterable[Attack],
    *,
    canaries: Canaries | None = None,
    judge: Judge | None = None,
    on_result: Callable[[AttackResult], None] | None = None,
) -> ScanResult:
    """Run ``attacks`` against ``client`` and return a :class:`ScanResult`."""
    canaries = canaries or load_canaries()
    scan = ScanResult(target=client.base_url)
    for attack in attacks:
        result, mode = run_attack(attack, client, canaries, judge)
        scan.mode = mode or scan.mode
        scan.results.append(result)
        if on_result:
            on_result(result)
    return scan
