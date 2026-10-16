"""LLM10 limits detector: fires when work is accepted unbounded, quiet when limits hold."""

from __future__ import annotations

import pytest

from scanner.detectors import build_detector, load_canaries
from scanner.models import DetectorSpec, Payload
from tests.scanner_helpers import make_attack, resp

CAN = load_canaries()


def run(params: dict, response, payload: Payload):
    det = build_detector(DetectorSpec(type="limits", params=params), CAN)
    return det.evaluate(make_attack("limits", params), payload, response)


BIG = Payload(name="big", messages=["hi"], pad_to=1_000)
SMALL = Payload(name="small", messages=["hi"])


def test_needs_a_valid_check() -> None:
    for params in ({}, {"check": "nope"}):
        with pytest.raises(ValueError):
            build_detector(DetectorSpec(type="limits", params=params), CAN)


# -- input_size ------------------------------------------------------------------------------
def test_input_size_fires_when_oversize_message_gets_2xx() -> None:
    assert run({"check": "input_size", "min_chars": 1_000}, resp("ok", status_code=200), BIG).fired


@pytest.mark.parametrize("code", [413, 422, 429, 400])
def test_input_size_quiet_when_rejected(code: int) -> None:
    assert not run(
        {"check": "input_size", "min_chars": 1_000}, resp("", status_code=code), BIG
    ).fired


def test_input_size_boundary_and_small_payload() -> None:
    p = {"check": "input_size", "min_chars": 1_000}
    assert run(p, resp("ok"), BIG).fired  # exactly at the threshold
    assert not run({**p, "min_chars": 1_001}, resp("ok"), BIG).fired
    assert not run(p, resp("ok"), SMALL).fired  # payload never was oversize


def test_input_size_counts_history() -> None:
    p = Payload(name="ctx", messages=["hi"], history_turns=10, history_chars=100)
    assert run({"check": "input_size", "min_chars": 1_000}, resp("ok"), p).fired


# -- burst -----------------------------------------------------------------------------------
def test_burst_fires_without_throttling() -> None:
    v = run({"check": "burst", "min_requests": 5}, resp("ok", status_codes=[200] * 5), SMALL)
    assert v.fired and "5 rapid requests" in v.evidence


def test_burst_quiet_when_throttled() -> None:
    codes = [200, 200, 200, 429, 429]
    assert not run({"check": "burst", "min_requests": 5}, resp("", status_codes=codes), SMALL).fired


def test_burst_quiet_below_threshold() -> None:
    assert not run(
        {"check": "burst", "min_requests": 5}, resp("ok", status_codes=[200] * 4), SMALL
    ).fired


def test_burst_falls_back_to_single_status_code() -> None:
    assert not run({"check": "burst", "min_requests": 2}, resp("ok"), SMALL).fired


# -- output_size -----------------------------------------------------------------------------
def test_output_size_fires_on_huge_reply_and_respects_boundary() -> None:
    p = {"check": "output_size", "min_reply_chars": 100}
    assert run(p, resp("w" * 100), SMALL).fired
    assert not run(p, resp("w" * 99), SMALL).fired


def test_output_size_quiet_when_request_rejected() -> None:
    p = {"check": "output_size", "min_reply_chars": 10}
    assert not run(p, resp("w" * 50, status_code=429), SMALL).fired


# -- transport / server errors are inconclusive, never a pass or a fail -----------------------
@pytest.mark.parametrize("check", ["input_size", "burst", "output_size"])
def test_server_errors_are_inconclusive(check: str) -> None:
    v = run({"check": check, "min_chars": 1, "min_requests": 1}, resp("", status_code=500), BIG)
    assert not v.fired and v.inconclusive
