"""Detector registry: maps the YAML ``detector.type`` string to a detector instance."""

from __future__ import annotations

from scanner.detectors.base import Canaries, Detector, load_canaries
from scanner.detectors.canary import CanaryDetector
from scanner.detectors.html_script import HtmlScriptDetector
from scanner.detectors.llm_judge import Judge, LLMJudgeDetector
from scanner.detectors.pii import PiiDetector
from scanner.detectors.toolcall import ToolCallDetector
from scanner.models import DetectorSpec

DETECTOR_TYPES: tuple[str, ...] = ("canary", "pii", "toolcall", "html_script", "llm_judge")


def build_detector(
    spec: DetectorSpec, canaries: Canaries | None = None, judge: Judge | None = None
) -> Detector:
    """Instantiate the detector named by ``spec``. Raises ``ValueError`` on bad type/params."""
    canaries = canaries or load_canaries()
    try:
        match spec.type:
            case "canary":
                return CanaryDetector(spec.params, canaries)
            case "pii":
                return PiiDetector(spec.params, canaries)
            case "toolcall":
                return ToolCallDetector(spec.params)
            case "html_script":
                return HtmlScriptDetector(spec.params)
            case "llm_judge":
                return LLMJudgeDetector(spec.params, judge)
    except KeyError as exc:
        raise ValueError(f"bad detector params: {exc}") from exc
    raise ValueError(f"unknown detector type {spec.type!r}; expected one of {DETECTOR_TYPES}")


__all__ = ["DETECTOR_TYPES", "Canaries", "Detector", "Judge", "build_detector", "load_canaries"]
