"""Pydantic models shared by the loader, detectors, runner and CLI."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

CATEGORIES: tuple[str, ...] = ("LLM01", "LLM02", "LLM05", "LLM06", "LLM07", "LLM08", "LLM10")


class Severity(StrEnum):
    """Severity of an attack, from most to least serious."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Payload(BaseModel):
    """One request sequence. ``messages`` is a list so multi-turn attacks are possible."""

    model_config = ConfigDict(extra="forbid")

    name: str
    messages: list[str] = Field(min_length=1)
    headers: dict[str, str] = Field(default_factory=dict)


class DetectorSpec(BaseModel):
    """Which detector judges the response, and its parameters."""

    model_config = ConfigDict(extra="forbid")

    type: str
    params: dict[str, Any] = Field(default_factory=dict)


class ToolCallRecord(BaseModel):
    """A tool call as reported by the target."""

    model_config = ConfigDict(extra="ignore")

    name: str
    args: dict[str, Any] = Field(default_factory=dict)
    executed: bool = False
    result: dict[str, Any] | None = None
    status: str = "denied"


class TargetResponse(BaseModel):
    """What detectors read: the target's chat contract plus scanner-side observations."""

    model_config = ConfigDict(extra="ignore")

    reply: str = ""
    reply_html: str | None = None
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    retrieved_docs: list[dict[str, Any]] = Field(default_factory=list)
    mode: dict[str, bool] = Field(default_factory=dict)
    blocked: str | None = None
    status_code: int = 200
    lab_refunds: list[dict[str, Any]] | None = None

    @model_validator(mode="after")
    def _default_html(self) -> TargetResponse:
        if self.reply_html is None:
            self.reply_html = self.reply
        return self


class Examples(BaseModel):
    """Required canned responses that prove the detector fires and stays quiet."""

    model_config = ConfigDict(extra="forbid")

    vulnerable: TargetResponse
    safe: TargetResponse


class Attack(BaseModel):
    """One attack from the YAML library."""

    model_config = ConfigDict(extra="forbid")

    id: str
    category: str
    title: str
    description: str
    severity: Severity
    payloads: list[Payload] = Field(min_length=1)
    detector: DetectorSpec
    remediation: str
    references: list[str] = Field(default_factory=list)
    examples: Examples

    @field_validator("category")
    @classmethod
    def _known_category(cls, value: str) -> str:
        if value not in CATEGORIES:
            raise ValueError(f"unknown category {value!r}; expected one of {', '.join(CATEGORIES)}")
        return value

    @model_validator(mode="after")
    def _id_matches_category(self) -> Attack:
        if not self.id.startswith(f"{self.category}-"):
            raise ValueError(f"id {self.id!r} must start with {self.category}-")
        return self


class Verdict(BaseModel):
    """A detector's judgement of one response."""

    fired: bool
    evidence: str = ""
    confidence: float = 1.0
    inconclusive: bool = False


Status = Literal["vulnerable", "not_vulnerable", "inconclusive", "error"]


class AttackResult(BaseModel):
    """Outcome of one attack across all its payloads."""

    attack_id: str
    category: str
    title: str
    severity: Severity
    status: Status
    payload: str | None = None
    evidence: str = ""
    confidence: float = 0.0
    remediation: str = ""
    error: str | None = None


class ScanResult(BaseModel):
    """A whole scan."""

    target: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    mode: dict[str, bool] = Field(default_factory=dict)
    results: list[AttackResult] = Field(default_factory=list)

    @property
    def findings(self) -> list[AttackResult]:
        """Results whose attack succeeded (the target is vulnerable)."""
        return [r for r in self.results if r.status == "vulnerable"]
