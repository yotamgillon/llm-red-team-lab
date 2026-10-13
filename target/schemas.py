"""Pydantic models for the HTTP API (the response contract the scanner's detectors read)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class HistoryTurn(BaseModel):
    """One earlier turn supplied by the client. Unbounded on purpose (planted LLM10 weakness)."""

    role: Literal["user", "assistant"]
    content: str


class ChatRequest(BaseModel):
    """Body of ``POST /api/chat``. No length limits in the vulnerable build."""

    message: str
    history: list[HistoryTurn] = Field(default_factory=list)


class ToolCallRecord(BaseModel):
    """What happened to one tool call requested by the model."""

    name: str
    args: dict[str, Any]
    executed: bool
    result: dict[str, Any] | None = None
    status: Literal["executed", "denied", "pending_confirmation", "error"]


class RetrievedDoc(BaseModel):
    """Metadata of a knowledge-base document placed into the prompt."""

    id: str
    title: str
    visibility: Literal["public", "internal"]


class Mode(BaseModel):
    """Which modes the server runs in."""

    mock: bool
    secure: bool


class ChatResponse(BaseModel):
    """Response of ``POST /api/chat``."""

    reply: str
    reply_html: str
    tool_calls: list[ToolCallRecord]
    retrieved_docs: list[RetrievedDoc]
    mode: Mode
    blocked: str | None = None
