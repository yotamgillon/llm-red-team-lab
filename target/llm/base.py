"""Provider-neutral request/response types for the LLM client."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol


@dataclass(frozen=True)
class ToolCall:
    """A tool invocation requested by the model."""

    id: str
    name: str
    args: dict[str, Any]


@dataclass(frozen=True)
class Message:
    """One conversation turn. ``tool`` messages carry the result of ``tool_call_id``."""

    role: Literal["user", "assistant", "tool"]
    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None
    tool_name: str | None = None


@dataclass(frozen=True)
class ToolSpec:
    """Tool description handed to the model."""

    name: str
    description: str
    parameters: dict[str, Any]


@dataclass(frozen=True)
class LLMRequest:
    """Everything the model sees: system prompt (including retrieved context), turns, tools."""

    system: str
    messages: list[Message]
    tools: list[ToolSpec] = field(default_factory=list)
    max_tokens: int | None = None


@dataclass(frozen=True)
class LLMResult:
    """Model output: text and/or tool calls."""

    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)


class LLMClient(Protocol):
    """Anything that can complete a request."""

    def complete(self, request: LLMRequest) -> LLMResult:
        """Return the model's reply for ``request``."""
        ...
