"""Real Anthropic client. The API key is read from the environment, never hard-coded."""

from __future__ import annotations

from typing import Any

from target.llm.base import LLMRequest, LLMResult, Message, ToolCall

DEFAULT_MAX_TOKENS = 1024


def to_anthropic_messages(messages: list[Message]) -> list[dict[str, Any]]:
    """Convert provider-neutral messages into Anthropic Messages API format."""
    out: list[dict[str, Any]] = []
    for m in messages:
        if m.role == "user":
            out.append({"role": "user", "content": m.content})
        elif m.role == "assistant":
            blocks: list[dict[str, Any]] = []
            if m.content:
                blocks.append({"type": "text", "text": m.content})
            blocks += [
                {"type": "tool_use", "id": c.id, "name": c.name, "input": c.args}
                for c in m.tool_calls
            ]
            out.append({"role": "assistant", "content": blocks})
        else:
            block = {"type": "tool_result", "tool_use_id": m.tool_call_id, "content": m.content}
            if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list):
                out[-1]["content"].append(block)
            else:
                out.append({"role": "user", "content": [block]})
    return out


class AnthropicClient:
    """Calls the Anthropic Messages API with tool support."""

    def __init__(self, api_key: str, model: str) -> None:
        import anthropic

        self._client = anthropic.Anthropic(api_key=api_key)
        self._model = model

    def complete(self, request: LLMRequest) -> LLMResult:
        """Send ``request`` to the API and translate the response."""
        kwargs: dict[str, Any] = {
            "model": self._model,
            "system": request.system,
            "messages": to_anthropic_messages(request.messages),
            "max_tokens": request.max_tokens or DEFAULT_MAX_TOKENS,
        }
        if request.tools:
            kwargs["tools"] = [
                {"name": t.name, "description": t.description, "input_schema": t.parameters}
                for t in request.tools
            ]
        resp = self._client.messages.create(**kwargs)
        text = "".join(b.text for b in resp.content if b.type == "text")
        calls = [
            ToolCall(id=b.id, name=b.name, args=dict(b.input))
            for b in resp.content
            if b.type == "tool_use"
        ]
        return LLMResult(text=text, tool_calls=calls)
