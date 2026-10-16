"""NovaBank Support: a deliberately vulnerable FastAPI chatbot (educational, synthetic data).

Never expose this app beyond localhost. Run: ``uvicorn target.main:app``.
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, Header
from fastapi.responses import FileResponse

from target.config import Settings
from target.db import Database
from target.llm.base import LLMClient, LLMRequest, Message
from target.prompts import SECURE_PROMPT, VULNERABLE_PROMPT, build_system_prompt
from target.rag import Retriever, load_docs
from target.schemas import ChatRequest, ChatResponse, Mode, RetrievedDoc, ToolCallRecord
from target.tools import TOOL_SPECS, ToolContext, dispatch

STATIC_DIR = Path(__file__).parent / "static"


def make_llm(settings: Settings) -> LLMClient:
    """Return the MOCK model or the real Anthropic client according to ``settings``."""
    if settings.mock_mode:
        from target.llm.mock_client import MockClient

        return MockClient()
    from target.llm.anthropic_client import AnthropicClient

    assert settings.anthropic_api_key is not None
    return AnthropicClient(settings.anthropic_api_key, settings.anthropic_model)


def create_app(settings: Settings | None = None, llm: LLMClient | None = None) -> FastAPI:
    """Build the app. Each app instance owns its own in-memory database."""
    settings = settings or Settings.from_env()
    app = FastAPI(title="NovaBank Support (deliberately vulnerable)")
    db = Database()
    retriever = Retriever(load_docs())
    model = llm or make_llm(settings)
    app.state.settings = settings
    app.state.db = db

    @app.get("/health")
    def health() -> dict[str, object]:
        """Liveness probe that also reports the active modes."""
        return {"status": "ok", "mock": settings.mock_mode, "secure": settings.secure_mode}

    @app.get("/")
    def index() -> FileResponse:
        """Serve the chat page."""
        return FileResponse(STATIC_DIR / "index.html")

    @app.post("/api/chat", response_model=ChatResponse)
    def chat(body: ChatRequest, x_session_token: str | None = Header(default=None)) -> ChatResponse:
        """Answer one chat message: retrieve docs, call the model, run requested tools."""
        docs = retriever.search(body.message)
        base = SECURE_PROMPT if settings.secure_mode else VULNERABLE_PROMPT
        system = build_system_prompt(base, docs)
        messages = [Message(t.role, t.content) for t in body.history]
        messages.append(Message("user", body.message))
        ctx = ToolContext(db, db.customer_for_token(x_session_token), settings.secure_mode)
        records: list[ToolCallRecord] = []
        text = ""
        for _ in range(settings.max_tool_rounds):
            result = model.complete(LLMRequest(system, messages, TOOL_SPECS))
            text = result.text
            if not result.tool_calls:
                break
            messages.append(Message("assistant", result.text, result.tool_calls))
            for call in result.tool_calls:
                record = dispatch(call.name, call.args, ctx)
                records.append(record)
                messages.append(
                    Message(
                        "tool",
                        json.dumps(record.result or {"status": record.status}),
                        tool_call_id=call.id,
                        tool_name=call.name,
                    )
                )
        else:
            # Tool budget exhausted: ask once more for plain text with the results so far.
            text = model.complete(LLMRequest(system, messages, [])).text
        return ChatResponse(
            reply=text,
            reply_html=text,  # planted LLM05 weakness: raw model text goes straight to innerHTML
            tool_calls=records,
            retrieved_docs=[
                RetrievedDoc(id=d.id, title=d.title, visibility=d.visibility) for d in docs
            ],  # type: ignore[arg-type]
            mode=Mode(mock=settings.mock_mode, secure=settings.secure_mode),
        )

    if settings.lab_endpoints:

        @app.get("/_lab/state")
        def lab_state() -> dict[str, object]:
            """Ground truth for scanner detectors: refund ledger and access log."""
            return db.lab_state()

        @app.post("/_lab/reset")
        def lab_reset() -> dict[str, str]:
            """Reseed the database between attacks."""
            db.reset()
            return {"status": "reset"}

    return app


app = create_app()
