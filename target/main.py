"""NovaBank Support: a deliberately vulnerable FastAPI chatbot (educational, synthetic data).

Never expose this app beyond localhost. Run: ``uvicorn target.main:app``.
"""

from __future__ import annotations

import hmac
import json
import logging
import secrets
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from target.config import Settings
from target.db import Database
from target.guardrails import BLOCKED_REPLY, check_input, escape_html, filter_output
from target.llm.base import LLMClient, LLMRequest, Message
from target.prompts import SECURE_PROMPT, VULNERABLE_PROMPT, build_system_prompt
from target.rag import Retriever, find_injection, load_docs
from target.ratelimit import TokenBucketLimiter
from target.schemas import ChatRequest, ChatResponse, Mode, RetrievedDoc, ToolCallRecord
from target.tools import TOOL_SPECS, ToolContext, dispatch

STATIC_DIR = Path(__file__).parent / "static"
LOG = logging.getLogger("target")
# Secure mode: the page's only script is /static/chat.js, nothing inline, nothing remote.
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'"
)


def make_llm(settings: Settings) -> LLMClient:
    """Return the MOCK model or the real Anthropic client according to ``settings``."""
    if settings.mock_mode:
        from target.llm.mock_client import MockClient

        return MockClient()
    from target.llm.anthropic_client import AnthropicClient

    assert settings.anthropic_api_key is not None
    return AnthropicClient(settings.anthropic_api_key, settings.anthropic_model)


def _enforce_limits(body: ChatRequest, settings: Settings) -> None:
    """Raise 413 when the message or history exceeds the configured bounds (secure mode)."""
    if len(body.message) > settings.max_message_chars:
        raise HTTPException(413, f"message longer than {settings.max_message_chars} characters")
    if len(body.history) > settings.max_history_turns:
        raise HTTPException(413, f"history longer than {settings.max_history_turns} turns")
    if sum(len(t.content) for t in body.history) > settings.max_history_chars:
        raise HTTPException(413, f"history longer than {settings.max_history_chars} characters")


def _blocked(settings: Settings, reason: str) -> ChatResponse:
    """Refusal returned without calling the model."""
    return ChatResponse(
        reply=BLOCKED_REPLY,
        reply_html=escape_html(BLOCKED_REPLY),
        tool_calls=[],
        retrieved_docs=[],
        mode=Mode(mock=settings.mock_mode, secure=settings.secure_mode),
        blocked=reason,
    )


def create_app(settings: Settings | None = None, llm: LLMClient | None = None) -> FastAPI:
    """Build the app. Each app instance owns its own in-memory database."""
    settings = settings or Settings.from_env()
    app = FastAPI(title="NovaBank Support (deliberately vulnerable)")
    db = Database()
    docs_all = load_docs()
    retriever = Retriever(docs_all)
    model = llm or make_llm(settings)
    secure = settings.secure_mode
    # Secure mode: a configured staff token, or a random one nobody (model included) can know.
    staff_token = settings.staff_token or secrets.token_urlsafe(24)
    limiter = TokenBucketLimiter(settings.rate_limit_burst, settings.rate_limit_per_second)
    app.state.settings = settings
    app.state.db = db
    app.state.limiter = limiter
    app.state.flagged_docs = (
        {d.id: find_injection(d.body) for d in docs_all if find_injection(d.body)} if secure else {}
    )
    for doc_id in app.state.flagged_docs:
        LOG.warning("ingestion check: %s contains instruction-like text, sanitised", doc_id)

    def is_staff(token: str | None) -> bool:
        return bool(token) and hmac.compare_digest(token or "", staff_token)

    if secure:

        @app.middleware("http")
        async def secure_headers(request: Request, call_next):  # type: ignore[no-untyped-def]
            """Reject oversized bodies before parsing; add CSP and nosniff to every response."""
            try:
                declared = int(request.headers.get("content-length") or 0)
            except ValueError:
                declared = settings.max_body_bytes + 1
            if declared > settings.max_body_bytes:
                response: Response = JSONResponse({"detail": "request body too large"}, 413)
            else:
                response = await call_next(request)
            response.headers["Content-Security-Policy"] = CSP
            response.headers["X-Content-Type-Options"] = "nosniff"
            return response

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/health")
    def health() -> dict[str, object]:
        """Liveness probe that also reports the active modes."""
        return {"status": "ok", "mock": settings.mock_mode, "secure": settings.secure_mode}

    @app.get("/")
    def index() -> FileResponse:
        """Serve the chat page."""
        return FileResponse(STATIC_DIR / "index.html")

    @app.post("/api/chat", response_model=ChatResponse)
    def chat(
        request: Request,
        body: ChatRequest,
        x_session_token: str | None = Header(default=None),
        x_staff_token: str | None = Header(default=None),
    ) -> ChatResponse:
        """Answer one chat message: retrieve docs, call the model, run requested tools."""
        staff = False
        if secure:
            allowed, retry_after = limiter.check(request.client.host if request.client else "?")
            if not allowed:
                raise HTTPException(429, "rate limit exceeded", {"Retry-After": str(retry_after)})
            _enforce_limits(body, settings)
            staff = is_staff(x_staff_token)
            verdict = check_input(
                body.message, [t.content for t in body.history if t.role == "user"]
            )
            if not verdict.allowed:
                return _blocked(settings, f"input_guardrail:{verdict.rule}")
        docs = retriever.search(body.message, allow_internal=staff or not secure)
        base = SECURE_PROMPT if secure else VULNERABLE_PROMPT
        system = build_system_prompt(base, docs, untrusted=secure)
        max_tokens = settings.max_output_tokens if secure else None
        messages = [Message(t.role, t.content) for t in body.history]
        messages.append(Message("user", body.message))
        ctx = ToolContext(
            db, db.customer_for_token(x_session_token), secure, refund_cap=settings.refund_cap
        )
        records: list[ToolCallRecord] = []
        text = ""
        for _ in range(settings.max_tool_rounds):
            result = model.complete(LLMRequest(system, messages, TOOL_SPECS, max_tokens))
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
            text = model.complete(LLMRequest(system, messages, [], max_tokens)).text
        if secure:
            text = filter_output(text, settings.max_output_chars).text
            reply_html = escape_html(text)
        else:
            reply_html = text  # planted LLM05 weakness: raw model text goes straight to innerHTML
        return ChatResponse(
            reply=text,
            reply_html=reply_html,
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
            limiter.reset()  # a burst test must not rate-limit the next attack
            return {"status": "reset"}

    if secure:

        @app.post("/api/refunds/{pending_id}/confirm")
        def confirm_refund(
            pending_id: int, x_staff_token: str | None = Header(default=None)
        ) -> dict[str, object]:
            """Human confirmation of a queued refund. Needs the staff token; the model has no
            tool, token or route that reaches this endpoint."""
            if not is_staff(x_staff_token):
                raise HTTPException(403, "staff token required")
            done = db.confirm_pending_refund(pending_id)
            if done is None:
                raise HTTPException(404, "no such pending refund")
            return {"status": "executed", **done}

    return app


app = create_app()
