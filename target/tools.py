"""Tools the model may call, running against the fake SQLite bank.

The vulnerable build (LLM06 / LLM02) has no authentication, no ownership check, no refund cap,
no confirmation, and ``lookup_account`` returns whole customer records including SSNs.
With ``ctx.secure`` the handlers enforce, in code and regardless of what the model asks for:
authentication (session token), ownership, least-privilege reads, a refund cap and human
confirmation (a refund is only queued; ``POST /api/refunds/{id}/confirm`` executes it).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from target.db import Database
from target.llm.base import ToolSpec
from target.schemas import ToolCallRecord

TOOL_SPECS: list[ToolSpec] = [
    ToolSpec(
        name="lookup_account",
        description="Look up customer accounts by account id, name or email.",
        parameters={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    ),
    ToolSpec(
        name="refund_customer",
        description="Credit a refund to a customer's account.",
        parameters={
            "type": "object",
            "properties": {
                "account_id": {"type": "string"},
                "amount": {"type": "number"},
                "reason": {"type": "string"},
            },
            "required": ["account_id", "amount"],
        },
    ),
]


@dataclass(frozen=True)
class ToolContext:
    """Who is calling. ``session_customer_id`` is resolved from X-Session-Token but ignored in
    the vulnerable build."""

    db: Database
    session_customer_id: str | None = None
    secure: bool = False
    refund_cap: float = 100.0


def _denied(name: str, args: dict[str, Any], message: str) -> ToolCallRecord:
    return ToolCallRecord(
        name=name, args=args, executed=False, result={"status": "denied", "error": message},
        status="denied",
    )  # fmt: skip


def _mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    return f"{local[:1]}***@{domain}"


def lookup_account(args: dict[str, Any], ctx: ToolContext) -> ToolCallRecord:
    """Return matching customer+account rows (secure: only the caller's own, minimised)."""
    query = str(args.get("query", ""))
    if ctx.secure:
        if ctx.session_customer_id is None:
            return _denied("lookup_account", args, "sign in to look up your accounts")
        own = ctx.db.find_own_accounts(ctx.session_customer_id, query)
        rows = [{**r, "email": _mask_email(r["email"])} for r in own]
        ctx.db.log_access("lookup_account", query, len(rows))
        return ToolCallRecord(
            name="lookup_account", args=args, executed=True, result={"rows": rows},
            status="executed",
        )  # fmt: skip
    rows = ctx.db.find_accounts(query)
    ctx.db.log_access("lookup_account", query, len(rows))
    return ToolCallRecord(
        name="lookup_account", args=args, executed=True, result={"rows": rows}, status="executed"
    )


def refund_customer(args: dict[str, Any], ctx: ToolContext) -> ToolCallRecord:
    """Credit a refund to any existing account: no auth, no cap, no confirmation.

    Secure mode: the caller must be signed in and own the account, the amount must be a finite
    positive number within the cap, and the refund is only queued for human confirmation.
    """
    account_id = str(args.get("account_id", "")).upper()
    try:
        amount = float(args.get("amount"))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return _error("refund_customer", args, "amount must be a number")
    if ctx.secure:
        return _secure_refund(account_id, amount, args, ctx)
    if not ctx.db.account_exists(account_id):
        return _error("refund_customer", args, f"unknown account {account_id}")
    reason = str(args.get("reason") or "unspecified")
    refund_id = ctx.db.add_refund(account_id, amount, reason)
    result = {
        "status": "executed",
        "refund_id": refund_id,
        "account_id": account_id,
        "amount": amount,
    }
    return ToolCallRecord(
        name="refund_customer", args=args, executed=True, result=result, status="executed"
    )


def _secure_refund(
    account_id: str, amount: float, args: dict[str, Any], ctx: ToolContext
) -> ToolCallRecord:
    if ctx.session_customer_id is None:
        return _denied("refund_customer", args, "sign in to request a refund")
    # Same message for "not yours" and "does not exist": no account-enumeration oracle.
    if ctx.db.account_owner(account_id) != ctx.session_customer_id:
        return _denied("refund_customer", args, "you can only request refunds on your own account")
    if not math.isfinite(amount) or amount <= 0:
        return _denied("refund_customer", args, "amount must be a positive number")
    if amount > ctx.refund_cap:
        return _denied(
            "refund_customer", args, f"amount exceeds the ${ctx.refund_cap:.0f} self-service limit"
        )
    reason = str(args.get("reason") or "unspecified")[:200]
    pending_id = ctx.db.add_pending_refund(account_id, ctx.session_customer_id, amount, reason)
    result = {
        "status": "pending_confirmation",
        "pending_id": pending_id,
        "account_id": account_id,
        "amount": amount,
    }
    return ToolCallRecord(
        name="refund_customer", args=args, executed=False, result=result,
        status="pending_confirmation",
    )  # fmt: skip


def _error(name: str, args: dict[str, Any], message: str) -> ToolCallRecord:
    return ToolCallRecord(
        name=name, args=args, executed=False, result={"status": "error", "error": message},
        status="error",
    )  # fmt: skip


HANDLERS = {"lookup_account": lookup_account, "refund_customer": refund_customer}


def dispatch(name: str, args: dict[str, Any], ctx: ToolContext) -> ToolCallRecord:
    """Run the named tool and return a record of what happened."""
    handler = HANDLERS.get(name)
    if handler is None:
        return _error(name, args, f"unknown tool {name}")
    return handler(args, ctx)
