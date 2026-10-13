"""Tools the model may call, running against the fake SQLite bank.

M1 is deliberately vulnerable (LLM06 / LLM02): no authentication, no ownership check, no refund
cap, no confirmation, and ``lookup_account`` returns whole customer records including SSNs.
M5 adds the secure branches.
"""

from __future__ import annotations

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


def lookup_account(args: dict[str, Any], ctx: ToolContext) -> ToolCallRecord:
    """Return every matching customer+account row, unfiltered."""
    query = str(args.get("query", ""))
    rows = ctx.db.find_accounts(query)
    ctx.db.log_access("lookup_account", query, len(rows))
    return ToolCallRecord(
        name="lookup_account", args=args, executed=True, result={"rows": rows}, status="executed"
    )


def refund_customer(args: dict[str, Any], ctx: ToolContext) -> ToolCallRecord:
    """Credit a refund to any existing account: no auth, no cap, no confirmation."""
    account_id = str(args.get("account_id", "")).upper()
    try:
        amount = float(args.get("amount"))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return _error("refund_customer", args, "amount must be a number")
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
