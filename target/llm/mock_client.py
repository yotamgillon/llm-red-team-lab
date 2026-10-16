"""Deterministic MOCK model: a *simulated* naive, instruction-following assistant.

It is not a measurement of any real model. Every reply is computed from the inputs the app
actually built (system prompt, retrieved context, conversation), so different inputs give
different outputs and the same input always gives the same output. Vulnerable behaviour
depends on what the app put in the prompt: secrets leak only if they are in the system text,
and retrieved instructions are obeyed only if they are not wrapped as untrusted data.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from itertools import cycle, islice
from typing import Any

from target.llm.base import LLMRequest, LLMResult, Message, ToolCall
from target.prompts import CONTEXT_HEADER, HARDENED_MARKER, UNTRUSTED_CLOSE, UNTRUSTED_OPEN
from target.rag import tokenize

MAX_UNITS = 20000

ACC_RE = re.compile(r"\bACC-\d{4}\b", re.IGNORECASE)
AMOUNT_RE = re.compile(r"(?<![\w-])\$?(\d+(?:\.\d{1,2})?)(?![\w-])")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
TAG_RE = re.compile(r"<[a-zA-Z!/][^>]*>")
COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
DOC_HEAD_RE = re.compile(r"^\[(kb_\d+)\] (.+)$", re.MULTILINE)
BASE64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
JOIN_RE = re.compile(
    r"join(?:ing)?\s+(?:the\s+)?(?:(?:words?|strings?|parts?)\s+)?[\"'“]?([^\"'”\s]+)[\"'”]?"
    r"\s+and\s+[\"'“]?([^\"'”\s]+)[\"'”]?",
    re.IGNORECASE,
)
REFUND_INSTR_RE = re.compile(
    r"refund_customer for account (ACC-\d{4}) with amount (\d+(?:\.\d+)?)"
    r"(?: and reason \"([^\"]*)\")?",
    re.IGNORECASE,
)
OVERRIDE_RE = re.compile(
    r"ignore (?:all |any )?(?:your |the )?(?:previous|prior|above|earlier)"
    r" (?:instructions|rules|prompts)"
    r"|disregard (?:all |your |the )?(?:previous |prior )?(?:instructions|rules)"
    r"|you are now\b|developer mode|\bdan\b|do anything now|pretend (?:to be|you are)"
    r"|new instructions:|^\s*\[?(?:system|admin)\]?\s*:|<\s*system\s*>|###\s*system"
    r"|ignora las instrucciones|ignorez les instructions|ignoriere alle|игнорируй",
    re.IGNORECASE | re.MULTILINE,
)
EXTRACT_RE = re.compile(
    r"system prompt|your instructions|initial instructions|repeat everything above"
    r"|repeat the text above|your (?:full )?configuration|instructions begin with"
    r"|what were you told|translate[^.]*instructions",
    re.IGNORECASE,
)
QUOTE_RE = re.compile(
    r"word for word|verbatim|quote (?:the|that|this)|full text|exact(?:ly)? (?:text|wording)",
    re.IGNORECASE,
)
SIZE_RE = re.compile(r"(\d[\d,]*)\s*(?:words|times|lines|paragraphs|items|sentences)", re.I)
GREETING_RE = re.compile(r"^\s*(hi|hello|hey|good (?:morning|afternoon|evening))\b", re.I)
NAME_RE = re.compile(r"look ?up ([A-Z][a-z]+(?: [A-Z][a-z]+)?)")
REFUSAL = (
    "I can't help with that request, but I'm happy to assist with your NovaBank "
    "balance, fees, cards or refunds."
)


@dataclass(frozen=True)
class Injection:
    """An instruction found in retrieved context that the model chose to obey."""

    refund: tuple[str, float, str] | None
    marker: str | None


def decode_base64_segments(text: str) -> list[str]:
    """Return printable text decoded from base64-looking tokens in ``text``."""
    out: list[str] = []
    for token in BASE64_RE.findall(text):
        try:
            decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True).decode()
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if " " in decoded and decoded.isprintable():
            out.append(decoded)
    return out


def find_marker(text: str) -> str | None:
    """Execute a 'join X and Y' style instruction and return the assembled string."""
    m = JOIN_RE.search(text)
    return m.group(1) + m.group(2) if m else None


def strip_untrusted(context: str) -> str:
    """Remove spans wrapped as untrusted data (the model treats those as plain data)."""
    pattern = re.escape(UNTRUSTED_OPEN) + r".*?" + re.escape(UNTRUSTED_CLOSE)
    return re.sub(pattern, "", context, flags=re.DOTALL)


def find_injection(visible_context: str) -> Injection | None:
    """Detect instruction-like text in trusted-looking context and parse what it asks for."""
    chunks = [m.group(1) for m in COMMENT_RE.finditer(visible_context)]
    chunks += [
        ln for ln in visible_context.splitlines() if "ignore previous instructions" in ln.lower()
    ]
    for chunk in chunks:
        if not re.search(r"ai-assistant-instruction|ignore previous instructions", chunk, re.I):
            continue
        r = REFUND_INSTR_RE.search(chunk)
        refund = (r.group(1).upper(), float(r.group(2)), r.group(3) or "injected") if r else None
        marker = find_marker(chunk)
        if refund or marker:
            return Injection(refund, marker)
    return None


def doc_bodies(context: str) -> list[tuple[str, str]]:
    """Return (title, full body) per retrieved doc, with HTML comments removed."""
    heads = list(DOC_HEAD_RE.finditer(context))
    out: list[tuple[str, str]] = []
    for i, h in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(context)
        body = COMMENT_RE.sub("", context[h.end() : end])
        out.append((h.group(2), re.sub(r"</?untrusted_data>", "", body).strip()))
    return out


def doc_summaries(context: str) -> list[tuple[str, str]]:
    """Return (title, first sentence) per retrieved doc, with HTML comments removed."""
    heads = list(DOC_HEAD_RE.finditer(context))
    out: list[tuple[str, str]] = []
    for i, h in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(context)
        body = COMMENT_RE.sub("", context[h.end() : end])
        body = re.sub(r"</?untrusted_data>", "", body).strip()
        first = re.split(r"(?<=[.!?])\s", body, maxsplit=1)[0] if body else ""
        out.append((h.group(2), first))
    return out


class MockClient:
    """Rule-based stand-in for an LLM. See module docstring."""

    def complete(self, request: LLMRequest) -> LLMResult:
        """Compute a reply from the request alone (no randomness, no hidden state)."""
        instructions, _, context = request.system.partition(CONTEXT_HEADER)
        hardened = HARDENED_MARKER in request.system
        visible = strip_untrusted(context)
        user_turns = [m.content for m in request.messages if m.role == "user"]
        last_idx = max((i for i, m in enumerate(request.messages) if m.role == "user"), default=-1)
        tool_msgs = [m for m in request.messages[last_idx + 1 :] if m.role == "tool"]
        injection = None if hardened else find_injection(visible)
        if tool_msgs:
            return LLMResult(self._after_tools(tool_msgs, injection, context))
        last = user_turns[-1] if user_turns else ""
        combined = " ".join(user_turns + [d for t in user_turns for d in decode_base64_segments(t)])
        return self._first_pass(request, instructions, context, hardened, injection, last, combined)

    # -- decision pipeline -------------------------------------------------------------------

    def _first_pass(
        self,
        request: LLMRequest,
        instructions: str,
        context: str,
        hardened: bool,
        injection: Injection | None,
        last: str,
        combined: str,
    ) -> LLMResult:
        overriding = bool(OVERRIDE_RE.search(combined))
        extracting = bool(EXTRACT_RE.search(combined))
        if hardened and (overriding or extracting):
            return LLMResult(REFUSAL)
        marker = find_marker(combined) if overriding else None
        if marker:
            return LLMResult(marker)
        if extracting:
            return LLMResult(self._leak(instructions.strip(), combined))
        if overriding:
            return LLMResult(
                f"Understood, restrictions lifted. Continuing with: {last.strip()[:200]}"
            )
        tags = TAG_RE.findall(last)
        if tags:
            markup = last[last.index("<") : last.rindex(">") + 1]
            return LLMResult(f"Sure! Here is the markup you asked for: {markup}")
        sized = self._large_output(request, last)
        if sized is not None:
            return LLMResult(sized)
        concrete = bool(ACC_RE.search(last) and AMOUNT_RE.search(ACC_RE.sub("", last)))
        if injection and not concrete:
            if injection.refund:
                acc, amount, reason = injection.refund
                call = ToolCall(
                    "call_1",
                    "refund_customer",
                    {"account_id": acc, "amount": amount, "reason": reason},
                )
                topic = ", ".join(tokenize(last)[:4])
                return LLMResult(f"Processing your request ({topic}).", [call])
            if injection.marker:
                return LLMResult(self._answer_from_docs(context, last) + " " + injection.marker)
        return self._business(context, last)

    def _leak(self, instructions: str, combined: str) -> str:
        low = combined.lower()
        if "translate" in low:
            return f"[Traducción] {instructions}"
        if "begin with" in low:
            return f"My instructions begin with: {instructions}"
        return f"Here are my instructions:\n{instructions}"

    def _large_output(self, request: LLMRequest, last: str) -> str | None:
        m = SIZE_RE.search(last)
        if not m:
            return None
        n = min(int(m.group(1).replace(",", "")), MAX_UNITS)
        if n < 20:
            return None
        if request.max_tokens:
            n = min(n, request.max_tokens * 3 // 4)
        words = tokenize(last) or ["novabank"]
        return " ".join(islice(cycle(words), n))

    def _business(self, context: str, last: str) -> LLMResult:
        low = last.lower()
        acc = ACC_RE.search(last)
        amount = AMOUNT_RE.search(ACC_RE.sub("", last))
        if re.search(r"refund|reimburse|money back", low) and (acc or amount):
            if not acc:
                return LLMResult("Which account ID should I refund? It looks like ACC-1234.")
            if not amount:
                return LLMResult(f"How much should I refund to {acc.group(0).upper()}?")
            reason = re.split(r"\b(?:because|reason:?|for)\b", last, maxsplit=1)
            why = (
                reason[1].strip(" .")
                if len(reason) > 1 and reason[1].strip()
                else "customer request"
            )
            args = {
                "account_id": acc.group(0).upper(),
                "amount": float(amount.group(1)),
                "reason": why,
            }
            return LLMResult(
                f"Refunding ${amount.group(1)} to {args['account_id']}.",
                [ToolCall("call_1", "refund_customer", args)],
            )
        query = self._lookup_query(last, acc)
        if query:
            return LLMResult(
                f"Let me look that up: {query}",
                [ToolCall("call_1", "lookup_account", {"query": query})],
            )
        if re.search(r"\bbalance\b|my details", low):
            return LLMResult("Sure. Which account ID should I check? It looks like ACC-1234.")
        if _has_docs(context) and QUOTE_RE.search(last):
            return LLMResult(self._quote_docs(context))
        if _has_docs(context):
            return LLMResult(self._answer_from_docs(context, last))
        if m := GREETING_RE.match(last):
            return LLMResult(
                f"{m.group(1).capitalize()}! I'm NovaBank Support. How can I help you today?"
            )
        topic = ", ".join(tokenize(last)[:4])
        if not topic:
            return LLMResult("Could you tell me a little more about what you need?")
        return LLMResult(
            f"I understand you're asking about {topic}. I can help with balances, fees, cards "
            "and refunds. Could you share a bit more detail?"
        )

    def _lookup_query(self, last: str, acc: re.Match[str] | None) -> str | None:
        low = last.lower()
        if acc:
            return acc.group(0).upper()
        if e := EMAIL_RE.search(last):
            return e.group(0)
        if n := NAME_RE.search(last):
            return n.group(1)
        if re.search(r"\b(all|every|everyone|list)\b", low) and re.search(
            r"customers?|accounts?|emails?|users?", low
        ):
            return "*"
        return None

    def _quote_docs(self, context: str) -> str:
        """A naive model quotes whatever was retrieved, whoever is asking."""
        return "\n\n".join(f"{title}: {body}" for title, body in doc_bodies(context))

    def _answer_from_docs(self, context: str, last: str) -> str:
        docs = doc_summaries(context)
        if not docs:
            return "I'm not sure about that one. Could you rephrase?"
        title, first = docs[0]
        extra = f" (See also: {', '.join(t for t, _ in docs[1:])}.)" if len(docs) > 1 else ""
        return f"According to '{title}': {first}{extra}"

    def _after_tools(
        self, tool_msgs: list[Message], injection: Injection | None, context: str
    ) -> str:
        lines: list[str] = []
        for m in tool_msgs:
            data: dict[str, Any] = _loads(m.content)
            if m.tool_name == "lookup_account":
                rows = data.get("rows", [])
                if not rows:
                    lines.append("I couldn't find a matching account.")
                for r in rows:
                    lines.append(
                        f"{r.get('account_id')}: {r.get('name')}, email {r.get('email')}, phone "
                        f"{r.get('phone')}, SSN {r.get('ssn')}, address {r.get('address')}, "
                        f"balance ${r.get('balance')}"
                    )
            elif m.tool_name == "refund_customer":
                status = data.get("status", "error")
                if status == "executed":
                    lines.append(
                        f"Refund of ${data.get('amount')} to {data.get('account_id')} is complete "
                        f"(refund #{data.get('refund_id')})."
                    )
                elif status == "pending_confirmation":
                    lines.append("Your refund request was submitted and awaits staff confirmation.")
                else:
                    lines.append(f"I couldn't process that refund: {data.get('error', status)}.")
            else:
                lines.append(f"Tool {m.tool_name} returned: {m.content[:200]}")
        if injection and injection.marker:
            lines.append(injection.marker)
        return "\n".join(lines)


def _has_docs(context: str) -> bool:
    return bool(DOC_HEAD_RE.search(context))


def _loads(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}
