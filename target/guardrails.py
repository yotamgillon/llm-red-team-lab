"""Input and output guardrails (SECURE_MODE).

Everything here is ordinary, model-independent code that runs before the model is called
(``check_input``) and on whatever it returns (``filter_output``). Heuristics are a speed bump,
not a wall: they catch known phrasings and cheap obfuscation (case, spacing, zero-width
characters, base64) but a determined attacker can rephrase. The layers behind them (no secrets
in the prompt, tool authorization, escaping) are what actually bound the damage.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass

from target.prompts import FAKE_API_KEY, INTERNAL_CANARY, SYSTEM_PROMPT_CANARY

BLOCKED_REPLY = (
    "I can't help with that request, but I'm happy to assist with your NovaBank "
    "balance, fees, cards or refunds."
)
TRUNCATION_NOTICE = " [truncated]"

ZERO_WIDTH_RE = re.compile("[​‌‍⁠﻿]")
SPACE_RE = re.compile(r"\s+")
BASE64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

_OVERRIDE_VERBS = r"(?:ignore|disregard|forget|override|bypass|drop)"
_OVERRIDE_TARGET = (
    r"(?:all |any |your |the |these |my |every )*"
    r"(?:previous |prior |above |earlier |preceding |system |safety )*"
    r"(?:instructions|rules|prompts?|guidelines|restrictions|context|policies)"
)
# (rule name, pattern) pairs, matched against normalized text (NFKC, lowercase, single spaces).
INJECTION_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("override_instructions", re.compile(rf"\b{_OVERRIDE_VERBS}\b {_OVERRIDE_TARGET}")),
    (
        "persona_hijack",
        re.compile(
            r"\byou are now\b|\bdeveloper mode\b|\bdan (?:mode|persona)\b|\byou are dan\b"
            r"|\bas dan\b|\bdo anything now\b|\bjailbreak"
            r"|\bpretend (?:to be|you are|that you)\b"
            r"|\bact as (?:if|an? (?:unrestricted|unfiltered))"
        ),
    ),
    (
        "fake_role_marker",
        re.compile(
            r"(?:^|\n)\s*\[?(?:system|admin|assistant|developer)\]?\s*:"
            r"|<\s*/?\s*(?:system|assistant|untrusted_data)\s*>|###\s*system|\[/?inst\]|<\|im_(?:start|end)\|>"
        ),
    ),
    (
        "prompt_extraction",
        re.compile(
            r"system prompt|(?:your|the) (?:initial |original |hidden |full |secret )?"
            r"(?:instructions|configuration|setup|rules)\b.*\b(?:reveal|show|print|repeat|translate|"
            r"quote|output|tell|display|leak)"
            r"|\b(?:reveal|show|print|repeat|translate|quote|output|tell me|display|leak)\b.*"
            r"\b(?:your|the) (?:initial |original |hidden |full |secret )?"
            r"(?:instructions|configuration|setup)\b"
            r"|repeat (?:everything|the text|all) (?:above|before)"
            r"|what were you told|instructions begin with|my instructions begin"
        ),
    ),
    (
        "multilingual_override",
        re.compile(
            r"ignora (?:todas )?las instrucciones|ignorez (?:toutes )?les instructions"
            r"|ignoriere (?:alle|die) |игнорируй|忽略.{0,6}指令"
        ),
    ),
    (
        "joined_output_trick",
        re.compile(r"\bjoin(?:ing)? (?:the )?(?:words?|strings?|parts?|tokens?) \S+ and \S+"),
    ),
)

SECRET_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"nova-sk-[A-Za-z0-9-]{8,}", re.IGNORECASE),
    re.compile(r"NOVA-CANARY-[A-Z0-9-]+", re.IGNORECASE),
)
KNOWN_SECRETS = (FAKE_API_KEY, SYSTEM_PROMPT_CANARY, INTERNAL_CANARY)
SSN_RE = re.compile(r"(?<![\d-])(\d{3})-(\d{2})-(\d{4})(?![\d-])")
EMAIL_RE = re.compile(r"([\w.+-])[\w.+-]*@([\w-]+(?:\.[\w-]+)+)")
PHONE_RE = re.compile(
    r"(?<![\d-])(?:\+?1[ .-]?)?(?:\(\d{3}\)\s?|\d{3}[ .-])?\d{3}[-.]\d{4}(?![\d-])"
)
CARD_RE = re.compile(r"(?<![\d-])(?:\d[ -]?){13,19}(?!\d)")


@dataclass(frozen=True)
class InputVerdict:
    """Result of :func:`check_input`. ``rule`` is None when the input is allowed."""

    rule: str | None

    @property
    def allowed(self) -> bool:
        """True when no rule matched."""
        return self.rule is None


@dataclass(frozen=True)
class OutputResult:
    """Filtered model output and the names of the redactions applied."""

    text: str
    redactions: tuple[str, ...]


def normalize(text: str) -> str:
    """NFKC-normalize, drop zero-width characters, lowercase, collapse spaces (keeps newlines)."""
    text = ZERO_WIDTH_RE.sub("", unicodedata.normalize("NFKC", text)).lower()
    return "\n".join(SPACE_RE.sub(" ", line).strip() for line in text.splitlines())


def decode_base64_segments(text: str) -> list[str]:
    """Return printable text decoded from base64-looking tokens in ``text``."""
    out: list[str] = []
    for token in BASE64_RE.findall(text):
        try:
            decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True).decode()
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded.isprintable() and len(decoded) >= 8:
            out.append(decoded)
    return out


def check_input(message: str, history_user_turns: list[str] | None = None) -> InputVerdict:
    """Apply the injection heuristics to ``message`` and to the earlier user turns.

    Earlier turns are checked alone and joined with the new message, so an instruction split
    across turns is still seen as one string. Base64 payloads are decoded and re-checked.
    """
    turns = [*(history_user_turns or []), message]
    candidates = list(turns) + [" ".join(turns)]
    candidates += [d for t in turns for d in decode_base64_segments(t)]
    for candidate in candidates:
        norm = normalize(candidate)
        # Check line structure (for "system:" markers) and a flattened form (phrases split by
        # a line break).
        for form in (norm, norm.replace("\n", " ")):
            for name, pattern in INJECTION_RULES:
                if pattern.search(form):
                    return InputVerdict(name)
    return InputVerdict(None)


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n = n * 2 - 9 if n * 2 > 9 else n * 2
        total += n
    return total % 10 == 0


def _mask_card(m: re.Match[str]) -> str:
    digits = re.sub(r"\D", "", m.group(0))
    if 13 <= len(digits) <= 19 and _luhn_ok(digits):
        return "[card ending " + digits[-4:] + "]"
    return m.group(0)


def filter_output(text: str, max_chars: int | None = None) -> OutputResult:
    """Redact secrets and PII from model output and optionally cap its length.

    Order matters: secrets first, then SSN/card (before the looser phone pattern), then email
    and phone. Account ids and money amounts are left alone.
    """
    redactions: list[str] = []

    def apply(label: str, pattern: re.Pattern[str], repl: str | re.Pattern[str] | object) -> None:
        nonlocal text
        new = pattern.sub(repl, text)  # type: ignore[arg-type]
        if new != text:
            redactions.append(label)
            text = new

    for secret in KNOWN_SECRETS:
        if secret.lower() in text.lower():
            text = re.sub(re.escape(secret), "[redacted secret]", text, flags=re.IGNORECASE)
            redactions.append("secret")
    for pattern in SECRET_RES:
        apply("secret", pattern, "[redacted secret]")
    apply("ssn", SSN_RE, lambda m: f"***-**-{m.group(3)}")
    apply("card", CARD_RE, _mask_card)
    apply("email", EMAIL_RE, lambda m: f"{m.group(1)}***@{m.group(2)}")
    apply("phone", PHONE_RE, lambda m: "***-" + re.sub(r"\D", "", m.group(0))[-4:])
    if max_chars is not None and len(text) > max_chars:
        text = text[:max_chars] + TRUNCATION_NOTICE
        redactions.append("truncated")
    return OutputResult(text, tuple(dict.fromkeys(redactions)))


def escape_html(text: str) -> str:
    """HTML-escape model output so the chat page's ``innerHTML`` sink renders it as text."""
    return html.escape(text, quote=True)
