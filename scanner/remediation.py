"""Category-level fallback fixes. An attack's own ``remediation`` text takes precedence."""

from __future__ import annotations

CATEGORY_REMEDIATION: dict[str, str] = {
    "LLM01": "Treat all user and retrieved text as untrusted data; add input guardrails and "
    "keep privileged actions outside the model's control.",
    "LLM02": "Enforce authorization in code, return only the minimum fields, and mask PII "
    "in outputs.",
    "LLM05": "HTML-escape model output before rendering and send a restrictive CSP.",
    "LLM06": "Bind tools to the authenticated user, cap amounts and require human confirmation "
    "for sensitive actions.",
    "LLM07": "Keep secrets out of prompts and treat the system prompt as public.",
    "LLM08": "Filter retrieval by caller permissions and treat retrieved text as untrusted.",
    "LLM10": "Limit input size, history, output tokens and request rate.",
}


def remediation_for(category: str, own: str = "") -> str:
    """Return the attack's own remediation, falling back to the category default."""
    return own or CATEGORY_REMEDIATION.get(category, "")
