"""Runtime settings for the NovaBank target, read from environment variables."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

TRUE_VALUES = {"1", "true", "yes", "on"}
DEFAULT_MODEL = "claude-haiku-5-5"


class ConfigError(RuntimeError):
    """Raised when the environment describes an impossible configuration."""


@dataclass(frozen=True)
class Settings:
    """Immutable target settings.

    ``secure_mode`` switches on the M5 mitigations (guardrails, authz, limits, escaping). The
    limit fields below are only enforced in secure mode; the vulnerable build has none.
    """

    mock_mode: bool = True
    secure_mode: bool = False
    lab_endpoints: bool = True
    anthropic_api_key: str | None = None
    anthropic_model: str = DEFAULT_MODEL
    max_tool_rounds: int = 3
    staff_token: str | None = None  # secure mode: confirms refunds / may read internal docs
    max_message_chars: int = 2_000
    max_history_turns: int = 20
    max_history_chars: int = 8_000
    max_body_bytes: int = 64_000
    max_output_tokens: int = 512
    max_output_chars: int = 4_000
    rate_limit_burst: int = 10
    rate_limit_per_second: float = 1.0
    refund_cap: float = 100.0

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        """Build settings from ``env`` (defaults to ``os.environ`` after loading ``.env``).

        MOCK_MODE defaults to true when no ANTHROPIC_API_KEY is set. MOCK_MODE=false
        without a key is a startup error.
        """
        if env is None:
            load_dotenv(Path(".env"))
            env = os.environ
        key = (env.get("ANTHROPIC_API_KEY") or "").strip() or None
        mock_raw = env.get("MOCK_MODE")
        mock = (key is None) if mock_raw is None else mock_raw.strip().lower() in TRUE_VALUES
        if not mock and key is None:
            raise ConfigError("MOCK_MODE=false requires ANTHROPIC_API_KEY to be set")
        return cls(
            mock_mode=mock,
            secure_mode=env.get("SECURE_MODE", "false").strip().lower() in TRUE_VALUES,
            lab_endpoints=env.get("LAB_ENDPOINTS", "true").strip().lower() in TRUE_VALUES,
            anthropic_api_key=key,
            anthropic_model=env.get("ANTHROPIC_MODEL") or DEFAULT_MODEL,
            staff_token=(env.get("STAFF_TOKEN") or "").strip() or None,
        )


def load_dotenv(path: Path) -> None:
    """Load KEY=VALUE lines from ``path`` into ``os.environ`` without overriding existing vars."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        os.environ.setdefault(name.strip(), value.strip().strip("\"'"))
