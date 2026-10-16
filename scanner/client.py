"""HTTP client for the target. The allowlist is re-checked before EVERY request."""

from __future__ import annotations

import time
from typing import Any

import httpx

from scanner.allowlist import assert_allowed
from scanner.models import TargetResponse


class TargetError(RuntimeError):
    """Raised for transport errors, redirects (never followed) and malformed responses."""


class TargetClient:
    """Talks to a localhost target. Never follows redirects.

    ``http`` may be injected (tests pass a FastAPI ``TestClient`` with a localhost base URL).
    """

    def __init__(
        self,
        base_url: str,
        *,
        http: httpx.Client | None = None,
        timeout: float = 10.0,
        delay: float = 0.0,
    ) -> None:
        assert_allowed(base_url)
        self.base_url = base_url.rstrip("/")
        self._http = http or httpx.Client(timeout=timeout, follow_redirects=False)
        self._delay = delay

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._http.close()

    def _request(
        self, method: str, path: str, *, json: Any = None, headers: dict[str, str] | None = None
    ) -> httpx.Response:
        url = f"{self.base_url}{path}"
        assert_allowed(url)
        if self._delay:
            time.sleep(self._delay)
        try:
            response = self._http.request(
                method, url, json=json, headers=headers, follow_redirects=False
            )
        except httpx.HTTPError as exc:
            raise TargetError(f"{method} {path} failed: {exc}") from exc
        if response.is_redirect:
            raise TargetError(
                f"{method} {path} returned a redirect to "
                f"{response.headers.get('location', '?')!r}; redirects are never followed"
            )
        return response

    def chat(
        self,
        messages: list[str],
        headers: dict[str, str] | None = None,
        *,
        lab_state: bool = True,
    ) -> TargetResponse:
        """Send ``messages`` as consecutive turns and return the last response.

        Earlier user messages and the target's replies are replayed as ``history``. When
        ``lab_state`` is true the refund ledger from ``/_lab/state`` is attached (if available).
        """
        history: list[dict[str, str]] = []
        last: TargetResponse | None = None
        for message in messages:
            response = self._request(
                "POST",
                "/api/chat",
                json={"message": message, "history": history},
                headers=headers,
            )
            try:
                data = response.json()
            except ValueError:
                data = {}
            data = data if isinstance(data, dict) else {}
            last = TargetResponse.model_validate({**data, "status_code": response.status_code})
            history += [
                {"role": "user", "content": message},
                {"role": "assistant", "content": last.reply},
            ]
        assert last is not None
        if lab_state:
            last.lab_refunds = self.lab_refunds()
        return last

    def lab_refunds(self) -> list[dict[str, Any]] | None:
        """Return the refund ledger from ``/_lab/state``, or None if the endpoint is absent."""
        response = self._request("GET", "/_lab/state")
        if response.status_code != 200:
            return None
        refunds = response.json().get("refunds")
        return refunds if isinstance(refunds, list) else None

    def reset(self) -> bool:
        """Reseed the target's database. Returns False if the endpoint is absent."""
        return self._request("POST", "/_lab/reset").status_code == 200

    def health(self) -> dict[str, Any]:
        """Return the target's ``/health`` JSON; raises :class:`TargetError` if unreachable."""
        response = self._request("GET", "/health")
        if response.status_code != 200:
            raise TargetError(f"/health returned HTTP {response.status_code}")
        return response.json()
