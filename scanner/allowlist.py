"""Localhost-only allowlist. The scanner must never send a request to any other host."""

from __future__ import annotations

from urllib.parse import urlsplit

ALLOWED_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1"})
ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})


class TargetNotAllowedError(ValueError):
    """Raised when a URL points anywhere other than localhost, 127.0.0.1 or ::1."""


def is_allowed(url: str) -> bool:
    """Return True only if ``url`` is http(s) and its parsed hostname is exactly allowed.

    The URL is parsed, never prefix-matched. Credentials in the URL, backslashes, whitespace and
    control characters are refused because different parsers disagree about them.
    """
    if not isinstance(url, str) or not url or url != url.strip():
        return False
    if "\\" in url or any(ord(ch) < 0x21 or ord(ch) == 0x7F for ch in url):
        return False
    try:
        parts = urlsplit(url)
        host = parts.hostname
        parts.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError:
        return False
    if parts.scheme not in ALLOWED_SCHEMES or parts.username is not None:
        return False
    if parts.password is not None or "@" in parts.netloc:
        return False
    return host in ALLOWED_HOSTS


def assert_allowed(url: str) -> None:
    """Raise :class:`TargetNotAllowedError` unless ``url`` passes :func:`is_allowed`."""
    if not is_allowed(url):
        raise TargetNotAllowedError(
            f"refusing target {url!r}: only http(s) URLs for localhost, 127.0.0.1 and ::1 "
            "are allowed"
        )
