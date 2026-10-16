from __future__ import annotations

import pytest

from scanner.allowlist import TargetNotAllowedError, assert_allowed, is_allowed

ALLOWED = [
    "http://localhost",
    "http://localhost:8000",
    "http://localhost:8000/api/chat",
    "https://localhost/",
    "http://127.0.0.1",
    "http://127.0.0.1:8000/health",
    "http://[::1]:8000",
    "http://[::1]/",
    "http://LOCALHOST:8000",
]

REFUSED = [
    "http://example.com",
    "http://localhost.evil.com",
    "http://localhost@evil.com",
    "http://127.0.0.1.evil.com",
    "http://127.0.0.1.nip.io",
    "http://evil.com#localhost",
    "http://evil.com/?h=localhost",
    "http://evil.com\\@localhost",
    "http://user:pw@localhost",
    "http://localhost:pw@evil.com",
    "http://127.0.0.2",
    "http://0.0.0.0:8000",
    "http://localhost.:8000",
    "http://notlocalhost",
    "http://[::2]/",
    "ftp://localhost",
    "file://localhost/etc/passwd",
    "//localhost",
    "localhost",
    "localhost:8000",
    "",
    "   ",
    "not a url",
    "http://",
    "http://localhost:notaport",
    " http://localhost",
    "http://localhost\n.evil.com",
]


@pytest.mark.parametrize("url", ALLOWED)
def test_allowed_urls(url: str) -> None:
    assert is_allowed(url)
    assert_allowed(url)


@pytest.mark.parametrize("url", REFUSED)
def test_refused_urls(url: str) -> None:
    assert not is_allowed(url)
    with pytest.raises(TargetNotAllowedError):
        assert_allowed(url)


def test_required_spoofing_cases_are_refused() -> None:
    for url in (
        "http://example.com",
        "http://localhost.evil.com",
        "http://localhost@evil.com",
        "http://127.0.0.1.evil.com",
    ):
        assert not is_allowed(url), url


def test_non_string_is_refused() -> None:
    assert not is_allowed(None)  # type: ignore[arg-type]
