from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from target.config import Settings
from target.main import create_app


@pytest.fixture
def client() -> Iterator[TestClient]:
    """Vulnerable MOCK target served in-process; fresh database per test."""
    with TestClient(create_app(Settings(mock_mode=True, secure_mode=False))) as c:
        yield c
