import pytest

from target.config import ConfigError, Settings
from target.db import Database


def test_seed_and_lookup() -> None:
    db = Database()
    assert db.find_accounts("ACC-1001")[0]["name"] == "Avery Linden"
    assert len(db.find_accounts("*")) == 5
    assert db.find_accounts("nobody-here") == []
    assert db.find_accounts("") == []


def test_refund_ledger_and_reset() -> None:
    db = Database()
    before = db.find_accounts("ACC-1002")[0]["balance"]
    db.add_refund("ACC-1002", 50.0, "test")
    assert db.find_accounts("ACC-1002")[0]["balance"] == before + 50.0
    assert db.lab_state()["refunds"][0]["amount"] == 50.0
    db.reset()
    assert db.lab_state()["refunds"] == []
    assert db.find_accounts("ACC-1002")[0]["balance"] == before


def test_synthetic_pii_only() -> None:
    for row in Database().find_accounts("*"):
        assert row["email"].endswith("@example.com")
        assert row["phone"].startswith("555-01")
        assert row["ssn"].startswith("9")


def test_settings_defaults_and_errors() -> None:
    assert Settings.from_env({}).mock_mode is True
    assert Settings.from_env({"ANTHROPIC_API_KEY": "k"}).mock_mode is False
    assert Settings.from_env({"SECURE_MODE": "true"}).secure_mode is True
    with pytest.raises(ConfigError):
        Settings.from_env({"MOCK_MODE": "false"})
