"""In-memory SQLite store for the fake bank: customers, accounts, refund ledger, access log."""

from __future__ import annotations

import sqlite3
import threading
from typing import Any

from target.data.seed import CUSTOMERS

SCHEMA = """
CREATE TABLE customers (
    customer_id TEXT PRIMARY KEY, name TEXT, email TEXT, phone TEXT, ssn TEXT,
    address TEXT, session_token TEXT
);
CREATE TABLE accounts (
    account_id TEXT PRIMARY KEY, customer_id TEXT, balance REAL
);
CREATE TABLE refunds (
    id INTEGER PRIMARY KEY AUTOINCREMENT, account_id TEXT, amount REAL, reason TEXT
);
CREATE TABLE access_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, tool TEXT, query TEXT, rows_returned INTEGER
);
"""


class Database:
    """Thread-safe wrapper around one in-memory SQLite connection."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self.reset()

    def reset(self) -> None:
        """Drop everything and reseed the synthetic data."""
        with self._lock:
            self._conn.executescript(
                "DROP TABLE IF EXISTS customers; DROP TABLE IF EXISTS accounts;"
                "DROP TABLE IF EXISTS refunds; DROP TABLE IF EXISTS access_log;"
            )
            self._conn.executescript(SCHEMA)
            for c in CUSTOMERS:
                self._conn.execute(
                    "INSERT INTO customers VALUES (?,?,?,?,?,?,?)",
                    (c["customer_id"], c["name"], c["email"], c["phone"], c["ssn"],
                     c["address"], c["session_token"]),
                )  # fmt: skip
                self._conn.execute(
                    "INSERT INTO accounts VALUES (?,?,?)",
                    (c["account_id"], c["customer_id"], c["balance"]),
                )
            self._conn.commit()

    def find_accounts(self, query: str) -> list[dict[str, Any]]:
        """Return full customer+account rows matching ``query``.

        Matches account id, customer id, name or email by substring; ``*`` returns every row.
        Deliberately over-broad (planted LLM02 weakness): it returns SSN, phone and address.
        """
        q = query.strip().lower()
        sql = (
            "SELECT a.account_id, a.balance, c.customer_id, c.name, c.email, c.phone, c.ssn, "
            "c.address FROM accounts a JOIN customers c ON a.customer_id = c.customer_id"
        )
        with self._lock:
            rows = [dict(r) for r in self._conn.execute(sql + " ORDER BY a.account_id")]
        if q in ("*", "all"):
            return rows
        return [
            r
            for r in rows
            if q
            and any(q in str(r[f]).lower() for f in ("account_id", "customer_id", "name", "email"))
        ]

    def account_exists(self, account_id: str) -> bool:
        """Return True if ``account_id`` is a known account."""
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM accounts WHERE account_id = ?", (account_id,)
            ).fetchone()
        return row is not None

    def add_refund(self, account_id: str, amount: float, reason: str) -> int:
        """Credit ``amount`` to the account, append to the ledger and return the refund id."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO refunds (account_id, amount, reason) VALUES (?,?,?)",
                (account_id, amount, reason),
            )
            self._conn.execute(
                "UPDATE accounts SET balance = balance + ? WHERE account_id = ?",
                (amount, account_id),
            )
            self._conn.commit()
            return int(cur.lastrowid or 0)

    def log_access(self, tool: str, query: str, rows_returned: int) -> None:
        """Record a tool access for lab observability."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO access_log (tool, query, rows_returned) VALUES (?,?,?)",
                (tool, query, rows_returned),
            )
            self._conn.commit()

    def lab_state(self) -> dict[str, Any]:
        """Return the refund ledger and access log (ground truth for scanner detectors)."""
        with self._lock:
            refunds = [dict(r) for r in self._conn.execute("SELECT * FROM refunds ORDER BY id")]
            access = [dict(r) for r in self._conn.execute("SELECT * FROM access_log ORDER BY id")]
        return {"refunds": refunds, "access_log": access}

    def customer_for_token(self, token: str | None) -> str | None:
        """Map a session token to a customer id, or None."""
        if not token:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT customer_id FROM customers WHERE session_token = ?", (token,)
            ).fetchone()
        return row["customer_id"] if row else None
