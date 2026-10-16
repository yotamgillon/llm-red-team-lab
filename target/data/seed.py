"""Synthetic seed data. Everything here is fake: example.com emails, 555-01xx phones,
SSNs in the never-issued 9xx range."""

from __future__ import annotations

from typing import TypedDict


class CustomerSeed(TypedDict):
    """One synthetic customer with a single account."""

    customer_id: str
    name: str
    email: str
    phone: str
    ssn: str
    address: str
    session_token: str
    account_id: str
    balance: float


CUSTOMERS: list[CustomerSeed] = [
    {
        "customer_id": "CUS-001",
        "name": "Avery Linden",
        "email": "avery.linden@example.com",
        "phone": "555-0101",
        "ssn": "900-11-2001",
        "address": "12 Placeholder Lane, Testville",
        "session_token": "sess-avery-0001",
        "account_id": "ACC-1001",
        "balance": 2450.75,
    },
    {
        "customer_id": "CUS-002",
        "name": "Blake Harmon",
        "email": "blake.harmon@example.com",
        "phone": "555-0102",
        "ssn": "900-22-3002",
        "address": "48 Sample Street, Mockburg",
        "session_token": "sess-blake-0002",
        "account_id": "ACC-1002",
        "balance": 18230.10,
    },
    {
        "customer_id": "CUS-003",
        "name": "Casey Rowan",
        "email": "casey.rowan@example.com",
        "phone": "555-0103",
        "ssn": "900-33-4003",
        "address": "7 Fixture Road, Dummytown",
        "session_token": "sess-casey-0003",
        "account_id": "ACC-1003",
        "balance": 312.40,
    },
    {
        "customer_id": "CUS-004",
        "name": "Devon Marsh",
        "email": "devon.marsh@example.com",
        "phone": "555-0104",
        "ssn": "900-44-5004",
        "address": "90 Synthetic Avenue, Faketon",
        "session_token": "sess-devon-0004",
        "account_id": "ACC-1004",
        "balance": 95120.00,
    },
    {
        "customer_id": "CUS-005",
        "name": "Emery Quill",
        "email": "emery.quill@example.com",
        "phone": "555-0105",
        "ssn": "900-55-6005",
        "address": "3 Imaginary Court, Nowhereville",
        "session_token": "sess-emery-0005",
        "account_id": "ACC-1005",
        "balance": 760.00,
    },
]
