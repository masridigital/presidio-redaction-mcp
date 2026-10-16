#!/usr/bin/env python3
"""Write the synthetic corpus. Seeded Faker, no real PHI, client, or Lumina data."""

from __future__ import annotations

import base64
from pathlib import Path

import yaml
from faker import Faker

SEED = 4242
HEADER = "SYNTHETIC — FAKE DATA — NOT REAL PERSONS"


def build() -> dict:
    faker = Faker("en_US")
    Faker.seed(SEED)
    faker.seed_instance(SEED)
    local = faker.user_name()
    generated_email = f"{local}@example.com"
    cases = [
        {"entity": "PERSON", "kind": "canonical", "value": "Testy McFakerson"},
        {"entity": "PERSON", "kind": "canonical", "value": "Jane Synthetic-Doe"},
        {"entity": "PERSON", "kind": "canonical", "value": "Pat Placeholder"},
        {"entity": "PERSON", "kind": "adversarial", "value": "Testy McFakerson", "form": "json_key"},
        {"entity": "EMAIL_ADDRESS", "kind": "canonical", "value": "fake.user@example.com"},
        {"entity": "EMAIL_ADDRESS", "kind": "canonical", "value": generated_email},
        {"entity": "EMAIL_ADDRESS", "kind": "canonical", "value": "pat.placeholder@example.org"},
        {"entity": "MRN", "kind": "canonical", "value": "MRN-SYN-0001234"},
        {"entity": "MRN", "kind": "adversarial", "value": "M R N - S Y N - 0001234"},
        {"entity": "MRN", "kind": "adversarial", "value": "MRN-SYN-0001234", "form": "base64"},
        {"entity": "RECORD_ID", "kind": "canonical", "value": "REC-SYN-000042"},
        {"entity": "ACCOUNT_ID", "kind": "canonical", "value": "ACCT-SYN-99990000"},
        {"entity": "NPI", "kind": "canonical", "value": "NPI-SYN-1234567890"},
        {"entity": "US_SSN", "kind": "canonical", "value": "000-00-0000"},
        {"entity": "US_SSN", "kind": "canonical", "value": "666-12-3456"},
        {"entity": "US_SSN", "kind": "canonical", "value": "900-00-0001"},
        {"entity": "US_SSN", "kind": "adversarial", "value": "666.12.3456"},
        {"entity": "PHONE_NUMBER", "kind": "canonical", "value": "555-0100"},
        {"entity": "PHONE_NUMBER", "kind": "canonical", "value": "555-0199"},
        {"entity": "DATE_OF_BIRTH", "kind": "canonical", "value": "1900-01-01"},
        {"entity": "DATE_OF_BIRTH", "kind": "canonical", "value": "1901-02-02"},
        {"entity": "CREDIT_CARD", "kind": "canonical", "value": "4111 1111 1111 1111"},
        {"entity": "CREDIT_CARD", "kind": "canonical", "value": "4111-1111-1111-1111"},
        {"entity": "LOCATION", "kind": "canonical", "value": "123 Fake Street, Testville, ZZ 00000"},
    ]
    return {
        "header": "SYNTHETIC",
        "banner": HEADER,
        "seed": SEED,
        "faker_email": generated_email,
        "cases": cases,
        "negatives": ["#24058", "v1.2.3", "192.0.2.10", "Q3 2026"],
        "base64_example": base64.b64encode(b"MRN-SYN-0001234").decode("ascii"),
    }


def main() -> None:
    payload = build()
    destination = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "synthetic_corpus.yaml"
    destination.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
    destination.write_text(f"# {HEADER}\n{text}", encoding="utf-8")


if __name__ == "__main__":
    main()
