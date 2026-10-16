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
        # Realistic labeled forms. Digit strings are impossible specimens, not issued identifiers.
        {"entity": "MRN", "kind": "canonical", "value": "MRN: 0001234"},
        {"entity": "MRN", "kind": "canonical", "value": "MRN 845221901"},
        {"entity": "MRN", "kind": "canonical", "value": "M.R.N. 1000456"},
        {"entity": "MRN", "kind": "canonical", "value": "Medical Record Number: 0000456789"},
        {"entity": "MRN", "kind": "canonical", "value": "MR# 7654321"},
        {"entity": "ACCOUNT_ID", "kind": "canonical", "value": "Account Number: 99990000"},
        {"entity": "ACCOUNT_ID", "kind": "canonical", "value": "Account ID: 001122334455"},
        {"entity": "ACCOUNT_ID", "kind": "canonical", "value": "Acct #: 44002211"},
        {"entity": "ACCOUNT_ID", "kind": "canonical", "value": "Acct. 1234567890123"},
        {"entity": "RECORD_ID", "kind": "canonical", "value": "Record ID: 000042"},
        {"entity": "RECORD_ID", "kind": "canonical", "value": "Record Number: 8844221"},
        {"entity": "RECORD_ID", "kind": "canonical", "value": "Record #: 550019"},
        {"entity": "RECORD_ID", "kind": "canonical", "value": "REC-000042"},
        {"entity": "RECORD_ID", "kind": "canonical", "value": "REC 100045"},
        {"entity": "NPI", "kind": "canonical", "value": "NPI: 0000000000"},
        {"entity": "NPI", "kind": "canonical", "value": "NPI 1234567890"},
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


def build_bidirectional() -> dict:
    """Policy the redaction tests apply to every corpus row, in both directions."""
    return {
        "header": "SYNTHETIC",
        "banner": HEADER,
        "inbound_vpn": {"text": "mask", "base64": "block", "json_key": "block"},
        "inbound_cloudflare": "block",
        "outbound": {"text": "mask", "base64": "block", "json_key": "block"},
        "block_reasons": {"base64": "unanalyzable_content", "json_key": "pii_in_key"},
        "placeholders": {
            "PERSON": "<PERSON>",
            "EMAIL_ADDRESS": "<EMAIL_ADDRESS>",
            "MRN": "<MRN>",
            "RECORD_ID": "<RECORD_ID>",
            "ACCOUNT_ID": "<ACCOUNT_ID>",
            "NPI": "<NPI>",
            "US_SSN": "<US_SSN>",
            "PHONE_NUMBER": "<PHONE_NUMBER>",
            "DATE_OF_BIRTH": "<DATE_OF_BIRTH>",
            "CREDIT_CARD": "<CREDIT_CARD>",
            "LOCATION": "<LOCATION>",
        },
    }


def build_builtin_recall() -> dict:
    """Specimens the default Presidio 2.2.362 engine is expected to catch.

    Values are fictional. 901-23-4567 is not an issuable SSN (area 9xx) and not
    a valid ITIN group. 555-01xx and 202-555-01xx are reserved fictional numbers.
    4111... is the Visa test PAN. 192.0.2.10 is TEST-NET-1.
    """
    return {
        "header": "SYNTHETIC",
        "banner": HEADER,
        "presidio": "2.2.362",
        "spacy_model": "en_core_web_lg==3.8.0",
        "score_threshold": 0.4,
        "cases": [
            {"entity": "US_SSN", "value": "901-23-4567", "text": "SSN 901-23-4567"},
            {"entity": "US_SSN", "value": "901.23.4567", "text": "SSN 901.23.4567"},
            {"entity": "EMAIL_ADDRESS", "value": "fake.user@example.com", "text": "email fake.user@example.com"},
            {"entity": "EMAIL_ADDRESS", "value": "pat.placeholder@example.org", "text": "email pat.placeholder@example.org"},
            {"entity": "PHONE_NUMBER", "value": "(555) 010-0199", "text": "phone (555) 010-0199"},
            {"entity": "PHONE_NUMBER", "value": "+1-202-555-0127", "text": "phone +1-202-555-0127"},
            {"entity": "PHONE_NUMBER", "value": "202-555-0148", "text": "phone 202-555-0148"},
            {"entity": "CREDIT_CARD", "value": "4111 1111 1111 1111", "text": "card 4111 1111 1111 1111"},
            {"entity": "CREDIT_CARD", "value": "4111-1111-1111-1111", "text": "card 4111-1111-1111-1111"},
            {"entity": "DATE_TIME", "value": "1900-01-01", "text": "dob 1900-01-01"},
            {"entity": "DATE_TIME", "value": "1901-02-02", "text": "dob 1901-02-02"},
            {"entity": "PERSON", "value": "Jane Doe", "text": "person Jane Doe visited"},
            {"entity": "PERSON", "value": "Alex Example", "text": "person Alex Example visited"},
            {"entity": "LOCATION", "value": "Testville", "text": "loc 123 Fake Street, Testville, ZZ 00000"},
            {"entity": "IP_ADDRESS", "value": "192.0.2.10", "text": "from 192.0.2.10 today"},
        ],
        "gaps": [
            {"entity": "PERSON", "value": "Testy McFakerson", "text": "person Testy McFakerson", "backstop": "deny_list"},
            {"entity": "MRN", "value": "MRN: 0001234", "text": "MRN: 0001234", "backstop": "ad_hoc"},
            {"entity": "RECORD_ID", "value": "REC-000042", "text": "REC-000042", "backstop": "ad_hoc"},
            {"entity": "NPI", "value": "NPI: 0000000000", "text": "NPI: 0000000000", "backstop": "ad_hoc"},
        ],
    }


def _write(path: Path, payload: dict) -> None:
    text = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
    path.write_text(f"# {HEADER}\n{text}", encoding="utf-8")


def main() -> None:
    destination = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    destination.mkdir(parents=True, exist_ok=True)
    _write(destination / "synthetic_corpus.yaml", build())
    _write(destination / "bidirectional_redaction.yaml", build_bidirectional())
    _write(destination / "builtin_recall.yaml", build_builtin_recall())


if __name__ == "__main__":
    main()
