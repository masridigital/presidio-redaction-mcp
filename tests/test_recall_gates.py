"""Per-entity recall on the synthetic corpus. A miss on one entity fails that gate."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import yaml

from presidio_redaction_mcp.errors import FailClosed

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "PERSON",
    "US_SSN",
    "MRN",
    "RECORD_ID",
    "ACCOUNT_ID",
    "NPI",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "LOCATION",
    "DATE_OF_BIRTH",
}


def _load(name: str) -> dict:
    return yaml.safe_load((ROOT / "config" / name).read_text(encoding="utf-8"))


def _corpus() -> dict:
    return yaml.safe_load((ROOT / "tests" / "fixtures" / "synthetic_corpus.yaml").read_text(encoding="utf-8"))


def _caught(stack, case: dict) -> bool:
    form = case.get("form")
    if form == "base64":
        payload = base64.b64encode(case["value"].encode()).decode("ascii")
    elif form == "json_key":
        payload = {case["value"]: "status"}
    else:
        payload = {"summary": f"note {case['value']} end"}
    redactor = stack["runtime"].service.redactor
    try:
        rewritten, _counts = stack["vpn"].portal.call(redactor.redact, payload)
    except FailClosed as exc:
        return case["value"] not in exc.reason_code
    return case["value"] not in json.dumps(rewritten)


def test_floor_file_names_every_required_entity():
    floors = _load("recall-floors.yaml")
    assert set(floors["entities"]) == REQUIRED
    assert floors["canonical_floor"] == 1.0
    assert floors["adversarial_floor"] == 1.0


def test_each_entity_meets_its_canonical_floor(stack):
    floors = _load("recall-floors.yaml")
    corpus = _corpus()
    missed: dict[str, list[str]] = {}
    for entity in floors["entities"]:
        cases = [case for case in corpus["cases"] if case["entity"] == entity and case["kind"] == "canonical"]
        assert cases, entity
        failures = [case["value"] for case in cases if not _caught(stack, case)]
        if failures:
            missed[entity] = failures
        recall = (len(cases) - len(failures)) / len(cases)
        assert recall >= floors["canonical_floor"], (entity, failures)
    assert not missed


def test_each_entity_with_adversarial_rows_meets_the_floor(stack):
    floors = _load("recall-floors.yaml")
    corpus = _corpus()
    seen = False
    for entity in floors["entities"]:
        cases = [case for case in corpus["cases"] if case["entity"] == entity and case["kind"] == "adversarial"]
        if not cases:
            continue
        seen = True
        failures = [case["value"] for case in cases if not _caught(stack, case)]
        recall = (len(cases) - len(failures)) / len(cases)
        assert recall >= floors["adversarial_floor"], (entity, failures)
    assert seen


def test_negatives_are_not_treated_as_entities(stack):
    corpus = _corpus()
    redactor = stack["runtime"].service.redactor
    text = "ticket #24058 version v1.2.3 in Q3 2026"
    rewritten, _counts = stack["vpn"].portal.call(redactor.redact, text)
    assert rewritten == text
    for negative in corpus["negatives"]:
        assert negative in text
