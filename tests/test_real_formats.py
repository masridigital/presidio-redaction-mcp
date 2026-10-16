"""Unlabeled identifier context, and the double's IP / DOB agreement."""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from presidio_redaction_mcp.recognizers import load_recognizers
from tests.presidio_double import PresidioDouble

ROOT = Path(__file__).resolve().parents[1]


def _corpus() -> dict:
    import yaml

    return yaml.safe_load((ROOT / "tests" / "fixtures" / "synthetic_corpus.yaml").read_text(encoding="utf-8"))


def test_context_words_catch_unlabeled_ids_and_spare_plain_numbers():
    recognizers = load_recognizers(ROOT / "config" / "recognizers.yaml")
    corpus = _corpus()
    wanted = {
        "medical record is 0001234": "MRN",
        "chart number is 845221901": "MRN",
        "patient id is 1000456": "MRN",
        "0001234 is the mrn": "MRN",
        "account number is 99990000": "ACCOUNT_ID",
        "member id is 0011223344": "ACCOUNT_ID",
        "99990000 is the account number": "ACCOUNT_ID",
        "record number is 8844221": "RECORD_ID",
        "rec # is 000042": "RECORD_ID",
    }
    for value, entity in wanted.items():
        spans = recognizers.find_spans(f"note {value} end")
        assert any(span["entity_type"] == entity for span in spans), value
        assert value not in {span["entity_type"] for span in spans}
    for text in corpus["context_false_positives"]:
        spans = recognizers.find_spans(text)
        assert not any(span["entity_type"] in {"MRN", "ACCOUNT_ID", "RECORD_ID"} for span in spans), text


def test_double_labels_ip_and_iso_dates_and_keeps_custom_dob():
    double = PresidioDouble()

    def analyze(text: str, recognizers: list | None = None) -> list[dict]:
        response = double.handle(
            httpx.Request(
                "POST",
                "http://presidio.test/analyze",
                json={
                    "text": text,
                    "language": "en",
                    "score_threshold": 0.4,
                    "ad_hoc_recognizers": recognizers or [],
                },
            )
        )
        return json.loads(response.read().decode())

    ip = analyze("from 192.0.2.10 today")
    assert any(item["entity_type"] == "IP_ADDRESS" and "192.0.2.10" == "from 192.0.2.10 today"[item["start"] : item["end"]] for item in ip)
    dob = analyze("dob 1900-01-01")
    assert any(item["entity_type"] == "DATE_TIME" for item in dob)
    assert "1900-01-01" == "dob 1900-01-01"[dob[0]["start"] : dob[0]["end"]] or any(
        "dob 1900-01-01"[item["start"] : item["end"]] == "1900-01-01" for item in dob
    )
    recognizers = load_recognizers(ROOT / "config" / "recognizers.yaml")
    custom = analyze("note 1900-01-01 end", list(recognizers.ad_hoc))
    types = {item["entity_type"] for item in custom if "note 1900-01-01 end"[item["start"] : item["end"]] == "1900-01-01"}
    assert "DATE_OF_BIRTH" in types
    assert "DATE_TIME" not in types
    plain = analyze("ticket #24058 version v1.2.3 in Q3 2026")
    assert plain == []
