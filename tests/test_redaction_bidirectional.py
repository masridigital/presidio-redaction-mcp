"""Bidirectional redaction of every synthetic fixture, on VPN and on Cloudflare."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import yaml

from presidio_redaction_mcp.errors import FailClosed
from tests.conftest import SECRETS, mcp_call, tool_text

ROOT = Path(__file__).resolve().parents[1]


def _corpus() -> dict:
    return yaml.safe_load((ROOT / "tests" / "fixtures" / "synthetic_corpus.yaml").read_text(encoding="utf-8"))


def _policy() -> dict:
    return yaml.safe_load((ROOT / "tests" / "fixtures" / "bidirectional_redaction.yaml").read_text(encoding="utf-8"))


def _payload(case: dict):
    form = case.get("form")
    if form == "base64":
        return base64.b64encode(case["value"].encode()).decode("ascii"), "base64"
    if form == "json_key":
        return {case["value"]: "status"}, "json_key"
    return f"note {case['value']} end", "text"


def test_policy_fixture_covers_both_directions_and_is_synthetic():
    policy = _policy()
    assert policy["header"] == "SYNTHETIC"
    assert policy["inbound_cloudflare"] == "block"
    assert policy["inbound_vpn"]["text"] == "mask"
    assert policy["inbound_vpn"]["base64"] == "block"
    assert policy["outbound"]["text"] == "mask"
    assert set(policy["placeholders"]) >= {
        "PERSON",
        "MRN",
        "RECORD_ID",
        "ACCOUNT_ID",
        "NPI",
        "US_SSN",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CREDIT_CARD",
        "LOCATION",
        "DATE_OF_BIRTH",
    }
    corpus = _corpus()
    assert corpus["cases"]
    entities = {case["entity"] for case in corpus["cases"]}
    assert entities == set(policy["placeholders"])


def test_every_fixture_is_masked_or_blocked_in_both_directions(stack):
    policy = _policy()
    corpus = _corpus()
    redactor = stack["runtime"].service.redactor

    def redact(payload):
        return stack["vpn"].portal.call(redactor.redact, payload)

    for case in corpus["cases"]:
        payload, form = _payload(case)
        placeholder = policy["placeholders"][case["entity"]]
        decision = policy["inbound_vpn"][form]
        if decision == "block":
            with pytest_raises_reason(stack, payload, policy["block_reasons"][form], case["value"]):
                pass
        else:
            rewritten, _counts = redact(payload)
            rendered = json.dumps(rewritten)
            assert case["value"] not in rendered, case
            assert placeholder in rendered, case
            before = len(stack["runtime"].upstreams["stackjack"].calls)
            response = mcp_call(
                stack["vpn"],
                SECRETS["claude_local_token"],
                "stackjack_search_docs",
                {"query": payload if isinstance(payload, str) else case["value"], "limit": 1},
            )
            assert response.status_code == 200, case
            forwarded = json.dumps(stack["runtime"].upstreams["stackjack"].calls[-1].arguments)
            assert case["value"] not in forwarded, case
            assert placeholder in forwarded, case
            assert len(stack["runtime"].upstreams["stackjack"].calls) == before + 1

        outbound_decision = policy["outbound"][form]
        outbound_payload = payload if form != "text" else {"summary": case["value"]}
        if outbound_decision == "block":
            with pytest_raises_reason(stack, outbound_payload, policy["block_reasons"][form], case["value"]):
                pass
        else:
            rewritten, _counts = redact(outbound_payload)
            rendered = json.dumps(rewritten)
            assert case["value"] not in rendered, case
            assert placeholder in rendered, case

        if form == "text":
            before = len(stack["runtime"].upstreams["stackjack"].calls)
            blocked = mcp_call(
                stack["cloudflare"],
                SECRETS["grok_bot_token"],
                "stackjack_search_docs",
                {"query": case["value"], "limit": 1},
                cloudflare=True,
            )
            assert "phi_in_cloudflare_tool_args" in tool_text(blocked), case
            assert case["value"] not in blocked.text
            assert len(stack["runtime"].upstreams["stackjack"].calls) == before


class pytest_raises_reason:
    def __init__(self, stack, payload, reason: str, secret: str) -> None:
        self.stack = stack
        self.payload = payload
        self.reason = reason
        self.secret = secret

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, _tb) -> bool:
        redactor = self.stack["runtime"].service.redactor
        try:
            self.stack["vpn"].portal.call(redactor.redact, self.payload)
        except FailClosed as caught:
            assert caught.reason_code == self.reason
            assert self.secret not in caught.reason_code
            return exc_type is None
        raise AssertionError(f"expected {self.reason}")


def test_negatives_pass_through_the_local_redactor(stack):
    corpus = _corpus()
    redactor = stack["runtime"].service.redactor
    for negative in corpus["negatives"]:
        rewritten, _counts = stack["vpn"].portal.call(redactor.redact, f"ticket {negative} end")
        assert negative in rewritten
