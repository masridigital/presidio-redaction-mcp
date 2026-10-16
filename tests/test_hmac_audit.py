"""Keyed HMAC of tool arguments. The audit row stores the digest, never the arguments."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest

from presidio_redaction_mcp.errors import ConfigError
from tests.conftest import SECRETS, mcp_call, tool_text

KEY = SECRETS["audit_hmac_key"].encode("utf-8")


def _hmac(arguments: dict) -> str:
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hmac.new(KEY, canonical, hashlib.sha256).hexdigest()


def _allow_row(stack) -> dict:
    rows = [
        row
        for row in stack["runtime"].audit.rows()
        if row["event"] == "tool_call" and row["decision"] == "allow"
    ]
    assert rows
    return rows[-1]


def test_audit_hmac_matches_the_keyed_canonical_json(stack):
    arguments = {"query": "MRN-SYN-0001234", "limit": 2}
    response = mcp_call(stack["vpn"], SECRETS["claude_local_token"], "stackjack_search_docs", arguments)
    assert response.status_code == 200
    row = _allow_row(stack)
    assert row["args_hmac"] == _hmac(arguments)
    assert row["args_hmac"] == _hmac({"limit": 2, "query": "MRN-SYN-0001234"})
    unsalted = hashlib.sha256(
        json.dumps(arguments, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    spaced = hmac.new(
        KEY,
        json.dumps(arguments, sort_keys=True).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    other_key = hmac.new(b"another-test-key-not-a-secret-0000", json.dumps(arguments, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
    assert row["args_hmac"] != unsalted
    assert row["args_hmac"] != spaced
    assert row["args_hmac"] != other_key
    redacted = _hmac({"query": "<MRN>", "limit": 2})
    assert row["args_hmac"] != redacted


def test_denied_call_still_hmacs_the_raw_arguments(stack):
    arguments = {"limit": 100}
    response = mcp_call(stack["vpn"], SECRETS["claude_local_token"], "stackjack_list_advisories", arguments)
    assert "pagination_cap_exceeded" in tool_text(response)
    row = [item for item in stack["runtime"].audit.rows() if item["event"] == "tool_call"][-1]
    assert row["decision"] == "deny"
    assert row["args_hmac"] == _hmac(arguments)
    blob = stack["runtime"].audit.path.read_text(encoding="utf-8")
    for secret in SECRETS.values():
        assert secret not in blob
    assert "100" not in row["args_hmac"]


def test_audit_file_mode_is_owner_only_and_config_change_has_no_args(stack):
    mode = stack["runtime"].audit.path.stat().st_mode & 0o777
    assert mode == 0o600
    changes = [row for row in stack["runtime"].audit.rows() if row["event"] == "config_change"]
    assert changes
    assert changes[0]["reason_code"] == "config_loaded"
    assert "args_hmac" not in changes[0]
    assert changes[0]["config_sha256"]


def test_short_hmac_key_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("PRM_ENV", "test")
    for name, value in SECRETS.items():
        monkeypatch.setenv(f"PRM_SECRET_{name.upper()}", value)
    monkeypatch.setenv("PRM_SECRET_AUDIT_HMAC_KEY", "too-short")
    from presidio_redaction_mcp.config import load_settings

    with pytest.raises(ConfigError) as caught:
        load_settings(Path(__file__).resolve().parents[1] / "config" / "allowlist.yaml", env="test")
    assert caught.value.reason_code == "hmac_key_too_short"
