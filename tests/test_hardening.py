from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from presidio_redaction_mcp.app import _is_blocked_payload
from presidio_redaction_mcp.audit import AuditLog
from presidio_redaction_mcp.auth import authenticate
from presidio_redaction_mcp.config import load_settings
from presidio_redaction_mcp.errors import AuthError, ConfigError, FailClosed
from tests.conftest import SECRETS, mcp_call, mcp_headers

ROOT = Path(__file__).resolve().parents[1]


def test_cloudflared_artifacts_are_gone():
    assert not (ROOT / "deploy" / "cloudflared").exists()
    assert not (ROOT / "deploy" / "systemd" / "cloudflared.service").exists()
    assert not (ROOT / "src" / "presidio_redaction_mcp" / "tunnel.py").exists()
    assert not (ROOT / "src" / "presidio_redaction_mcp" / "access_jwt.py").exists()
    assert not (ROOT / "deploy" / "ufw" / "cloudflare-ipv4.txt").exists()


def test_cloudflare_access_jwt_is_not_accepted(stack):
    assert not (ROOT / "src" / "presidio_redaction_mcp" / "access_jwt.py").exists()
    headers = mcp_headers(SECRETS["grok_bot_token"], cloudflare=False)
    headers["Cf-Access-Jwt-Assertion"] = "header.payload.signature"
    headers["X-MS-CLIENT-PRINCIPAL"] = "claude-local"
    response = stack["cloudflare"].post(
        "/mcp/",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "stackjack_health_check", "arguments": {"limit": 1}}},
    )
    assert response.status_code == 401
    assert response.json()["reason_code"] == "cf_service_token_required"
    blob = stack["runtime"].audit.path.read_text(encoding="utf-8")
    assert "header.payload.signature" not in blob
    with pytest.raises(AuthError) as denied:
        authenticate(stack["runtime"].settings.callers, ingress="private", authorization="Bearer not-a-jwt")
    assert denied.value.reason_code == "entra_required"


def test_duplicate_placeholder_and_env_secrets_are_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("PRM_ENV", "test")
    raw = yaml.safe_load((ROOT / "config" / "allowlist.yaml").read_text(encoding="utf-8"))
    path = tmp_path / "allowlist.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    (tmp_path / "recognizers.yaml").write_text(
        (ROOT / "config" / "recognizers.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    for name, value in SECRETS.items():
        monkeypatch.setenv(f"PRM_SECRET_{name.upper()}", value)
    monkeypatch.setenv("PRM_SECRET_CLAUDE_LOCAL_TOKEN", SECRETS["grok_bot_token"])
    with pytest.raises(ConfigError) as duplicate:
        load_settings(path, env="test")
    assert duplicate.value.reason_code == "duplicate_secret_value"

    monkeypatch.setenv("PRM_SECRET_CLAUDE_LOCAL_TOKEN", SECRETS["claude_local_token"])
    monkeypatch.setenv("PRM_SECRET_GROK_BOT_TOKEN", "replace-with-vault-token-but-long-enough-0123456789abcdef")
    with pytest.raises(ConfigError) as placeholder:
        load_settings(path, env="test")
    assert placeholder.value.reason_code == "secret_placeholder"

    monkeypatch.setenv("PRM_SECRET_GROK_BOT_TOKEN", "a" * 40)
    with pytest.raises(ConfigError) as low:
        load_settings(path, env="test")
    assert low.value.reason_code == "secret_low_entropy"

    monkeypatch.setenv("PRM_ENV", "production")
    monkeypatch.setenv("PRM_SECRET_GROK_BOT_TOKEN", SECRETS["grok_bot_token"])
    for name in SECRETS:
        monkeypatch.delenv(f"PRM_SECRET_FILE_{name.upper()}", raising=False)
    with pytest.raises(ConfigError) as denied:
        load_settings(ROOT / "config" / "allowlist.yaml", env="production")
    assert denied.value.reason_code == "secret_env_fallback_denied"


def test_read_verb_allowlist_rejects_a_non_read_tool(tmp_path, monkeypatch):
    monkeypatch.setenv("PRM_ENV", "test")
    for name, value in SECRETS.items():
        monkeypatch.setenv(f"PRM_SECRET_{name.upper()}", value)
    raw = yaml.safe_load((ROOT / "config" / "allowlist.yaml").read_text(encoding="utf-8"))
    tool = json.loads(json.dumps(raw["upstreams"]["stackjack"]["tools"][0]))
    tool["name"] = "stackjack_run_check"
    raw["upstreams"]["stackjack"]["tools"].append(tool)
    path = tmp_path / "allowlist.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    (tmp_path / "recognizers.yaml").write_text(
        (ROOT / "config" / "recognizers.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError):
        load_settings(path, env="test")


def test_unexpected_exception_is_audited_and_list_results_are_not_errors(stack, monkeypatch):
    async def boom(_tool, _arguments):
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(stack["runtime"].upstreams["stackjack"], "call", boom)
    response = mcp_call(stack["vpn"], SECRETS["claude_local_token"], "stackjack_health_check", {"limit": 1})
    assert "internal_error" in response.text
    assert "synthetic failure" not in response.text
    reasons = [row["reason_code"] for row in stack["runtime"].audit.rows()]
    assert "internal_error" in reasons
    assert _is_blocked_payload('["status"]') is False
    assert _is_blocked_payload('{"error":"blocked","reason_code":"x"}') is True


def test_rate_limit_and_nesting_caps(stack):
    stack["runtime"].settings.allowlist.limits.requests_per_minute = 1
    first = mcp_call(stack["vpn"], SECRETS["claude_local_token"], "stackjack_health_check", {"limit": 1})
    second = mcp_call(stack["vpn"], SECRETS["claude_local_token"], "stackjack_health_check", {"limit": 1})
    assert first.status_code == 200
    assert "rate_limited" in second.text
    nested: dict = {"status": "ok"}
    cursor = nested
    for _ in range(8):
        cursor["child"] = {"status": "ok"}
        cursor = cursor["child"]
    with pytest.raises(FailClosed) as caught:
        stack["vpn"].portal.call(stack["runtime"].service.redactor.redact, nested)
    assert caught.value.reason_code == "nesting_too_deep"


def test_audit_hash_chain_and_file_forward(tmp_path):
    key = b"0123456789abcdef0123456789abcdef"
    forward = tmp_path / "siem.log"
    audit = AuditLog(tmp_path / "audit.jsonl", tmp_path / "state", key, forward=f"file:{forward}")
    audit.record(
        caller="claude-local",
        ingress="vpn",
        phi_capable=True,
        upstream="stackjack",
        tool="stackjack_health_check",
        args_hmac="ab" * 32,
        entity_counts={},
        decision="allow",
        reason_code="ok",
        latency_ms=1,
        config_sha256="cd" * 32,
    )
    assert audit.verify()
    forwarded = forward.read_text(encoding="utf-8")
    assert "stackjack_health_check" in forwarded
    row = audit.rows()[-1]
    row["caller"] = "tampered"
    audit.path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    assert audit.verify() is False
