"""Result blocking is not decided by phi_capable alone."""

from __future__ import annotations

import asyncio
import copy
from pathlib import Path

import pytest
import yaml

from presidio_redaction_mcp.auth import CallerIdentity
from presidio_redaction_mcp.config import load_settings
from presidio_redaction_mcp.errors import ConfigError
from presidio_redaction_mcp.upstream import MockUpstream
from tests.conftest import SECRETS, build_test_runtime
from tests.presidio_double import PresidioDouble

ROOT = Path(__file__).resolve().parents[1]
CLAUDE = "11111111-1111-4111-8111-111111111111"
WEBUI = "22222222-2222-4222-8222-222222222222"


def _load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutated: dict):
    monkeypatch.setenv("PRM_ENV", "test")
    for name, value in SECRETS.items():
        monkeypatch.setenv(f"PRM_SECRET_{name.upper()}", value)
    path = tmp_path / "allowlist.yaml"
    path.write_text(yaml.safe_dump(mutated), encoding="utf-8")
    (tmp_path / "recognizers.yaml").write_text(
        (ROOT / "config" / "recognizers.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return load_settings(path, env="test")


def test_open_webui_stays_non_phi_until_local_ai_stack_clears():
    raw = yaml.safe_load((ROOT / "config" / "allowlist.yaml").read_text(encoding="utf-8"))
    assert raw["callers"]["open-webui"]["phi_capable"] is False
    assert raw["callers"]["open-webui"]["baa"] is False
    assert raw["callers"]["claude-local"]["phi_capable"] is True
    assert raw["callers"]["claude-local"]["baa"] is True


def test_cloudflare_ingress_cannot_be_phi_capable(tmp_path, monkeypatch):
    raw = yaml.safe_load((ROOT / "config" / "allowlist.yaml").read_text(encoding="utf-8"))
    mutated = copy.deepcopy(raw)
    mutated["callers"]["edge-bot"] = {
        "phi_capable": True,
        "baa": False,
        "allowed_ingress": ["cloudflare"],
        "token_secret": "edge_bot_token",
        "cf_access_client_id_secret": "edge_cf_id",
        "cf_access_client_secret_secret": "edge_cf_secret",
    }
    monkeypatch.setenv("PRM_SECRET_EDGE_BOT_TOKEN", SECRETS["grok_bot_token"][:-4] + "abcd")
    monkeypatch.setenv("PRM_SECRET_EDGE_CF_ID", SECRETS["grok_cf_access_client_id"][:-4] + "abcd")
    monkeypatch.setenv("PRM_SECRET_EDGE_CF_SECRET", SECRETS["grok_cf_access_client_secret"][:-4] + "abcd")
    with pytest.raises(ConfigError) as caught:
        _load(tmp_path, monkeypatch, mutated)
    assert caught.value.reason_code == "cloudflare_ingress_cannot_be_phi_capable"


def _phi_upstream():
    stackjack = MockUpstream(name="stackjack", base_url="https://stackjack.invalid/mcp")
    stackjack.result_body = {"status": "operational", "summary": "record MRN-SYN-0001234"}
    composio = MockUpstream(name="composio", base_url="https://composio.invalid/mcp")
    return stackjack, composio


def test_cloudflare_ingress_blocks_a_phi_capable_result(tmp_path, monkeypatch):
    stackjack, composio = _phi_upstream()
    double = PresidioDouble()
    runtime = build_test_runtime(
        tmp_path,
        monkeypatch,
        double.transport(),
        upstreams={"stackjack": stackjack, "composio": composio},
    )
    caller = CallerIdentity(name="claude-local", phi_capable=True, ingress="cloudflare")
    try:
        text = asyncio.run(runtime.service.call_tool(caller, "stackjack_health_check", {"limit": 1}))
        assert "phi_in_non_baa_tool_result" in text
        assert "MRN-SYN-0001234" not in text
        assert "<MRN>" not in text
    finally:
        asyncio.run(runtime.presidio.aclose())


def test_entra_client_off_the_baa_allowlist_is_blocked(tmp_path, monkeypatch):
    stackjack, composio = _phi_upstream()
    double = PresidioDouble()
    runtime = build_test_runtime(
        tmp_path,
        monkeypatch,
        double.transport(),
        upstreams={"stackjack": stackjack, "composio": composio},
    )
    runtime.service.settings.baa_client_ids = frozenset({CLAUDE})
    off = CallerIdentity(
        name="open-webui",
        phi_capable=True,
        ingress="private",
        authn="entra",
        client_id=WEBUI,
    )
    on = CallerIdentity(
        name="claude-local",
        phi_capable=True,
        ingress="private",
        authn="entra",
        client_id=CLAUDE,
    )
    try:
        blocked = asyncio.run(runtime.service.call_tool(off, "stackjack_health_check", {"limit": 1}))
        assert "phi_in_non_baa_tool_result" in blocked
        assert "<MRN>" not in blocked
        assert "MRN-SYN-0001234" not in blocked
        masked = asyncio.run(runtime.service.call_tool(on, "stackjack_health_check", {"limit": 1}))
        assert "<MRN>" in masked
        assert "MRN-SYN-0001234" not in masked
        assert "phi_in_non_baa_tool_result" not in masked
    finally:
        asyncio.run(runtime.presidio.aclose())
