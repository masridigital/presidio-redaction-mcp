"""Caller tokens are bound to one ingress. The wrong door is 401 and makes no upstream call."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from presidio_redaction_mcp.auth import authenticate
from presidio_redaction_mcp.config import load_settings
from presidio_redaction_mcp.errors import AuthError, ConfigError
from tests.conftest import SECRETS, grok_call, mcp_call, mcp_headers, tool_text

ROOT = Path(__file__).resolve().parents[1]


def _calls(stack) -> int:
    return len(stack["runtime"].upstreams["stackjack"].calls) + len(stack["runtime"].upstreams["composio"].calls)


@pytest.mark.parametrize(
    ("token", "status", "reason"),
    [
        ("grok_bot_token", 401, "ingress_not_allowed"),
        ("claude_local_token", 200, None),
        ("open_webui_token", 200, None),
        (None, 401, "invalid_token"),
        ("not-a-token", 401, "invalid_token"),
    ],
)
def test_ingress_matrix(stack, token, status, reason):
    before = _calls(stack)
    headers = mcp_headers(SECRETS.get(token, token or ""))
    if token is None:
        headers.pop("Authorization", None)
    elif token == "":
        headers["Authorization"] = "Bearer "
    response = stack["vpn"].post(
        "/mcp/",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "stackjack_health_check", "arguments": {"limit": 1}},
        },
    )
    assert response.status_code == status
    if reason:
        assert response.json()["reason_code"] == reason
        assert _calls(stack) == before
    else:
        assert "MRN-SYN-0001234" not in tool_text(response)


def test_cloudflare_mark_has_no_listener(stack):
    for token in (SECRETS["grok_bot_token"], SECRETS["claude_local_token"], SECRETS["open_webui_token"]):
        with pytest.raises(AuthError) as caught:
            authenticate(
                stack["runtime"].settings.callers,
                ingress="cloudflare",
                authorization=f"Bearer {token}",
            )
        assert caught.value.reason_code == "ingress_not_allowed"


def test_cloudflare_phi_is_blocked_and_vpn_phi_is_masked(stack):
    before = _calls(stack)
    blocked = grok_call(
        stack,
        "stackjack_search_docs",
        {"query": "Testy McFakerson MRN-SYN-0001234", "limit": 1},
    )
    assert "phi_in_cloudflare_tool_args" in tool_text(blocked)
    assert _calls(stack) == before
    assert "MRN-SYN-0001234" not in blocked.text

    masked = mcp_call(
        stack["vpn"],
        SECRETS["open_webui_token"],
        "stackjack_search_docs",
        {"query": "Testy McFakerson MRN-SYN-0001234", "limit": 1},
    )
    assert masked.status_code == 200
    forwarded = json_arguments(stack)
    assert "MRN-SYN-0001234" not in forwarded
    assert "<MRN>" in forwarded
    assert "<PERSON>" in forwarded
    rows = [row for row in stack["runtime"].audit.rows() if row["event"] == "tool_call"]
    assert rows[-1]["caller"] == "open-webui"
    assert rows[-1]["ingress"] == "vpn"
    assert rows[-1]["phi_capable"] is False
    grok_rows = [row for row in rows if row["reason_code"] == "phi_in_cloudflare_tool_args"]
    assert grok_rows[-1]["caller"] == "grok-bot"
    assert grok_rows[-1]["ingress"] == "cloudflare"
    assert grok_rows[-1]["phi_capable"] is False


def json_arguments(stack) -> str:
    import json

    call = stack["runtime"].upstreams["stackjack"].calls[-1]
    return json.dumps(call.arguments)


def test_there_is_no_baa_switch_for_grok(tmp_path, monkeypatch):
    monkeypatch.setenv("PRM_ENV", "test")
    for name, value in SECRETS.items():
        monkeypatch.setenv(f"PRM_SECRET_{name.upper()}", value)
    raw = yaml.safe_load((ROOT / "config" / "allowlist.yaml").read_text(encoding="utf-8"))

    def dump(mutated: dict) -> Path:
        path = tmp_path / "allowlist.yaml"
        path.write_text(yaml.safe_dump(mutated), encoding="utf-8")
        (tmp_path / "recognizers.yaml").write_text(
            (ROOT / "config" / "recognizers.yaml").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        return path

    cases = []
    phi = copy.deepcopy(raw)
    phi["callers"]["grok-bot"]["phi_capable"] = True
    cases.append(phi)
    door = copy.deepcopy(raw)
    door["callers"]["grok-bot"]["allowed_ingress"] = ["vpn"]
    cases.append(door)
    both = copy.deepcopy(raw)
    both["callers"]["claude-local"]["allowed_ingress"] = ["cloudflare"]
    cases.append(both)
    flag = copy.deepcopy(raw)
    flag["callers"]["grok-bot"]["baa"] = True
    cases.append(flag)
    webui = copy.deepcopy(raw)
    webui["callers"]["open-webui"]["cf_access_client_id_secret"] = "open_webui_cf_id"
    cases.append(webui)
    for mutated in cases:
        with pytest.raises(ConfigError):
            load_settings(dump(mutated), env="test")


def test_prefix_of_a_token_is_not_accepted(stack):
    before = _calls(stack)
    response = mcp_call(stack["vpn"], SECRETS["claude_local_token"][:8], "stackjack_health_check", {"limit": 1})
    assert response.status_code == 401
    assert response.json()["reason_code"] == "invalid_token"
    assert _calls(stack) == before
