"""Default deny: unknown tools, wildcards, write verbs, and empty tool lists."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml
from starlette.testclient import TestClient

from presidio_redaction_mcp.config import load_settings
from presidio_redaction_mcp.errors import ConfigError, PolicyError
from presidio_redaction_mcp.factory import build_runtime
from presidio_redaction_mcp.audit import AuditLog
from tests.conftest import SECRETS, mcp_call, tool_text

ROOT = Path(__file__).resolve().parents[1]

REJECTED_NAMES = [
    "stackjack_*",
    "stackjack_health?",
    "stackjack_health[0]",
    "all_tools",
    "stackjack_list_all",
    "stackjack_list-all",
    "stackjack_export_notes",
    "stackjack_send_file",
    "stackjack_write_note",
    "stackjack_create_item",
    "stackjack_update_item",
    "stackjack_delete_item",
    "stackjack_bulk_fetch",
    "stackjack_download_dump",
    "stackjack_upload_file",
    "stackjack_post_status",
    "stackjack_put_status",
    "stackjack_patch_status",
    "stackjack_insert_row",
    "stackjack_remove_row",
    "stackjack_execute_job",
    "stackjack_reply_note",
    "stackjack_forward_note",
    "stackjack_share_note",
    "stackjack_add_note",
    "stackjack_edit_note",
    "stackjack_new_note",
]


def _raw() -> dict:
    return yaml.safe_load((ROOT / "config" / "allowlist.yaml").read_text(encoding="utf-8"))


def _load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutated: dict):
    monkeypatch.setenv("PRM_ENV", "test")
    for name, value in SECRETS.items():
        monkeypatch.setenv(f"PRM_SECRET_{name.upper()}", value)
    path = tmp_path / "allowlist.yaml"
    path.write_text(yaml.safe_dump(mutated), encoding="utf-8")
    recognizers = tmp_path / "recognizers.yaml"
    recognizers.write_text((ROOT / "config" / "recognizers.yaml").read_text(encoding="utf-8"), encoding="utf-8")
    return load_settings(path, env="test")


def _reject(tmp_path, monkeypatch, mutate) -> None:
    raw = copy.deepcopy(_raw())
    mutate(raw)
    with pytest.raises(ConfigError):
        _load(tmp_path, monkeypatch, raw)


def test_committed_allowlist_is_two_upstreams_and_has_no_wildcards():
    raw = _raw()
    assert set(raw["upstreams"]) == {"stackjack", "composio"}
    assert "default_allow" not in raw
    assert raw["upstreams"]["stackjack"]["tools"]
    assert raw["upstreams"]["composio"]["tools"]
    for upstream in raw["upstreams"].values():
        for tool in upstream["tools"]:
            for field in ("name", "toolkit", "action_id"):
                if tool.get(field):
                    assert not any(char in tool[field] for char in "*?[]")
            for arg in tool["arguments"]:
                assert not any(char in arg["name"] for char in "*?[]")
            for field in tool["allowed_result_fields"]:
                assert not any(char in field for char in "*?[]")
            assert tool["read_only"] is True
            assert tool["phi_scope"] == "none"


def test_unknown_tool_is_denied_and_not_forwarded(stack):
    response = mcp_call(stack["vpn"], SECRETS["claude_local_token"], "stackjack_export_clients", {})
    assert "tool_not_allowlisted" in tool_text(response)
    assert stack["runtime"].upstreams["stackjack"].calls == []
    assert stack["runtime"].upstreams["composio"].calls == []
    assert "stackjack_export_clients" not in stack["runtime"].audit.path.read_text(encoding="utf-8")


@pytest.mark.parametrize("name", REJECTED_NAMES)
def test_wildcard_and_write_names_fail_to_load(tmp_path, monkeypatch, name):
    def mutate(raw: dict) -> None:
        raw["upstreams"]["stackjack"]["tools"][0]["name"] = name

    _reject(tmp_path, monkeypatch, mutate)


def test_wildcard_field_and_argument_names_fail_to_load(tmp_path, monkeypatch):
    _reject(tmp_path, monkeypatch, lambda raw: raw["upstreams"]["stackjack"]["tools"][0]["allowed_result_fields"].append("*"))
    _reject(
        tmp_path,
        monkeypatch,
        lambda raw: raw["upstreams"]["stackjack"]["tools"][0]["arguments"].append(
            {"name": "query*", "type": "string"}
        ),
    )


def test_other_upstream_shapes_fail_to_load(tmp_path, monkeypatch):
    def extra(raw: dict) -> None:
        raw["upstreams"]["halo"] = copy.deepcopy(raw["upstreams"]["stackjack"])
        raw["upstreams"]["halo"]["kind"] = "stackjack"

    def missing(raw: dict) -> None:
        del raw["upstreams"]["composio"]

    def http_url(raw: dict) -> None:
        raw["upstreams"]["stackjack"]["base_url"] = "http://stackjack.invalid/mcp"

    def cloudflare_url(raw: dict) -> None:
        raw["upstreams"]["stackjack"]["base_url"] = "https://stackjack.trycloudflare.com/mcp"

    def default_allow(raw: dict) -> None:
        raw["default_allow"] = True

    def read_only_false(raw: dict) -> None:
        raw["upstreams"]["stackjack"]["tools"][0]["read_only"] = False

    def phi_scope(raw: dict) -> None:
        raw["upstreams"]["stackjack"]["tools"][0]["phi_scope"] = "phi"

    def page_cap(raw: dict) -> None:
        raw["upstreams"]["stackjack"]["tools"][0]["max_items"] = 21

    def empty_fields(raw: dict) -> None:
        raw["upstreams"]["stackjack"]["tools"][0]["allowed_result_fields"] = []

    def missing_pin(raw: dict) -> None:
        raw["upstreams"]["composio"]["tools"][0]["connected_account_id"] = None

    for mutate in (extra, missing, http_url, cloudflare_url, default_allow, read_only_false, phi_scope, page_cap, empty_fields, missing_pin):
        _reject(tmp_path, monkeypatch, mutate)


def test_empty_tool_lists_load_and_deny_every_call(tmp_path, monkeypatch):
    raw = copy.deepcopy(_raw())
    raw["upstreams"]["stackjack"]["tools"] = []
    raw["upstreams"]["composio"]["tools"] = []
    settings = _load(tmp_path, monkeypatch, raw)
    audit = AuditLog(tmp_path / "audit.jsonl", tmp_path / "config-sha")
    runtime = build_runtime(settings, audit)
    with TestClient(runtime.vpn_app, base_url="http://testserver") as client:
        response = mcp_call(client, SECRETS["claude_local_token"], "stackjack_health_check", {"limit": 1})
    assert "tool_not_allowlisted" in tool_text(response)
    assert runtime.upstreams["stackjack"].calls == []


def test_star_test_host_is_not_a_wildcard(tmp_path, monkeypatch):
    raw = copy.deepcopy(_raw())
    raw["egress"]["test_hosts"] = ["*", "*.example", "evil.example"]
    settings = _load(tmp_path, monkeypatch, raw)
    with pytest.raises(PolicyError):
        settings.egress.check("https://example.com/mcp", purpose="upstream")
    with pytest.raises(PolicyError):
        settings.egress.check("https://backend.composio.dev/mcp", purpose="upstream")
    assert settings.egress.check("https://stackjack.invalid/mcp", purpose="upstream") == "stackjack.invalid"
