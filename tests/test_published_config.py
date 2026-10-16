"""The proxy reads the published store and fails closed when it is not valid."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from presidio_admin.schema import default_config, parse_config
from presidio_admin.store import ConfigStore
from presidio_redaction_mcp.auth import CallerIdentity
from presidio_redaction_mcp.config import assert_published_store, load_settings
from presidio_redaction_mcp.errors import ConfigError
from presidio_redaction_mcp.published_config import apply_published, load_published_or_fail

ROOT = Path(__file__).resolve().parents[1]
STORE_KEY = b"s" * 32
AUDIT_KEY = b"a" * 32


def _settings(monkeypatch: pytest.MonkeyPatch):
    from tests.conftest import apply_test_secrets

    apply_test_secrets(monkeypatch)
    return load_settings(ROOT / "config" / "allowlist.yaml", env="test")


def test_published_reader_fails_closed_and_applies_thresholds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ConfigError):
        load_published_or_fail(tmp_path / "absent", store_key=STORE_KEY, audit_key=AUDIT_KEY)

    store = ConfigStore(tmp_path / "store", store_key=STORE_KEY, audit_key=AUDIT_KEY)
    config = default_config().model_copy(update={"score_threshold": 0.55, "claude_verifier_enabled": True})
    data = config.model_dump(mode="json")
    for recognizer in data["recognizers"]:
        for pattern in recognizer["patterns"]:
            if pattern["name"] == "mrn_canonical":
                pattern["enabled"] = False
    data["clients"] = [
        {
            "client_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "display_name": "Synthetic PHI Reader",
            "app_role": "PHI",
            "enabled": True,
        },
        {
            "client_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "display_name": "Synthetic Workload",
            "app_role": "NonPHI",
            "enabled": True,
        },
    ]
    published = parse_config(data)
    store.bootstrap(default_config())
    store.publish(
        published,
        actor_oid="11111111-1111-4111-8111-111111111111",
        approver_oid="22222222-2222-4222-8222-222222222222",
        summary=["reviewed"],
        proposal_id="proposal",
        action="approve",
    )
    loaded = load_published_or_fail(store.root, store_key=STORE_KEY, audit_key=AUDIT_KEY)
    assert loaded.config.score_threshold == 0.55
    assert loaded.config.pattern_state()["mrn_canonical"][1] is False
    assert loaded.version_id == 2

    settings = apply_published(_settings(monkeypatch), loaded)
    assert settings.allowlist.presidio.score_threshold == 0.55
    assert settings.allowlist.verifier.enabled is True
    assert settings.published_version_id == 2
    assert settings.published_sha256 == loaded.sha256
    by_app = {client.app_id: client for client in settings.entra_clients}
    phi = by_app["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"]
    assert phi.phi_capable is True
    assert phi.human is True
    assert "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" in settings.baa_client_ids
    assert all(rule.name != "mrn_canonical" for rule in settings.recognizers.patterns)
    workload = by_app["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]
    assert workload.phi_capable is False
    assert workload.human is False
    assert "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" not in settings.baa_client_ids

    pointer = json.loads((store.root / "active.json").read_text(encoding="utf-8"))
    pointer["sha256"] = "ab" * 32
    (store.root / "active.json").write_text(json.dumps(pointer), encoding="utf-8")
    with pytest.raises(ConfigError) as caught:
        load_published_or_fail(store.root, store_key=STORE_KEY, audit_key=AUDIT_KEY)
    assert caught.value.reason_code == "store_signature_invalid"


def test_production_and_entra_require_the_published_store(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(monkeypatch)
    assert settings.allowlist.require_published_config is True
    assert_published_store(settings, None)
    production = settings.model_copy(update={"env": "production"})
    with pytest.raises(ConfigError) as caught:
        assert_published_store(production, None)
    assert caught.value.reason_code == "published_config_required"
    entra = settings.model_copy(update={"auth_mode": "entra"})
    with pytest.raises(ConfigError) as entra_caught:
        assert_published_store(entra, None)
    assert entra_caught.value.reason_code == "published_config_required"
    assert_published_store(production, "https://prm.blob.core.windows.net/prm-config")


def test_startup_log_and_healthz_name_the_published_version(stack, caplog) -> None:
    import logging

    from presidio_redaction_mcp.published_config import log_published

    settings = stack["runtime"].settings
    digest = "ab" * 32
    settings.published_version_id = 4
    settings.published_sha256 = digest
    body = stack["vpn"].get("/healthz").json()
    assert body["version_id"] == 4
    assert body["published_sha256"] == digest
    with caplog.at_level(logging.INFO, logger="presidio_redaction_mcp"):
        log_published(4, digest)
    assert "version_id=4" in caplog.text
    assert digest in caplog.text


def test_store_keys_must_differ_from_the_proxy_audit_key() -> None:
    from presidio_redaction_mcp.__main__ import _distinct_store_keys

    _distinct_store_keys(b"s" * 32, b"a" * 32, b"p" * 32)
    with pytest.raises(SystemExit):
        _distinct_store_keys(b"s" * 32, b"s" * 32, b"p" * 32)
    with pytest.raises(SystemExit):
        _distinct_store_keys(b"s" * 32, b"a" * 32, b"s" * 32)


def test_prod_templates_set_the_config_store_without_shared_keys() -> None:
    proxy = (ROOT / "infra" / "main.bicep").read_text(encoding="utf-8")
    portal = (ROOT / "infra" / "admin-portal.bicep").read_text(encoding="utf-8")
    assert "PRM_CONFIG_STORE" in proxy
    assert "PRM_CONFIG_STORE" in portal
    assert "allowSharedKeyAccess: false" in portal
    assert "listKeys(" not in portal
    assert "accountKey:" not in portal
    assert "client_secret" not in portal
    assert "maxReplicas: 1" in portal


async def test_unpublished_tool_is_denied(stack) -> None:
    service = stack["runtime"].service
    service._published_tools = frozenset()
    caller = CallerIdentity(name="claude-local", phi_capable=True, ingress="vpn")
    text = await service.call_tool(caller, "stackjack_health_check", {"limit": 1})
    assert "tool_not_allowlisted" in text
