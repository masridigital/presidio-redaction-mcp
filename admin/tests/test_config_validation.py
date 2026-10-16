from __future__ import annotations

import json

import pytest

from presidio_admin.errors import ConfigRejected
from presidio_admin.proxy_loader import load_for_proxy
from presidio_admin.schema import default_config, parse_config
from presidio_admin.store import ConfigStore


def test_default_config_is_default_deny() -> None:
    config = default_config()
    assert set(config.upstreams) == {"stackjack", "composio"}
    assert config.enabled_tools() == []
    assert config.claude_verifier_enabled is False
    assert config.score_threshold == 0.4
    assert config.clients == []
    for upstream in config.upstreams.values():
        assert all(tool.read_only is True and tool.enabled is False for tool in upstream.tools)


def test_unknown_upstream_write_tool_and_low_scores_are_rejected() -> None:
    payload = default_config().model_dump(mode="json")
    extra = json.loads(json.dumps(payload))
    extra["upstreams"]["halo"] = extra["upstreams"]["stackjack"]
    with pytest.raises(ConfigRejected):
        parse_config(extra)

    renamed = default_config().model_dump(mode="json")
    renamed["upstreams"]["stackjack"]["tools"][0]["name"] = "stackjack_send_mail"
    with pytest.raises(ConfigRejected):
        parse_config(renamed)

    writable = default_config().model_dump(mode="json")
    writable["upstreams"]["stackjack"]["tools"][0]["read_only"] = False
    with pytest.raises(ConfigRejected):
        parse_config(writable)

    low_floor = default_config().model_dump(mode="json")
    low_floor["score_threshold"] = 0.2
    with pytest.raises(ConfigRejected):
        parse_config(low_floor)

    low_pattern = default_config().model_dump(mode="json")
    low_pattern["recognizers"][0]["patterns"][0]["score"] = 0.5
    with pytest.raises(ConfigRejected):
        parse_config(low_pattern)

    secret_field = default_config().model_dump(mode="json")
    secret_field["clients"] = [
        {
            "client_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
            "display_name": "Synthetic Reader",
            "app_role": "PHI",
            "enabled": True,
            "client_secret": "not-stored",
        }
    ]
    with pytest.raises(ConfigRejected):
        parse_config(secret_field)


def test_duplicate_client_and_email_display_name_are_rejected() -> None:
    payload = default_config().model_dump(mode="json")
    client = {
        "client_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
        "display_name": "Synthetic Reader",
        "app_role": "Other",
        "enabled": True,
    }
    payload["clients"] = [client]
    with pytest.raises(ConfigRejected):
        parse_config(payload)
    client["app_role"] = "PHI"
    client["display_name"] = "person@example.com"
    payload["clients"] = [client]
    with pytest.raises(ConfigRejected):
        parse_config(payload)
    client["display_name"] = "Synthetic Reader"
    payload["clients"] = [client, dict(client)]
    with pytest.raises(ConfigRejected):
        parse_config(payload)


def test_proxy_reader_fails_closed_on_a_tampered_or_missing_store(tmp_path, hmac_key: bytes, audit_key: bytes) -> None:
    with pytest.raises(ConfigRejected):
        load_for_proxy(tmp_path / "missing", store_key=hmac_key, audit_key=audit_key)

    store = ConfigStore(tmp_path / "store", store_key=hmac_key, audit_key=audit_key)
    store.bootstrap(default_config())
    loaded = load_for_proxy(store.root, store_key=hmac_key, audit_key=audit_key)
    assert loaded.config.enabled_tools() == []

    pointer = json.loads((store.root / "active.json").read_text(encoding="utf-8"))
    pointer["sha256"] = "0" * 64
    (store.root / "active.json").write_text(json.dumps(pointer), encoding="utf-8")
    with pytest.raises(ConfigRejected) as caught:
        load_for_proxy(store.root, store_key=hmac_key, audit_key=audit_key)
    assert caught.value.reason_code == "store_signature_invalid"

    with pytest.raises(ConfigRejected):
        load_for_proxy(store.root, store_key=b"k" * 32, audit_key=audit_key)


def test_a_signed_older_pointer_is_a_rollback(tmp_path, hmac_key: bytes, audit_key: bytes) -> None:
    store = ConfigStore(tmp_path / "store", store_key=hmac_key, audit_key=audit_key)
    store.bootstrap(default_config())
    first = (store.root / "active.json").read_bytes()
    tightened = default_config().model_copy(deep=True)
    data = tightened.model_dump(mode="json")
    data["upstreams"]["stackjack"]["enabled"] = False
    store.publish(
        parse_config(data),
        actor_oid="11111111-1111-4111-8111-111111111111",
        approver_oid=None,
        summary=["disable stackjack"],
        proposal_id="",
        action="publish",
    )
    assert store.read_active().version_id == 2
    (store.root / "active.json").write_bytes(first)
    with pytest.raises(ConfigRejected) as caught:
        load_for_proxy(store.root, store_key=hmac_key, audit_key=audit_key)
    assert caught.value.reason_code == "version_rollback"


def test_equal_hmac_keys_are_rejected(tmp_path) -> None:
    with pytest.raises(ConfigRejected) as caught:
        ConfigStore(tmp_path / "same", store_key=b"s" * 32, audit_key=b"s" * 32)
    assert caught.value.reason_code == "hmac_keys_must_differ"


def test_short_hmac_key_is_rejected(tmp_path) -> None:
    with pytest.raises(ConfigRejected) as caught:
        ConfigStore(tmp_path / "short", store_key=b"too-short", audit_key=b"a" * 32)
    assert caught.value.reason_code == "hmac_key_too_short"
