from __future__ import annotations

import io
import json
import logging
import sys

import pytest

from presidio_admin.errors import ApprovalError, ConfigRejected, alert_logger
from presidio_admin.floor import LocalVersionFloor
from presidio_admin.proxy_loader import load_for_proxy
from presidio_admin.schema import default_config, parse_config
from presidio_admin.signing import RsaConfigSigner
from presidio_admin.store import ConfigStore


def test_store_signature_invalid_is_the_only_alert() -> None:
    logger = alert_logger()
    stderr_handlers = [handler for handler in logger.handlers if isinstance(handler, logging.StreamHandler)]
    assert logger.propagate is False
    assert len(stderr_handlers) == 1
    assert stderr_handlers[0].stream is sys.stderr
    buffer = io.StringIO()
    stderr_handlers[0].stream = buffer
    try:
        with pytest.raises(ConfigRejected):
            raise ConfigRejected("published_config_missing")
        with pytest.raises(ApprovalError):
            raise ApprovalError("stale_proposal")
        assert buffer.getvalue() == ""
        with pytest.raises(ApprovalError):
            raise ApprovalError("store_signature_invalid")
        assert buffer.getvalue() == "alert reason_code=store_signature_invalid\n"
    finally:
        stderr_handlers[0].stream = sys.stderr


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


def test_proxy_reader_fails_closed_on_a_tampered_or_missing_store(tmp_path, signer: RsaConfigSigner) -> None:
    verifier = signer.public_verifier()
    with pytest.raises(ConfigRejected):
        load_for_proxy(tmp_path / "missing", verifier=verifier)

    store = ConfigStore(tmp_path / "store", signer=signer)
    store.bootstrap(default_config())
    loaded = load_for_proxy(store.root, verifier=verifier)
    assert loaded.config.enabled_tools() == []

    version = store.root / "versions" / "000001.json"
    version.write_bytes(version.read_bytes().replace(b"sha256", b"sha000", 1))
    with pytest.raises(ConfigRejected) as caught:
        load_for_proxy(store.root, verifier=verifier)
    assert caught.value.reason_code == "store_signature_invalid"

    with pytest.raises(ConfigRejected) as signed:
        load_for_proxy(store.root, verifier=signer)
    assert signed.value.reason_code == "sign_not_permitted"


def test_a_signed_older_pointer_is_a_rollback(tmp_path, signer: RsaConfigSigner) -> None:
    verifier = signer.public_verifier()
    store = ConfigStore(tmp_path / "store", signer=signer)
    store.bootstrap(default_config())
    data = default_config().model_dump(mode="json")
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
    (store.root / "versions" / "000002.json").unlink()
    with pytest.raises(ConfigRejected) as caught:
        load_for_proxy(store.root, verifier=verifier)
    assert caught.value.reason_code == "version_rollback"


def test_several_publishes_do_not_overwrite_version_files(tmp_path, signer: RsaConfigSigner) -> None:
    from presidio_admin.documents import LocalDocuments

    class WriteOnce(LocalDocuments):
        def write(self, name: str, data: bytes, *, if_match: str | None = None, create: bool = False) -> str:
            if self.read(name) is not None:
                raise ConfigRejected("store_conflict")
            return super().write(name, data, if_match=if_match, create=True)

    root = tmp_path / "store"
    store = ConfigStore(root, signer=signer, documents=WriteOnce(root))
    store.bootstrap(default_config())
    actor = "11111111-1111-4111-8111-111111111111"
    for upstream in ("stackjack", "composio"):
        data = store.read_active().config.model_dump(mode="json")
        data["upstreams"][upstream]["enabled"] = False
        store.publish(
            parse_config(data),
            actor_oid=actor,
            approver_oid=None,
            summary=[f"disable {upstream}"],
            proposal_id="",
            action="publish",
        )
    data = store.read_active().config.model_dump(mode="json")
    data["upstreams"]["stackjack"]["tools"][0]["max_items"] = 5
    store.publish(
        parse_config(data),
        actor_oid=actor,
        approver_oid=None,
        summary=["lower max items"],
        proposal_id="",
        action="publish",
    )
    assert store.read_active().version_id == 4
    assert (root / "versions" / "000001.json").is_file()
    assert (root / "versions" / "000004.json").is_file()
    assert not (root / "active.json").exists()
    assert len((root / "audit.jsonl").read_text(encoding="utf-8").splitlines()) == 4
    with pytest.raises(ConfigRejected) as caught:
        store.documents.write("versions/000001.json", b"{}", create=True)
    assert caught.value.reason_code == "store_conflict"


def test_version_floor_rejects_a_signed_snapshot(tmp_path, signer: RsaConfigSigner) -> None:
    verifier = signer.public_verifier()
    store = ConfigStore(tmp_path / "store", signer=signer)
    store.bootstrap(default_config())
    floor = LocalVersionFloor(tmp_path / "outside" / "floor.jsonl")
    floor.advance(4, "ab" * 32)
    with pytest.raises(ConfigRejected) as caught:
        load_for_proxy(store.root, verifier=verifier, floor=floor)
    assert caught.value.reason_code == "snapshot_replay"
    with pytest.raises(ConfigRejected) as inside:
        ConfigStore(tmp_path / "store", signer=signer, floor=LocalVersionFloor(tmp_path / "store" / "floor.jsonl"))
    assert inside.value.reason_code == "version_floor_inside_store"
