from __future__ import annotations

import pytest

from presidio_admin.approval import apply_patch, risk_flags
from presidio_admin.errors import ApprovalError, ConfigRejected
from presidio_admin.schema import default_config

PROPOSER = "11111111-1111-4111-8111-111111111111"
APPROVER = "22222222-2222-4222-8222-222222222222"
CLIENT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1"


def _principal(tokens, oid: str):
    return tokens.verifier.verify(tokens.token(oid))


def test_enabling_a_tool_needs_a_second_admin(changes, tokens) -> None:
    proposer = _principal(tokens, PROPOSER)
    pending = changes.submit(
        proposer,
        {"op": "set_tool_enabled", "upstream": "stackjack", "tool": "stackjack_health_check", "enabled": True},
    )
    assert pending.status == "pending"
    assert pending.risk_flags == ("enable_tool:stackjack_health_check",)
    assert changes.store.read_active().config.enabled_tools() == []
    with pytest.raises(ApprovalError) as caught:
        changes.approve(proposer, pending.proposal_id or "")
    assert caught.value.reason_code == "self_approval_forbidden"
    applied = changes.approve(_principal(tokens, APPROVER), pending.proposal_id or "")
    assert applied.status == "applied"
    assert changes.store.read_active().config.enabled_tools() == ["stackjack_health_check"]
    history = changes.store.history()
    assert history[-1]["approver_oid"] == APPROVER
    assert "enable_tool:stackjack_health_check" in history[-1]["summary"]


def test_disabling_a_tool_publishes_immediately(changes, tokens) -> None:
    proposer = _principal(tokens, PROPOSER)
    approver = _principal(tokens, APPROVER)
    pending = changes.submit(
        proposer,
        {"op": "set_tool_enabled", "upstream": "stackjack", "tool": "stackjack_search_docs", "enabled": True},
    )
    changes.approve(approver, pending.proposal_id or "")
    applied = changes.submit(
        proposer,
        {"op": "set_tool_enabled", "upstream": "stackjack", "tool": "stackjack_search_docs", "enabled": False},
    )
    assert applied.status == "applied"
    assert "stackjack_search_docs" not in changes.store.read_active().config.enabled_tools()


def test_lowering_a_threshold_needs_a_second_admin(store, changes, tokens) -> None:
    raised = default_config().model_copy(update={"score_threshold": 0.6})
    fresh = type(store)(store.root.parent / "lower", signer=store.signer)
    fresh.bootstrap(default_config())
    fresh.publish(
        raised,
        actor_oid=PROPOSER,
        approver_oid=APPROVER,
        summary=["raise the floor"],
        proposal_id="raise-floor",
        action="approve",
    )
    service = type(changes)(fresh)
    proposer = _principal(tokens, PROPOSER)
    pending = service.submit(proposer, {"op": "set_score_threshold", "value": 0.45})
    assert pending.status == "pending"
    assert any(flag.startswith("lower_threshold:score_threshold:") for flag in pending.risk_flags)
    assert fresh.read_active().config.score_threshold == 0.6
    service.approve(_principal(tokens, APPROVER), pending.proposal_id or "")
    assert fresh.read_active().config.score_threshold == 0.45


def test_raising_the_presidio_floor_also_needs_a_second_admin(changes, tokens) -> None:
    pending = changes.submit(_principal(tokens, PROPOSER), {"op": "set_score_threshold", "value": 0.7})
    assert pending.status == "pending"
    assert any(flag.startswith("weaken_detection:score_threshold:") for flag in pending.risk_flags)


def test_lowering_a_pattern_score_needs_a_second_admin(changes, tokens) -> None:
    pending = changes.submit(
        _principal(tokens, PROPOSER),
        {"op": "set_pattern_score", "recognizer": "synthetic_mrn", "pattern": "mrn_canonical", "value": 0.8},
    )
    assert pending.status == "pending"
    assert any(flag.startswith("lower_threshold:mrn_canonical:") for flag in pending.risk_flags)


def test_disabling_the_verifier_needs_a_second_admin(changes, tokens) -> None:
    proposer = _principal(tokens, PROPOSER)
    enabled = changes.submit(proposer, {"op": "set_verifier", "enabled": True})
    assert enabled.status == "applied"
    assert changes.store.read_active().config.claude_verifier_enabled is True
    pending = changes.submit(proposer, {"op": "set_verifier", "enabled": False})
    assert pending.status == "pending"
    assert pending.risk_flags == ("disable_verifier",)
    assert changes.store.read_active().config.claude_verifier_enabled is True
    changes.approve(_principal(tokens, APPROVER), pending.proposal_id or "")
    assert changes.store.read_active().config.claude_verifier_enabled is False
    restored = changes.submit(proposer, {"op": "set_verifier", "enabled": True})
    assert restored.status == "applied"
    assert changes.store.read_active().config.claude_verifier_enabled is True


def test_adding_a_client_needs_a_second_admin_and_maps_the_app_role(changes, tokens) -> None:
    proposer = _principal(tokens, PROPOSER)
    pending = changes.submit(
        proposer,
        {
            "op": "add_client",
            "client_id": CLIENT_ID,
            "display_name": "Synthetic PHI Reader",
            "app_role": "PHI",
        },
    )
    assert pending.status == "pending"
    assert pending.risk_flags == (f"add_client:{CLIENT_ID}",)
    assert changes.store.read_active().config.clients == []
    changes.approve(_principal(tokens, APPROVER), pending.proposal_id or "")
    client = changes.store.read_active().config.clients[0]
    assert client.client_id == CLIENT_ID
    assert client.app_role == "PHI"
    disabled = changes.submit(proposer, {"op": "set_client_enabled", "client_id": CLIENT_ID, "enabled": False})
    assert disabled.status == "applied"
    assert changes.store.read_active().config.clients[0].enabled is False
    again = changes.submit(proposer, {"op": "set_client_enabled", "client_id": CLIENT_ID, "enabled": True})
    assert again.status == "pending"
    assert again.risk_flags == (f"enable_client:{CLIENT_ID}",)


def test_nonphi_to_phi_needs_a_second_admin(changes, tokens) -> None:
    proposer = _principal(tokens, PROPOSER)
    approver = _principal(tokens, APPROVER)
    added = changes.submit(
        proposer,
        {
            "op": "add_client",
            "client_id": CLIENT_ID,
            "display_name": "Synthetic Workload",
            "app_role": "NonPHI",
        },
    )
    changes.approve(approver, added.proposal_id or "")
    pending = changes.submit(
        proposer,
        {"op": "set_client_role", "client_id": CLIENT_ID, "app_role": "PHI"},
    )
    assert pending.status == "pending"
    assert pending.risk_flags == (f"phi_role:{CLIENT_ID}",)
    assert changes.store.read_active().config.clients[0].app_role == "NonPHI"
    changes.approve(approver, pending.proposal_id or "")
    assert changes.store.read_active().config.clients[0].app_role == "PHI"


def test_stale_proposal_is_not_applied(changes, tokens) -> None:
    proposer = _principal(tokens, PROPOSER)
    approver = _principal(tokens, APPROVER)
    pending = changes.submit(
        proposer,
        {"op": "set_tool_enabled", "upstream": "composio", "tool": "UPTIMEROBOT_GET_MONITORS", "enabled": True},
    )
    tightened = changes.submit(
        proposer,
        {"op": "set_upstream_enabled", "upstream": "stackjack", "enabled": False},
    )
    assert tightened.status == "applied"
    with pytest.raises(ApprovalError) as caught:
        changes.approve(approver, pending.proposal_id or "")
    assert caught.value.reason_code == "stale_proposal"
    assert "UPTIMEROBOT_GET_MONITORS" not in changes.store.read_active().config.enabled_tools()


def test_invalid_changes_do_not_publish(changes, tokens) -> None:
    proposer = _principal(tokens, PROPOSER)
    before = changes.store.read_active().version_id
    with pytest.raises(ApprovalError):
        changes.submit(proposer, {"op": "set_score_threshold", "value": 0.2})
    with pytest.raises(ApprovalError):
        changes.submit(
            proposer,
            {"op": "add_client", "client_id": "not-a-guid", "display_name": "Synthetic", "app_role": "PHI"},
        )
    with pytest.raises(ApprovalError):
        changes.submit(proposer, {"op": "add_upstream", "name": "m365"})
    assert changes.store.read_active().version_id == before
    assert changes.store.list_proposals() == []


def test_risk_classifier_names_the_four_required_toggles() -> None:
    before = default_config()
    enabled = apply_patch(
        before,
        {"op": "set_tool_enabled", "upstream": "stackjack", "tool": "stackjack_get_doc_page", "enabled": True},
    )
    assert "enable_tool:stackjack_get_doc_page" in risk_flags(before, enabled)
    lowered = apply_patch(
        before.model_copy(update={"score_threshold": 0.8}),
        {"op": "set_score_threshold", "value": 0.5},
    )
    assert any(flag.startswith("lower_threshold:") for flag in risk_flags(before.model_copy(update={"score_threshold": 0.8}), lowered))
    verifier_on = before.model_copy(update={"claude_verifier_enabled": True})
    verifier_off = apply_patch(verifier_on, {"op": "set_verifier", "enabled": False})
    assert "disable_verifier" in risk_flags(verifier_on, verifier_off)
    added = apply_patch(
        before,
        {
            "op": "add_client",
            "client_id": CLIENT_ID,
            "display_name": "Synthetic NonPHI Reader",
            "app_role": "NonPHI",
        },
    )
    assert f"add_client:{CLIENT_ID}" in risk_flags(before, added)
    data = added.model_dump(mode="json")
    data["clients"][0]["app_role"] = "PHI"
    from presidio_admin.schema import parse_config

    phi = parse_config(data)
    assert f"phi_role:{CLIENT_ID}" in risk_flags(added, phi)


def test_third_upstream_is_rejected_even_as_a_document() -> None:
    payload = default_config().model_dump(mode="json")
    payload["upstreams"]["m365"] = payload["upstreams"]["stackjack"]
    with pytest.raises(ConfigRejected):
        from presidio_admin.schema import parse_config

        parse_config(payload)
