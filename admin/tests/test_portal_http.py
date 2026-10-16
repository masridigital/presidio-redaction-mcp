from __future__ import annotations

import re

PROPOSER = "11111111-1111-4111-8111-111111111111"


def _csrf(html: str) -> str:
    match = re.search(r"name='csrf' value='([^']+)'", html)
    assert match is not None
    return match.group(1)


def test_pages_and_form_approval_flow(client, tokens) -> None:
    health = client.get("/healthz")
    assert health.status_code == 200
    assert health.json()["config_valid"] is True
    assert health.json()["version_id"] == 1
    assert len(health.json()["sha256"]) == 64
    assert "s" * 16 not in health.text

    signed = client.post("/auth/session", headers=tokens.auth())
    assert signed.status_code == 200
    assert signed.json()["oid"] == PROPOSER

    upstreams = client.get("/upstreams")
    assert upstreams.status_code == 200
    assert "stackjack_health_check" in upstreams.text
    assert "Enable" in upstreams.text
    csrf = _csrf(upstreams.text)

    rejected = client.post(
        "/actions",
        data={"op": "set_tool_enabled", "upstream": "stackjack", "tool": "stackjack_health_check", "enabled": "true"},
    )
    assert rejected.status_code == 403

    pending = client.post(
        "/actions",
        data={
            "csrf": csrf,
            "op": "set_tool_enabled",
            "upstream": "stackjack",
            "tool": "stackjack_health_check",
            "enabled": "true",
        },
        follow_redirects=True,
    )
    assert pending.status_code == 200
    assert "second Admin" in pending.text
    proposals = client.get("/proposals")
    assert proposals.status_code == 200
    assert "stackjack_health_check" in proposals.text
    assert "Base hash" in proposals.text

    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert "prm_admin_up 1" in metrics.text
    assert "prm_admin_verifier_enabled 0" in metrics.text
    assert "prm_admin_proposals_pending 1" in metrics.text


def test_clients_page_offers_grant_phi(client, tokens, changes) -> None:
    proposer = tokens.verifier.verify(tokens.token(PROPOSER))
    approver = tokens.verifier.verify(tokens.token("22222222-2222-4222-8222-222222222222"))
    client_id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1"
    added = changes.submit(
        proposer,
        {
            "op": "add_client",
            "client_id": client_id,
            "display_name": "Synthetic Workload",
            "app_role": "NonPHI",
        },
    )
    changes.approve(approver, added.proposal_id or "")
    client.post("/auth/session", headers=tokens.auth())
    page = client.get("/clients")
    assert page.status_code == 200
    assert "Grant PHI" in page.text
    assert "NonPHI" in page.text
    csrf = _csrf(page.text)
    posted = client.post(
        "/actions",
        data={"csrf": csrf, "op": "set_client_role", "client_id": client_id, "app_role": "PHI"},
        follow_redirects=True,
    )
    assert posted.status_code == 200
    assert "second Admin" in posted.text
    assert changes.store.read_active().config.clients[0].app_role == "NonPHI"
