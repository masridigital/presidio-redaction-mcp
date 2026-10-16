from __future__ import annotations

import json

from presidio_admin.audit_view import GENESIS, read_lines, render_lines, row_hmac

PLANTED = "MRN-SYN-1234567"
PLANTED_NAME = "Jane Synthetic-Doe"
PLANTED_EMAIL = "jane@real-example.com"


def _line(key: bytes, previous: str, row: dict) -> str:
    body = dict(row)
    body["prev_hash"] = previous
    body["row_hash"] = row_hmac(key, body)
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def test_renderer_drops_payloads_and_verifies_the_chain(hmac_key: bytes) -> None:
    first = _line(
        hmac_key,
        GENESIS,
        {
            "event": "tool_call",
            "caller": "synthetic-client",
            "tool": "stackjack_health_check",
            "decision": "allow",
            "reason_code": "ok",
            "ts": "2026-10-16T00:00:00+00:00",
            "payload": f"note {PLANTED}",
            "arguments": {"query": PLANTED_EMAIL, "name": PLANTED_NAME},
            "result": {"text": PLANTED_NAME},
        },
    )
    previous = json.loads(first)["row_hash"]
    second = _line(
        hmac_key,
        previous,
        {
            "event": "tool_call",
            "tool": "stackjack_health_check",
            "decision": "deny",
            "reason_code": f"blocked {PLANTED}",
            "ts": "2026-10-16T00:00:01+00:00",
        },
    )
    view = render_lines([first, second], hmac_key)
    rendered = json.dumps(view)
    assert view["chain_valid"] is True
    assert PLANTED not in rendered
    assert PLANTED_NAME not in rendered
    assert PLANTED_EMAIL not in rendered
    assert "payload" not in view["rows"][0]
    assert "arguments" not in view["rows"][0]
    assert "result" not in view["rows"][0]
    assert view["rows"][0]["tool"] == "stackjack_health_check"
    assert view["rows"][1]["reason_code"] == "[redacted]"
    assert set(view["rows"][0]).issubset(
        {
            "event",
            "caller",
            "tool",
            "decision",
            "reason_code",
            "ts",
            "prev_hash",
            "row_hash",
        }
    )


def test_a_tampered_row_fails_verification(hmac_key: bytes) -> None:
    line = _line(
        hmac_key,
        GENESIS,
        {"event": "admin_change", "action": "publish", "decision": "recorded", "ts": "2026-10-16T00:00:00+00:00"},
    )
    tampered = line.replace("publish", "delete", 1)
    view = render_lines([tampered], hmac_key)
    assert view["chain_valid"] is False
    assert "payload" not in json.dumps(view)


def test_portal_audit_page_stays_phi_free(client, tokens, store, audit_key: bytes) -> None:
    path = store.root / "audit.jsonl"
    lines = read_lines(path)
    previous = json.loads(lines[-1])["row_hash"]
    planted = _line(
        audit_key,
        previous,
        {
            "event": "tool_call",
            "tool": "stackjack_health_check",
            "decision": "allow",
            "reason_code": "ok",
            "ts": "2026-10-16T00:00:02+00:00",
            "payload": PLANTED_NAME,
            "arguments": {"note": PLANTED},
        },
    )
    with path.open("a", encoding="utf-8") as handle:
        handle.write(planted + "\n")
    response = client.get("/api/audit", headers=tokens.auth())
    assert response.status_code == 200
    body = response.text
    assert response.json()["chain_valid"] is True
    assert PLANTED not in body
    assert PLANTED_NAME not in body
    page = client.get("/audit", headers=tokens.auth())
    assert page.status_code == 200
    assert PLANTED not in page.text
    assert PLANTED_NAME not in page.text
    assert "HMAC chain valid" in page.text
