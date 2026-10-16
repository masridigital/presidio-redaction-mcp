from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import httpx
import pytest
import yaml

from presidio_redaction_mcp.config import load_settings
from presidio_redaction_mcp.errors import ConfigError, FailClosed, PolicyError
from presidio_redaction_mcp.upstream import CANONICAL_RESULT_SECRETS
from scripts.generate_fixtures import HEADER, build
from tests.conftest import SECRETS, mcp_call, tool_text

ROOT = Path(__file__).resolve().parents[1]
CORPUS_PATH = ROOT / "tests" / "fixtures" / "synthetic_corpus.yaml"


def _corpus() -> dict:
    text = CORPUS_PATH.read_text(encoding="utf-8")
    return yaml.safe_load(text)


def _secrets() -> list[str]:
    corpus = _corpus()
    values = [case["value"] for case in corpus["cases"]]
    values.append(corpus["base64_example"])
    values.extend(CANONICAL_RESULT_SECRETS)
    return values


def _vpn(stack, name, arguments, token="claude"):
    token_value = SECRETS["claude_local_token"] if token == "claude" else SECRETS["open_webui_token"]
    return mcp_call(stack["vpn"], token_value, name, arguments, cloudflare=False)


def _grok(stack, name, arguments):
    return mcp_call(
        stack["cloudflare"],
        SECRETS["grok_bot_token"],
        name,
        arguments,
        cloudflare=True,
    )


def test_01_inbound_args_are_masked_before_the_mock_upstream(stack):
    response = _vpn(
        stack,
        "stackjack_search_docs",
        {"query": "status for Testy McFakerson MRN-SYN-0001234", "limit": 5},
    )
    assert response.status_code == 200
    upstream = stack["runtime"].upstreams["stackjack"]
    assert len(upstream.calls) == 1
    forwarded = json.dumps(upstream.calls[0].arguments)
    assert "MRN-SYN-0001234" not in forwarded
    assert "Testy McFakerson" not in forwarded
    assert "<MRN>" in forwarded
    assert "<PERSON>" in forwarded
    assert upstream.calls[0].via == "direct"
    assert upstream.calls[0].base_url == "https://stackjack.invalid/mcp"


def test_02_outbound_results_are_masked_only_for_private_entra_phi(stack):
    from presidio_redaction_mcp.auth import CallerIdentity

    vpn_text = tool_text(_vpn(stack, "stackjack_health_check", {"limit": 1}))
    for secret in CANONICAL_RESULT_SECRETS:
        assert secret not in vpn_text
    assert "<MRN>" in vpn_text
    claude_id = "11111111-1111-4111-8111-111111111111"
    stack["runtime"].service.settings.baa_client_ids = frozenset({claude_id})
    outsider = CallerIdentity(
        name="claude-local",
        phi_capable=True,
        ingress="private",
        authn="entra",
        client_id="44444444-4444-4444-8444-444444444444",
    )
    blocked_text = stack["vpn"].portal.call(
        stack["runtime"].service.call_tool,
        outsider,
        "stackjack_health_check",
        {"limit": 1},
    )
    assert "phi_in_non_baa_tool_result" in blocked_text
    for secret in CANONICAL_RESULT_SECRETS:
        assert secret not in blocked_text
    identity = CallerIdentity(
        name="claude-local",
        phi_capable=True,
        ingress="private",
        authn="entra",
        client_id=claude_id,
    )
    text = stack["vpn"].portal.call(
        stack["runtime"].service.call_tool,
        identity,
        "stackjack_health_check",
        {"limit": 1},
    )
    for secret in CANONICAL_RESULT_SECRETS:
        assert secret not in text
    assert "<MRN>" in text
    assert "<PERSON>" in text
    assert "patient_name" not in text
    assert "not-text" not in text
    assert "example.com/not-allowlisted" not in text


@pytest.mark.parametrize(
    ("mode", "reason"),
    [
        ("fail_all:down", "presidio_unreachable"),
        ("fail_all:timeout", "presidio_timeout"),
        ("fail_all:malformed", "presidio_malformed"),
        ("fail_all:http_500", "presidio_http_error"),
        ("fail_all:truncated", "presidio_stream_interrupted"),
        ("fail_all:wrong_type", "presidio_malformed"),
    ],
)
def test_03_inbound_presidio_failures_fail_closed(stack, mode, reason):
    stack["double"].mode = mode
    response = _vpn(stack, "stackjack_health_check", {"limit": 1})
    text = tool_text(response)
    assert reason in text
    assert stack["runtime"].upstreams["stackjack"].calls == []
    for secret in CANONICAL_RESULT_SECRETS:
        assert secret not in text


@pytest.mark.parametrize(
    ("mode", "reason"),
    [
        ("fail_analyzer_on_marker:down", "presidio_unreachable"),
        ("fail_anonymizer_on_marker:down", "presidio_unreachable"),
        ("timeout_on_marker:timeout", "presidio_timeout"),
        ("malformed_on_marker:malformed", "presidio_malformed"),
        ("http_on_marker:http_500", "presidio_http_error"),
        ("truncated_on_marker:truncated", "presidio_stream_interrupted"),
    ],
)
def test_03_outbound_presidio_failures_discard_the_result(stack, mode, reason):
    stack["double"].mode = mode
    response = _vpn(stack, "stackjack_health_check", {"limit": 1})
    text = tool_text(response)
    assert reason in text
    assert len(stack["runtime"].upstreams["stackjack"].calls) == 1
    for secret in CANONICAL_RESULT_SECRETS:
        assert secret not in text


def test_03_streaming_upstream_discards_partial_output(stack):
    upstream = stack["runtime"].upstreams["stackjack"]
    upstream.break_stream = True
    upstream.stream_token = "MRN-SYN-0009999"
    response = _vpn(stack, "stackjack_health_check", {"limit": 1})
    text = tool_text(response)
    assert "upstream_stream_interrupted" in text
    assert "MRN-SYN-0009999" not in text
    assert "MRN-SYN-0001234" not in response.content.decode()


async def test_03_presidio_truncated_body_fails_closed(stack):
    from presidio_redaction_mcp.presidio_client import PresidioClient

    class BrokenStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'{"text":'
            raise httpx.RemoteProtocolError("truncated")

        async def aclose(self) -> None:
            return None

    class Transport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                stream=BrokenStream(),
                headers={"content-type": "application/json"},
            )

    client = PresidioClient(
        analyzer_url="http://presidio.test/analyze",
        anonymizer_url="http://presidio.test/anonymize",
        recognizers=stack["runtime"].settings.recognizers,
        timeout_seconds=2,
        score_threshold=0.4,
        egress_check=stack["runtime"].settings.egress.check,
        transport=Transport(),
        require_https=False,
    )
    with pytest.raises(FailClosed) as caught:
        await client.anonymize_text("MRN-SYN-0001234")
    assert caught.value.reason_code == "presidio_stream_interrupted"
    await client.aclose()


def test_04_non_allowlisted_and_bulk_tools_are_denied(stack):
    for name in ("halo_export_everything", "UPTIMEROBOT_ADD_MONITOR", "stackjack_list_all_clients"):
        response = _vpn(stack, name, {})
        assert "tool_not_allowlisted" in tool_text(response)
    assert stack["runtime"].upstreams["stackjack"].calls == []
    assert stack["runtime"].upstreams["composio"].calls == []
    reasons = [row["reason_code"] for row in stack["runtime"].audit.rows() if row["event"] == "tool_call"]
    assert reasons.count("tool_not_allowlisted") == 3


def test_05_pagination_cap_is_enforced(stack):
    denied = _vpn(stack, "stackjack_list_advisories", {"limit": 100})
    assert "pagination_cap_exceeded" in tool_text(denied)
    assert stack["runtime"].upstreams["stackjack"].calls == []

    stack["runtime"].upstreams["stackjack"].force_overflow = True
    overflow = _vpn(stack, "stackjack_list_advisories", {"limit": 5})
    text = tool_text(overflow)
    assert "pagination_cap_exceeded" in text
    for secret in CANONICAL_RESULT_SECRETS:
        assert secret not in text
    assert len(stack["runtime"].upstreams["stackjack"].calls) == 1


def test_06_missing_invalid_and_wrong_assistant_tokens_are_401(stack):
    missing = stack["vpn"].post(
        "/mcp",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "stackjack_health_check", "arguments": {}}},
    )
    assert missing.status_code == 401

    invalid = mcp_call(stack["vpn"], "not-a-real-token", "stackjack_health_check", {"limit": 1})
    assert invalid.status_code == 401
    assert invalid.json()["reason_code"] == "invalid_token"

    wrong_door = mcp_call(stack["vpn"], SECRETS["grok_bot_token"], "stackjack_health_check", {"limit": 1})
    assert wrong_door.status_code == 401
    assert wrong_door.json()["reason_code"] == "ingress_not_allowed"

    claude_on_cf = mcp_call(
        stack["cloudflare"],
        SECRETS["claude_local_token"],
        "stackjack_health_check",
        {"limit": 1},
        cloudflare=True,
    )
    assert claude_on_cf.status_code == 401

    grok_without_cf = mcp_call(
        stack["cloudflare"],
        SECRETS["grok_bot_token"],
        "stackjack_health_check",
        {"limit": 1},
        cloudflare=False,
    )
    assert grok_without_cf.status_code == 401
    assert stack["runtime"].upstreams["stackjack"].calls == []
    assert stack["runtime"].upstreams["composio"].calls == []


def test_07_audit_row_has_caller_and_no_raw_pii(stack):
    response = _vpn(
        stack,
        "stackjack_search_docs",
        {"query": "MRN-SYN-0001234", "limit": 2},
    )
    assert response.status_code == 200
    rows = stack["runtime"].audit.rows()
    assert any(row["event"] == "config_change" and row["caller"] == "process" for row in rows)
    calls = [row for row in rows if row["event"] == "tool_call"]
    assert calls
    row = calls[-1]
    assert row["decision"] == "allow"
    assert row["reason_code"] == "ok"
    assert row["caller"] == "claude-local"
    assert row["ingress"] == "vpn"
    assert row["phi_capable"] is True
    assert row["upstream"] == "stackjack"
    assert row["tool"] == "stackjack_search_docs"
    assert row["config_sha256"]
    digest = hashlib.sha256(b"MRN-SYN-0001234").hexdigest()
    assert row["args_hmac"] != digest
    assert len(row["args_hmac"]) == 64
    blob = stack["runtime"].audit.path.read_text(encoding="utf-8")
    for secret in _secrets():
        assert secret not in blob


def test_08_cloudflare_egress_bytes_are_redacted_and_upstream_is_not_tunneled(stack, caplog):
    captured: list[bytes] = []
    corpus = _corpus()
    for case in corpus["cases"]:
        if case.get("form") == "base64":
            query = base64.b64encode(case["value"].encode()).decode("ascii")
        elif case.get("form") == "json_key":
            query = case["value"]
        else:
            query = case["value"]
        grok = _grok(stack, "stackjack_search_docs", {"query": query, "limit": 1})
        captured.append(grok.content)
        vpn = _vpn(stack, "stackjack_search_docs", {"query": query, "limit": 1})
        captured.append(vpn.content)
    clean = _grok(stack, "UPTIMEROBOT_GET_MONITORS", {"limit": 2})
    captured.append(clean.content)
    blob = b"\n".join(captured)
    for secret in _secrets():
        assert secret.encode() not in blob
    text = blob.decode("utf-8", errors="replace")
    assert "<MRN>" in text or "phi_in_cloudflare_tool_args" in text
    for call in stack["runtime"].upstreams["stackjack"].calls + stack["runtime"].upstreams["composio"].calls:
        assert call.via == "direct"
        assert "cloudflare" not in call.base_url
        assert call.base_url.endswith(".invalid/mcp")
        forwarded = json.dumps(call.arguments)
        for secret in _secrets():
            assert secret not in forwarded
    with pytest.raises(PolicyError):
        stack["runtime"].settings.egress.check("https://proxy.cloudflare.com/mcp", purpose="upstream")
    with pytest.raises(PolicyError):
        stack["runtime"].settings.egress.check("https://backend.composio.dev/mcp", purpose="upstream")
    audit_blob = stack["runtime"].audit.path.read_text(encoding="utf-8")
    for secret in _secrets():
        assert secret not in audit_blob
        assert secret not in caplog.text


def test_grok_phi_in_args_never_reaches_upstream(stack):
    before = len(stack["runtime"].upstreams["stackjack"].calls)
    response = _grok(
        stack,
        "stackjack_search_docs",
        {"query": "Testy McFakerson MRN-SYN-0001234", "limit": 1},
    )
    assert "phi_in_cloudflare_tool_args" in tool_text(response)
    assert len(stack["runtime"].upstreams["stackjack"].calls) == before
    assert "MRN-SYN-0001234" not in response.text


def test_open_webui_is_vpn_only_and_grok_clean_call_is_allowed(stack):
    webui = mcp_call(
        stack["vpn"],
        SECRETS["open_webui_token"],
        "stackjack_get_service_status",
        {"limit": 1},
    )
    assert webui.status_code == 200
    assert "phi_in_non_baa_tool_result" in tool_text(webui)
    grok_on_vpn = mcp_call(
        stack["vpn"],
        SECRETS["grok_bot_token"],
        "stackjack_health_check",
        {"limit": 1},
    )
    assert grok_on_vpn.status_code == 401
    allowed = _grok(stack, "stackjack_health_check", {"limit": 1})
    assert allowed.status_code == 200
    rendered = tool_text(allowed)
    assert "operational" in rendered
    assert "phi_in_non_phi_tool_result" not in rendered
    assert "MRN-SYN-0001234" not in rendered
    assert "summary" not in rendered
    denied = _grok(stack, "stackjack_search_docs", {"query": "status", "limit": 1})
    assert "caller_tool_not_allowed" in tool_text(denied)
    health = [call for call in stack["runtime"].upstreams["stackjack"].calls if call.tool == "stackjack_health_check"]
    assert len(health) == 1


def test_09_other_upstreams_wildcards_and_writes_fail_to_load(tmp_path, monkeypatch):
    monkeypatch.setenv("PRM_ENV", "test")
    for name, value in SECRETS.items():
        monkeypatch.setenv(f"PRM_SECRET_{name.upper()}", value)
    raw = yaml.safe_load((ROOT / "config" / "allowlist.yaml").read_text(encoding="utf-8"))

    def dump(mutated: dict) -> Path:
        path = tmp_path / "allowlist.yaml"
        path.write_text(yaml.safe_dump(mutated), encoding="utf-8")
        recognizer = tmp_path / "recognizers.yaml"
        if not recognizer.exists():
            recognizer.write_text((ROOT / "config" / "recognizers.yaml").read_text(encoding="utf-8"), encoding="utf-8")
        return path

    extra = json.loads(json.dumps(raw))
    extra["upstreams"]["halo"] = json.loads(json.dumps(extra["upstreams"]["stackjack"]))
    extra["upstreams"]["halo"]["kind"] = "stackjack"
    with pytest.raises(ConfigError):
        load_settings(dump(extra), env="test")

    wildcard = json.loads(json.dumps(raw))
    wildcard["upstreams"]["stackjack"]["tools"][0]["name"] = "stackjack_*"
    with pytest.raises(ConfigError):
        load_settings(dump(wildcard), env="test")

    write_tool = json.loads(json.dumps(raw))
    send = json.loads(json.dumps(write_tool["upstreams"]["composio"]["tools"][0]))
    send["name"] = "UPTIMEROBOT_SEND_ALERT"
    send["action_id"] = "UPTIMEROBOT_SEND_ALERT"
    write_tool["upstreams"]["composio"]["tools"].append(send)
    with pytest.raises(ConfigError):
        load_settings(dump(write_tool), env="test")

    missing = json.loads(json.dumps(raw))
    del missing["upstreams"]["composio"]
    with pytest.raises(ConfigError):
        load_settings(dump(missing), env="test")


def test_10_fixtures_carry_the_synthetic_header_and_match_the_seed(tmp_path):
    generated = build()
    on_disk = _corpus()
    assert on_disk == generated
    for path in (ROOT / "tests" / "fixtures").iterdir():
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        assert "SYNTHETIC" in text.splitlines()[0]
        assert HEADER.split("—")[0].strip() in text
    assert on_disk["header"] == "SYNTHETIC"
    assert on_disk["seed"] == 4242
    assert on_disk["faker_email"].endswith("@example.com")


def test_recall_floors_on_synthetic_fixtures(stack):
    floors = yaml.safe_load((ROOT / "config" / "recall-floors.yaml").read_text(encoding="utf-8"))
    corpus = _corpus()
    redactor = stack["runtime"].service.redactor
    caught: dict[str, list[bool]] = {entity: [] for entity in floors["entities"]}
    adversarial: dict[str, list[bool]] = {entity: [] for entity in floors["entities"]}

    def _redact(payload):
        return stack["vpn"].portal.call(redactor.redact, payload)

    for case in corpus["cases"]:
        form = case.get("form")
        if form == "base64":
            payload = base64.b64encode(case["value"].encode()).decode("ascii")
        elif form == "json_key":
            payload = {case["value"]: "status"}
        else:
            payload = f"note {case['value']} end"
        leaked = True
        try:
            rewritten, _counts = _redact(payload)
        except FailClosed as exc:
            leaked = case["value"] in exc.reason_code
            rendered = ""
        else:
            rendered = json.dumps(rewritten)
            leaked = case["value"] in rendered
        bucket = adversarial if case["kind"] == "adversarial" else caught
        bucket[case["entity"]].append(not leaked)
    for entity, results in caught.items():
        assert results, entity
        recall = sum(results) / len(results)
        assert recall >= floors["canonical_floor"], entity
    for entity, results in adversarial.items():
        if not results:
            continue
        recall = sum(results) / len(results)
        assert recall >= floors["adversarial_floor"], entity
    negative = "ticket #24058 version v1.2.3 in Q3 2026"
    rewritten, _counts = _redact(negative)
    assert rewritten == negative


def test_production_egress_is_the_two_upstreams_and_local_presidio_only(tmp_path, monkeypatch):
    monkeypatch.setenv("PRM_ENV", "production")
    for name, value in SECRETS.items():
        monkeypatch.delenv(f"PRM_SECRET_{name.upper()}", raising=False)
        secret = tmp_path / name
        secret.write_text(value + "\n", encoding="utf-8")
        monkeypatch.setenv(f"PRM_SECRET_FILE_{name.upper()}", str(secret))
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    ca = tmp_path / "ca.pem"
    for path in (cert, key, ca):
        path.write_text("placeholder-not-a-real-key\n", encoding="utf-8")
    monkeypatch.setenv("PRM_TLS_CERT_FILE", str(cert))
    monkeypatch.setenv("PRM_TLS_KEY_FILE", str(key))
    monkeypatch.setenv("PRM_PRESIDIO_CA_FILE", str(ca))
    monkeypatch.setenv("PRM_ACCESS_ISSUER", "https://team.cloudflareaccess.com")
    monkeypatch.setenv("PRM_ACCESS_AUDIENCE", "00112233445566778899aabbccddeeff")
    jwks = tmp_path / "jwks.json"
    jwks.write_text('{"keys":[{"kty":"RSA","kid":"prod","n":"aa","e":"AQAB"}]}', encoding="utf-8")
    monkeypatch.setenv("PRM_ACCESS_JWKS_FILE", str(jwks))
    settings = load_settings(ROOT / "config" / "allowlist.yaml", env="production")
    assert settings.egress.allowed_hosts() == frozenset(
        {"stackjack.invalid", "composio.invalid", "127.0.0.1"}
    )
    settings.egress.check("https://127.0.0.1:5001/analyze", purpose="presidio")
    with pytest.raises(PolicyError):
        settings.egress.check("https://127.0.0.1/analyze", purpose="upstream")
    with pytest.raises(PolicyError):
        settings.egress.check("https://api.github.com", purpose="upstream")
    assert "testserver" not in settings.allowlist.listeners.cloudflare_allowed_hosts
    assert "testserver" not in settings.allowlist.listeners.vpn_allowed_hosts
    assert settings.allowlist.presidio.analyzer_url.startswith("https://127.0.0.1")


def test_day1_tool_list_is_exact():
    raw = yaml.safe_load((ROOT / "config" / "allowlist.yaml").read_text(encoding="utf-8"))
    stackjack = [tool["name"] for tool in raw["upstreams"]["stackjack"]["tools"]]
    composio = [tool["name"] for tool in raw["upstreams"]["composio"]["tools"]]
    assert stackjack == [
        "stackjack_health_check",
        "stackjack_get_service_status",
        "stackjack_list_advisories",
        "stackjack_get_release_notes",
        "stackjack_search_docs",
        "stackjack_get_doc_page",
    ]
    assert composio == ["UPTIMEROBOT_GET_MONITORS", "UPTIMEROBOT_GET_ACCOUNT_DETAILS"]
    grok = raw["callers"]["grok-bot"]
    assert set(grok["allowed_tools"]) == {
        "stackjack_health_check",
        "stackjack_get_service_status",
        "UPTIMEROBOT_GET_MONITORS",
    }
    for field in ("summary", "date", "datetime", "ip", "ip_address", "text", "body"):
        assert field in grok["denied_result_fields"]
    for tool in raw["upstreams"]["composio"]["tools"]:
        assert tool["toolkit"] == "UPTIMEROBOT"
        assert tool["connected_account_id"] == "ca_day1_uptimerobot_nonphi_ro"
        assert tool["phi_scope"] == "none"
        assert tool["read_only"] is True
