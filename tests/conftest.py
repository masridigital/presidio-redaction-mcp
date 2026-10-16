from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from presidio_redaction_mcp.audit import AuditLog
from presidio_redaction_mcp.config import load_settings, with_presidio_urls
from presidio_redaction_mcp.factory import Runtime, build_runtime
from presidio_redaction_mcp.logging_setup import configure_logging
from tests.presidio_double import PresidioDouble

ROOT = Path(__file__).resolve().parents[1]


def _token(label: str) -> str:
    return hashlib.sha256(f"presidio-redaction-mcp-test-secret-{label}".encode()).hexdigest()


SECRETS = {
    "audit_hmac_key": _token("audit-hmac"),
    "grok_bot_token": _token("grok-bot"),
    "claude_local_token": _token("claude-local"),
    "open_webui_token": _token("open-webui"),
}


@pytest.fixture
def stack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("PRM_ENV", "test")
    for name, value in SECRETS.items():
        monkeypatch.setenv(f"PRM_SECRET_{name.upper()}", value)
    settings = with_presidio_urls(
        load_settings(ROOT / "config" / "allowlist.yaml", env="test"),
        "http://presidio.test/analyze",
        "http://presidio.test/anonymize",
    )
    configure_logging(settings.recognizers, "DEBUG", settings.secret_values)
    double = PresidioDouble()
    audit = AuditLog(
        tmp_path / "audit.jsonl",
        tmp_path / "config-sha",
        settings.audit_hmac_key,
        forward=None,
    )
    runtime = build_runtime(settings, audit, transport=double.transport())
    with TestClient(runtime.vpn_app, base_url="http://testserver") as vpn:
        yield {
            "vpn": vpn,
            "runtime": runtime,
            "double": double,
        }
    # The TestClient portal owns the app lifespan. Drop the HTTP client after it exits.
    import asyncio

    asyncio.run(runtime.presidio.aclose())
    if runtime.verifier is not None:
        asyncio.run(runtime.verifier.aclose())


def mcp_headers(token: str, *, cloudflare: bool = False) -> dict[str, str]:
    del cloudflare
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "mcp-protocol-version": "2025-03-26",
    }


class _ServiceResponse:
    def __init__(self, text: str) -> None:
        self.text = text
        self.content = text.encode()
        self.status_code = 200

    def json(self) -> dict:
        import json

        return json.loads(self.text)


def grok_call(stack, name: str, arguments: dict) -> _ServiceResponse:
    """Call the service as grok-bot. There is no Cloudflare HTTP listener."""
    from presidio_redaction_mcp.auth import CallerIdentity

    text = stack["vpn"].portal.call(
        stack["runtime"].service.call_tool,
        CallerIdentity(name="grok-bot", phi_capable=False, ingress="cloudflare"),
        name,
        arguments,
    )
    return _ServiceResponse(text)


def mcp_call(client: TestClient, token: str, name: str, arguments: dict, *, cloudflare: bool = False):
    response = client.post(
        "/mcp/",
        headers=mcp_headers(token, cloudflare=cloudflare),
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
    )
    return response


def tool_text(response) -> str:
    body = response.json()
    if "result" not in body:
        return response.text
    content = body["result"].get("content") or []
    return "".join(block.get("text", "") for block in content)


def runtime_of(stack_map: dict) -> Runtime:
    return stack_map["runtime"]


def apply_test_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PRM_ENV", "test")
    for name, value in SECRETS.items():
        monkeypatch.setenv(f"PRM_SECRET_{name.upper()}", value)


def build_test_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    transport=None,
    upstreams=None,
    rate_limiter=None,
    entra=None,
):
    """Runtime pointed at the in-test Presidio transport. Caller closes the HTTP client."""
    apply_test_secrets(monkeypatch)
    settings = with_presidio_urls(
        load_settings(ROOT / "config" / "allowlist.yaml", env="test"),
        "http://presidio.test/analyze",
        "http://presidio.test/anonymize",
    )
    configure_logging(settings.recognizers, "DEBUG", settings.secret_values)
    audit = AuditLog(tmp_path / "audit.jsonl", tmp_path / "config-sha", settings.audit_hmac_key)
    return build_runtime(
        settings,
        audit,
        transport=transport,
        upstreams=upstreams,
        rate_limiter=rate_limiter,
        entra=entra,
    )
