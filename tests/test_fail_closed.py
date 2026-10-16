"""Every fail-closed reason, including truncated and oversized Presidio streams."""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

import httpx
import pytest
from starlette.testclient import TestClient

from presidio_redaction_mcp.errors import FailClosed
from presidio_redaction_mcp.presidio_client import PresidioClient
from presidio_redaction_mcp.upstream import MockUpstream
from tests.conftest import SECRETS, build_test_runtime, mcp_call, tool_text
from tests.presidio_double import _apply, _detect

ROOT = Path(__file__).resolve().parents[1]
SECRET = "MRN-SYN-0001234"

# Reason codes the proxy can raise. The source scan below must match this set.
COVERED = {
    "anthropic_key_missing",
    "list_too_long",
    "nesting_too_deep",
    "payload_too_complex",
    "payload_too_large",
    "presidio_fanout_exceeded",
    "pii_in_key",
    "presidio_anonymizer_ineffective",
    "presidio_flagged",
    "presidio_http_error",
    "presidio_malformed",
    "presidio_must_be_https",
    "presidio_payload_too_large",
    "presidio_stream_interrupted",
    "presidio_timeout",
    "presidio_unreachable",
    "unanalyzable_content",
    "unmaskable_scalar",
    "upstream_stream_interrupted",
    "upstream_via_cloudflare",
    "verifier_echo",
    "verifier_http_error",
    "verifier_instruction_override",
    "verifier_malformed",
    "verifier_timeout",
    "verifier_unreachable",
}


class _Chunks(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes], error: Exception | None = None) -> None:
        self._chunks = chunks
        self._error = error

    async def __aiter__(self):
        for chunk in self._chunks:
            yield chunk
        if self._error is not None:
            raise self._error

    async def aclose(self) -> None:
        return None


def _ok(body: dict, path: str) -> httpx.Response:
    text = str(body.get("text", ""))
    if path.endswith("/anonymize"):
        rewritten = _apply(text, body.get("analyzer_results") or [])
        return httpx.Response(200, json={"text": rewritten})
    threshold = float(body.get("score_threshold") or 0)
    spans = [span for span in _detect(text, body.get("ad_hoc_recognizers") or []) if span["score"] >= threshold]
    return httpx.Response(200, json=spans)


def _fault_response(kind: str, text: str) -> httpx.Response | Exception:
    secret = SECRET.encode()
    if kind == "timeout":
        return httpx.TimeoutException("timed out")
    if kind == "connect":
        return httpx.ConnectError("down")
    if kind == "protocol":
        return httpx.RemoteProtocolError("reset")
    if kind == "http_500":
        return httpx.Response(500, content=secret, headers={"content-type": "application/json"})
    if kind == "malformed_json":
        return httpx.Response(200, content=b"{" + secret, headers={"content-type": "application/json"})
    if kind == "plain_type":
        return httpx.Response(200, content=secret, headers={"content-type": "text/plain"})
    if kind == "analyzer_object":
        return httpx.Response(200, json={"error": SECRET})
    if kind == "analyzer_bad_entity":
        return httpx.Response(200, json=[{"entity_type": "drop table", "start": 0, "end": 1, "score": 0.9}])
    if kind == "analyzer_bool_start":
        return httpx.Response(200, json=[{"entity_type": "MRN", "start": True, "end": 1, "score": 0.9}])
    if kind == "analyzer_bad_span":
        return httpx.Response(200, json=[{"entity_type": "MRN", "start": 5, "end": 1, "score": 0.9}])
    if kind == "anonymizer_list":
        return httpx.Response(200, json=[SECRET])
    if kind == "anonymizer_noop":
        return httpx.Response(200, json={"text": text})
    if kind == "stream_cut":
        return httpx.Response(
            200,
            stream=_Chunks([b'{"text": "' + secret], httpx.RemoteProtocolError("truncated")),
            headers={"content-type": "application/json"},
        )
    if kind == "stream_read":
        return httpx.Response(
            200,
            stream=_Chunks([secret], httpx.ReadError("reset")),
            headers={"content-type": "application/json"},
        )
    if kind == "stream_big":
        return httpx.Response(
            200,
            stream=_Chunks([secret + b" " + (b"A" * 1_000_001)]),
            headers={"content-type": "application/json"},
        )
    raise AssertionError(kind)


class FaultTransport(httpx.AsyncBaseTransport):
    def __init__(self, kind: str, *, scope: str, marked_only: bool) -> None:
        self.kind = kind
        self.scope = scope
        self.marked_only = marked_only

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        path = request.url.path
        text = str(body.get("text", ""))
        phase = "anonymize" if path.endswith("/anonymize") else "analyze"
        armed = (not self.marked_only or SECRET in text) and (self.scope == "all" or self.scope == phase)
        if not armed:
            return _ok(body, path)
        fault = _fault_response(self.kind, text)
        if isinstance(fault, Exception):
            raise fault
        return fault


def _vpn(runtime, name: str, arguments: dict):
    with TestClient(runtime.vpn_app, base_url="http://testserver") as client:
        response = mcp_call(client, SECRETS["claude_local_token"], name, arguments)
    asyncio.run(runtime.presidio.aclose())
    return response


MATRIX = [
    ("timeout", "presidio_timeout", "all"),
    ("connect", "presidio_unreachable", "all"),
    ("protocol", "presidio_stream_interrupted", "all"),
    ("http_500", "presidio_http_error", "all"),
    ("malformed_json", "presidio_malformed", "all"),
    ("plain_type", "presidio_malformed", "all"),
    ("analyzer_object", "presidio_malformed", "analyze"),
    ("analyzer_bad_entity", "presidio_malformed", "analyze"),
    ("analyzer_bool_start", "presidio_malformed", "analyze"),
    ("analyzer_bad_span", "presidio_malformed", "analyze"),
    ("anonymizer_list", "presidio_malformed", "anonymize"),
    ("anonymizer_noop", "presidio_anonymizer_ineffective", "anonymize"),
    # RemoteProtocolError is raised as a protocol failure and maps to
    # stream_interrupted. httpx 0.28 eager-reads the body inside post(), so a
    # ReadError during that read is an HTTPError and maps to unreachable.
    # Both still fail closed: zero upstream calls, result discarded.
    ("stream_cut", "presidio_stream_interrupted", "all"),
    ("stream_read", "presidio_unreachable", "all"),
    ("stream_big", "presidio_payload_too_large", "all"),
]


@pytest.mark.parametrize(("kind", "reason", "scope"), MATRIX)
def test_inbound_fault_makes_zero_upstream_calls(tmp_path, monkeypatch, kind, reason, scope):
    runtime = build_test_runtime(
        tmp_path,
        monkeypatch,
        FaultTransport(kind, scope=scope, marked_only=False),
    )
    response = _vpn(runtime, "stackjack_search_docs", {"query": SECRET, "limit": 1})
    text = tool_text(response)
    assert reason in text
    assert runtime.upstreams["stackjack"].calls == []
    assert SECRET.encode() not in response.content
    blob = runtime.audit.path.read_text(encoding="utf-8")
    assert SECRET not in blob


@pytest.mark.parametrize(("kind", "reason", "scope"), MATRIX)
def test_outbound_fault_discards_the_result(tmp_path, monkeypatch, kind, reason, scope):
    runtime = build_test_runtime(
        tmp_path,
        monkeypatch,
        FaultTransport(kind, scope=scope, marked_only=True),
    )
    response = _vpn(runtime, "stackjack_health_check", {"limit": 1})
    text = tool_text(response)
    assert reason in text
    assert len(runtime.upstreams["stackjack"].calls) == 1
    assert SECRET.encode() not in response.content
    assert "Testy McFakerson" not in text
    assert SECRET not in runtime.audit.path.read_text(encoding="utf-8")


def test_upstream_stream_break_discards_the_partial_token(stack):
    upstream = stack["runtime"].upstreams["stackjack"]
    upstream.break_stream = True
    upstream.stream_token = "MRN-SYN-0009999"
    response = mcp_call(stack["vpn"], SECRETS["claude_local_token"], "stackjack_health_check", {"limit": 1})
    assert "upstream_stream_interrupted" in tool_text(response)
    assert b"MRN-SYN-0009999" not in response.content
    assert "MRN-SYN-0009999" not in stack["runtime"].audit.path.read_text(encoding="utf-8")


def test_upstream_cloudflare_host_fails_closed(stack):
    tool = stack["runtime"].settings.allowlist.upstreams["stackjack"].tools[0]
    upstream = MockUpstream(name="stackjack", base_url="https://bad.trycloudflare.com/mcp")
    with pytest.raises(FailClosed) as caught:
        asyncio.run(upstream.call(tool, {"limit": 1}))
    assert caught.value.reason_code == "upstream_via_cloudflare"
    assert upstream.calls == []


def test_presidio_https_is_required_in_production_mode(stack):
    with pytest.raises(FailClosed) as caught:
        PresidioClient(
            analyzer_url="http://presidio-tls/analyze",
            anonymizer_url="http://presidio-tls/anonymize",
            recognizers=stack["runtime"].settings.recognizers,
            timeout_seconds=1,
            score_threshold=0.4,
            egress_check=lambda *_args, **_kwargs: "presidio-tls",
            require_https=True,
        )
    assert caught.value.reason_code == "presidio_must_be_https"


def test_payload_too_large_blocks_before_upstream(stack):
    redactor = stack["runtime"].service.redactor
    payload = "A" * (stack["runtime"].settings.allowlist.max_payload_bytes + 8)
    with pytest.raises(FailClosed) as caught:
        stack["vpn"].portal.call(redactor.redact, payload)
    assert caught.value.reason_code == "payload_too_large"
    assert stack["runtime"].upstreams["stackjack"].calls == []


def test_outbound_overflow_payload_is_discarded(tmp_path, monkeypatch):
    from tests.presidio_double import PresidioDouble

    double = PresidioDouble()
    limit = 262144

    class Huge(MockUpstream):
        async def call(self, tool, arguments):
            result = await super().call(tool, arguments)
            result["summary"] = "Z" * (limit + 32)
            return result

    runtime = build_test_runtime(tmp_path, monkeypatch, double.transport())
    runtime.upstreams["stackjack"] = Huge(name="stackjack", base_url="https://stackjack.invalid/mcp")
    runtime.service.upstreams = runtime.upstreams
    response = _vpn(runtime, "stackjack_health_check", {"limit": 1})
    assert "payload_too_large" in tool_text(response)
    assert b"ZZZZ" not in response.content
    assert SECRET.encode() not in response.content


@pytest.mark.parametrize("key", ["blob", "image", "audio", "file", "attachment", "pdf", "bytes", "resource", "embedded"])
def test_unanalyzable_keys_fail_closed(stack, key):
    redactor = stack["runtime"].service.redactor
    with pytest.raises(FailClosed) as caught:
        stack["vpn"].portal.call(redactor.redact, {key: "not-text"})
    assert caught.value.reason_code == "unanalyzable_content"
    assert "not-text" not in caught.value.reason_code


def test_base64_identifier_blocks_before_upstream(stack):
    import base64

    encoded = base64.b64encode(SECRET.encode()).decode("ascii")
    before = len(stack["runtime"].upstreams["stackjack"].calls)
    response = mcp_call(
        stack["vpn"],
        SECRETS["claude_local_token"],
        "stackjack_search_docs",
        {"query": encoded, "limit": 1},
    )
    assert "unanalyzable_content" in tool_text(response)
    assert len(stack["runtime"].upstreams["stackjack"].calls) == before
    assert SECRET.encode() not in response.content


def test_pii_in_key_fails_closed_without_echoing_the_key(stack):
    redactor = stack["runtime"].service.redactor
    with pytest.raises(FailClosed) as caught:
        stack["vpn"].portal.call(redactor.redact, {"Testy McFakerson": "status"})
    assert caught.value.reason_code == "pii_in_key"
    assert "Testy" not in str(caught.value)


def test_unmaskable_scalar_blocks_before_upstream(tmp_path, monkeypatch):
    class DigitSpan(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content.decode())
            text = str(body.get("text", ""))
            if text.isdigit() and request.url.path.endswith("/analyze"):
                return httpx.Response(
                    200,
                    json=[{"entity_type": "MRN", "start": 0, "end": len(text), "score": 0.99}],
                )
            if text.isdigit() and request.url.path.endswith("/anonymize"):
                return httpx.Response(200, json={"text": "<MRN>"})
            return _ok(body, request.url.path)

    runtime = build_test_runtime(tmp_path, monkeypatch, DigitSpan())
    response = _vpn(runtime, "stackjack_health_check", {"limit": 1})
    assert "unmaskable_scalar" in tool_text(response)
    assert runtime.upstreams["stackjack"].calls == []


def test_matrix_covers_every_failclosed_reason_in_source():
    reasons: set[str] = set()
    for path in (ROOT / "src").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        reasons.update(re.findall(r'FailClosed\("([a-z0-9_]+)"\)', text))
        reasons.update(re.findall(r'super\(\).__init__\("([a-z0-9_]+)"\)', text))
    assert reasons == COVERED
