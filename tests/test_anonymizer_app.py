"""The optional native anonymizer binds 5002 and does not echo errors."""

from __future__ import annotations

import importlib.util
import json
from http.client import HTTPConnection
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load():
    path = ROOT / "deploy" / "presidio-anonymizer" / "app.py"
    spec = importlib.util.spec_from_file_location("presidio_anonymizer_app", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_anonymizer_refuses_a_wildcard_bind(monkeypatch):
    app = _load()
    for value in ("", "   ", "0.0.0.0", "::", "[::]"):
        monkeypatch.setenv("PRESIDIO_BIND", value)
        with pytest.raises(SystemExit):
            app.listen_address()


def test_anonymizer_defaults_to_loopback_5002(monkeypatch):
    monkeypatch.delenv("PRESIDIO_BIND", raising=False)
    monkeypatch.delenv("PRESIDIO_PORT", raising=False)
    assert _load().listen_address() == ("127.0.0.1", 5002)


def test_anonymizer_http_replaces_text_and_hides_failures(capsys):
    secret = "MRN-SYN-0001234"

    def anonymize(payload):
        if payload.get("text") == "boom":
            raise RuntimeError(secret)
        return {"text": str(payload.get("text", "")).replace(secret, "<MRN>")}

    server = _load().serve_in_thread(anonymize)
    connection = None
    try:
        host, port = server.server_address
        connection = HTTPConnection(host, port, timeout=5)

        def exchange(method: str, path: str, body: bytes | None = None) -> tuple[int, bytes]:
            headers = {"Connection": "close"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            status = response.status
            connection.close()
            return status, raw

        status, raw = exchange("GET", "/health")
        assert status == 200
        assert json.loads(raw) == {"status": "ok"}

        body = json.dumps(
            {
                "text": f"record {secret}",
                "analyzer_results": [],
                "anonymizers": {"DEFAULT": {"type": "replace"}},
            }
        ).encode()
        status, raw = exchange("POST", "/anonymize", body)
        assert status == 200
        assert json.loads(raw)["text"] == "record <MRN>"

        status, raw = exchange("POST", "/anonymize", b"not-json")
        assert status == 400

        status, raw = exchange("POST", "/anonymize", json.dumps({"text": "boom"}).encode())
        assert status == 500
        assert json.loads(raw) == {"error": "internal"}
        assert secret.encode() not in raw
    finally:
        if connection is not None:
            connection.close()
        server.shutdown()
        server.server_close()
    captured = capsys.readouterr()
    assert secret not in captured.err
    assert secret not in captured.out
