"""Stdlib HTTP anonymizer for the optional native unit.

GET /health and POST /anonymize. Binds PRESIDIO_BIND (default 127.0.0.1)
and PRESIDIO_PORT (default 5002). A wildcard bind is refused. Azure keeps
the digest-pinned anonymizer image on port 3001; this process is not that one.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

_MAX_BODY = 1_000_000
_REFUSED_BINDS = frozenset({"", "0.0.0.0", "::", "[::]"})


def listen_address() -> tuple[str, int]:
    bind = os.environ.get("PRESIDIO_BIND", "127.0.0.1").strip()
    if bind in _REFUSED_BINDS:
        raise SystemExit("presidio_bind_refused")
    port = int(os.environ.get("PRESIDIO_PORT", "5002"))
    return bind, port


def build_anonymizer() -> Any:
    from presidio_anonymizer import AnonymizerEngine

    return AnonymizerEngine()


def anonymize_payload(engine: Any, payload: dict[str, Any]) -> dict[str, Any]:
    from presidio_anonymizer.services.app_entities_convertor import AppEntitiesConvertor

    if not isinstance(payload.get("text"), str):
        raise TypeError("text")
    operators = AppEntitiesConvertor.operators_config_from_json(payload.get("anonymizers"))
    results = AppEntitiesConvertor.analyzer_results_from_json(payload.get("analyzer_results"))
    rendered = engine.anonymize(
        text=payload["text"],
        analyzer_results=results,
        operators=operators,
    )
    body = json.loads(rendered.to_json())
    if not isinstance(body, dict) or not isinstance(body.get("text"), str):
        raise ValueError("malformed")
    return body


def _handler(anonymize: Callable[[dict[str, Any]], dict[str, Any]]) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802
            if self.path.split("?", 1)[0] != "/health":
                self._send(404, {"error": "not_found"})
                return
            self._send(200, {"status": "ok"})

        def do_POST(self) -> None:  # noqa: N802
            try:
                if self.path.split("?", 1)[0] != "/anonymize":
                    self._send(404, {"error": "not_found"})
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except (TypeError, ValueError):
                    self._send(400, {"error": "malformed"})
                    return
                if length <= 0 or length > _MAX_BODY:
                    self._send(413, {"error": "payload_too_large"})
                    return
                try:
                    payload = json.loads(self.rfile.read(length).decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError, ValueError, OSError):
                    self._send(400, {"error": "malformed"})
                    return
                if not isinstance(payload, dict):
                    self._send(400, {"error": "malformed"})
                    return
                try:
                    body = anonymize(payload)
                except (TypeError, ValueError, KeyError):
                    self._send(400, {"error": "malformed"})
                    return
                self._send(200, body)
            except Exception:
                try:
                    self._send(500, {"error": "internal"})
                except Exception:
                    return

        def handle_error(self) -> None:
            exc = sys.exception()
            name = type(exc).__name__ if exc is not None else "Exception"
            try:
                sys.stderr.write(name + "\n")
            except Exception:
                return

        def log_message(self, _format: str, *_args: Any) -> None:
            return

        def _send(self, status: int, body: Any) -> None:
            raw = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    return Handler


def serve_in_thread(
    anonymize: Callable[[dict[str, Any]], dict[str, Any]],
    bind: str = "127.0.0.1",
    port: int = 0,
) -> ThreadingHTTPServer:
    """Bind an ephemeral anonymizer for tests. The caller shuts the server down."""
    server = ThreadingHTTPServer((bind, port), _handler(anonymize))
    thread = threading.Thread(target=server.serve_forever, name="presidio-anonymizer", daemon=True)
    thread.start()
    return server


def main() -> None:
    engine = build_anonymizer()
    bind, port = listen_address()
    server = ThreadingHTTPServer((bind, port), _handler(lambda payload: anonymize_payload(engine, payload)))
    server.serve_forever()


if __name__ == "__main__":
    main()
