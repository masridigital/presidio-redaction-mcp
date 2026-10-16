"""HTTP analyzer for the custom image.

GET /health and POST /analyze. The engine is the stock Presidio registry plus
``register_us_recognizers``, so US_NPI is on this serving path.
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .us_recognizers import register_us_recognizers

_MAX_BODY = 1_000_000


def build_analyzer(nlp_engine: Any = None) -> Any:
    from presidio_analyzer import AnalyzerEngine

    if nlp_engine is None:
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        model = os.environ.get("PRESIDIO_SPACY_MODEL", "en_core_web_lg")
        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": model}],
            }
        )
        nlp_engine = provider.create_engine()
    engine = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
    register_us_recognizers(engine)
    return engine


def _analyze(engine: Any, payload: dict[str, Any]) -> list[dict[str, Any]]:
    from presidio_analyzer import AnalyzerRequest

    if not isinstance(payload.get("text"), str):
        raise TypeError("text")
    parsed = AnalyzerRequest(payload)
    results = engine.analyze(
        text=parsed.text,
        language=parsed.language or "en",
        entities=parsed.entities,
        score_threshold=0.0 if parsed.score_threshold is None else float(parsed.score_threshold),
        ad_hoc_recognizers=parsed.ad_hoc_recognizers or None,
        context=parsed.context,
        allow_list=parsed.allow_list,
    )
    return [
        {
            "entity_type": result.entity_type,
            "start": int(result.start),
            "end": int(result.end),
            "score": float(result.score),
        }
        for result in results
    ]


def _handler(engine: Any) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:  # noqa: N802
            if self.path.split("?", 1)[0] != "/health":
                self._send(404, {"error": "not_found"})
                return
            self._send(200, {"status": "ok"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path.split("?", 1)[0] != "/analyze":
                self._send(404, {"error": "not_found"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > _MAX_BODY:
                self._send(413, {"error": "payload_too_large"})
                return
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError, ValueError):
                self._send(400, {"error": "malformed"})
                return
            if not isinstance(payload, dict):
                self._send(400, {"error": "malformed"})
                return
            try:
                body = _analyze(engine, payload)
            except (TypeError, ValueError, KeyError):
                self._send(400, {"error": "malformed"})
                return
            self._send(200, body)

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


def serve_in_thread(engine: Any, bind: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    """Bind an ephemeral analyzer for tests. The caller shuts the server down."""
    server = ThreadingHTTPServer((bind, port), _handler(engine))
    thread = threading.Thread(target=server.serve_forever, name="presidio-analyzer", daemon=True)
    thread.start()
    return server


def main() -> None:
    bind = os.environ.get("PRESIDIO_BIND", "0.0.0.0")
    port = int(os.environ.get("PRESIDIO_PORT", "3000"))
    server = ThreadingHTTPServer((bind, port), _handler(build_analyzer()))
    server.serve_forever()


if __name__ == "__main__":
    main()
