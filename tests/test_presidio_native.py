"""Real Presidio 2.2.362, in process, with the pinned en_core_web_lg model.

The analyzer and anonymizer wheels do not ship the Flask entrypoint, so these
tests drive AnalyzerRequest and AppEntitiesConvertor — the same parsers the
2.2.362 HTTP app uses — and the proxy's HTTP client against those engines.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import pytest
import yaml
from starlette.testclient import TestClient

from tests.conftest import SECRETS, build_test_runtime, grok_call, mcp_call, tool_text

ROOT = Path(__file__).resolve().parents[1]
SECRET = "MRN-SYN-0001234"


def _require_native():
    if os.environ.get("PRM_REQUIRE_NATIVE") == "1":
        import presidio_analyzer  # noqa: F401
        import presidio_anonymizer  # noqa: F401
        return
    pytest.importorskip("presidio_analyzer")
    pytest.importorskip("presidio_anonymizer")


@pytest.fixture(scope="session")
def engines():
    _require_native()
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine

    return AnalyzerEngine(), AnonymizerEngine()


class NativeTransport(httpx.AsyncBaseTransport):
    """In-process stand-in for the socket, not for the recognizers."""

    def __init__(self, engine, anonymizer) -> None:
        self.engine = engine
        self.anonymizer = anonymizer
        self.bodies: list[tuple[str, dict]] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        from presidio_analyzer import AnalyzerRequest
        from presidio_anonymizer.services.app_entities_convertor import AppEntitiesConvertor

        body = json.loads(request.content.decode())
        path = request.url.path
        # OperatorConfig.from_json pops "type" from the live dict. Keep the wire body.
        self.bodies.append((path, json.loads(json.dumps(body))))
        if path.endswith("/analyze"):
            parsed = AnalyzerRequest(body)
            hits = self.engine.analyze(
                text=parsed.text,
                language=parsed.language,
                entities=parsed.entities,
                score_threshold=parsed.score_threshold,
                ad_hoc_recognizers=parsed.ad_hoc_recognizers,
                context=parsed.context,
                allow_list=parsed.allow_list,
            )
            payload = json.loads(json.dumps([hit.to_dict() for hit in hits]))
            return httpx.Response(200, json=payload)
        if path.endswith("/anonymize"):
            operators = AppEntitiesConvertor.operators_config_from_json(body.get("anonymizers"))
            results = AppEntitiesConvertor.analyzer_results_from_json(body.get("analyzer_results"))
            rendered = self.anonymizer.anonymize(
                text=body.get("text", ""),
                analyzer_results=results,
                operators=operators,
            )
            return httpx.Response(200, json=json.loads(rendered.to_json()))
        return httpx.Response(404, json={"error": "missing"})


def _fixture(name: str) -> dict:
    return yaml.safe_load((ROOT / "tests" / "fixtures" / name).read_text(encoding="utf-8"))


def _span_hit(hits, text: str, entity: str, value: str) -> bool:
    return any(hit.entity_type == entity and text[hit.start : hit.end] == value for hit in hits)


@pytest.mark.native
def test_pinned_presidio_and_spacy_model_are_importable():
    _require_native()
    import importlib.metadata as metadata

    assert metadata.version("presidio-analyzer") == "2.2.362"
    assert metadata.version("presidio-anonymizer") == "2.2.362"
    assert metadata.version("en-core-web-lg") == "3.8.0"
    assert metadata.version("spacy") == "3.8.16"


@pytest.mark.native
def test_deny_list_response_shape_and_anonymizer_template(engines):
    from presidio_analyzer import AnalyzerRequest
    from presidio_anonymizer.services.app_entities_convertor import AppEntitiesConvertor

    engine, anonymizer = engines
    recognizers = yaml.safe_load((ROOT / "config" / "recognizers.yaml").read_text(encoding="utf-8"))
    assert recognizers["deny_list"][0]["terms"]
    text = "seen Testy McFakerson MRN: 0001234"
    request = {
        "text": text,
        "language": "en",
        "score_threshold": 0.4,
        "ad_hoc_recognizers": [
            {
                "name": "deny_person",
                "supported_language": "en",
                "supported_entity": "PERSON",
                "deny_list": ["Testy McFakerson"],
            },
            {
                "name": "synthetic_mrn",
                "supported_language": "en",
                "supported_entity": "MRN",
                "patterns": [
                    {
                        "name": "mrn_labeled",
                        "regex": r"(?i)\b(?:medical\s+record\s+number|m\.r\.n\.|mrn|mr\s*#)[\s:#-]*\d{6,10}\b",
                        "score": 0.9,
                    }
                ],
            },
        ],
    }
    parsed = AnalyzerRequest(request)
    assert parsed.ad_hoc_recognizers, "deny_list ad hoc recognizer was rejected"
    hits = engine.analyze(
        text=parsed.text,
        language="en",
        score_threshold=0.4,
        ad_hoc_recognizers=parsed.ad_hoc_recognizers,
    )
    payload = [hit.to_dict() for hit in hits]
    for item in payload:
        assert isinstance(item["entity_type"], str)
        assert isinstance(item["start"], int) and not isinstance(item["start"], bool)
        assert isinstance(item["end"], int)
        assert isinstance(item["score"], float)
        assert item["start"] < item["end"] <= len(text)
    assert _span_hit(hits, text, "PERSON", "Testy McFakerson")
    assert _span_hit(hits, text, "MRN", "MRN: 0001234")
    operators = AppEntitiesConvertor.operators_config_from_json({"DEFAULT": {"type": "replace"}})
    results = AppEntitiesConvertor.analyzer_results_from_json(payload)
    rendered = json.loads(
        anonymizer.anonymize(text=text, analyzer_results=results, operators=operators).to_json()
    )
    assert "Testy McFakerson" not in rendered["text"]
    assert "0001234" not in rendered["text"]
    assert "<PERSON>" in rendered["text"]
    assert "<MRN>" in rendered["text"]
    assert "<{entity_type}>" not in rendered["text"]
    literal = AppEntitiesConvertor.operators_config_from_json(
        {"DEFAULT": {"type": "replace", "new_value": "<{entity_type}>"}}
    )
    literal_text = json.loads(
        anonymizer.anonymize(text=text, analyzer_results=results, operators=literal).to_json()
    )["text"]
    assert "<{entity_type}>" in literal_text


@pytest.mark.native
def test_builtin_recall_per_entity(engines):
    engine, _anonymizer = engines
    fixture = _fixture("builtin_recall.yaml")
    assert fixture["presidio"] == "2.2.362"
    assert fixture["spacy_model"] == "en_core_web_lg==3.8.0"
    by_entity: dict[str, list[bool]] = {}
    for case in fixture["cases"]:
        hits = engine.analyze(text=case["text"], language="en", score_threshold=0.4)
        caught = _span_hit(hits, case["text"], case["entity"], case["value"])
        by_entity.setdefault(case["entity"], []).append(caught)
    for entity, results in by_entity.items():
        recall = sum(results) / len(results)
        assert recall == 1.0, (entity, results)


@pytest.mark.native
def test_builtin_gaps_are_caught_by_ad_hoc_recognizers(engines):
    from presidio_analyzer import AnalyzerRequest
    from presidio_anonymizer.services.app_entities_convertor import AppEntitiesConvertor
    from presidio_redaction_mcp.recognizers import load_recognizers

    engine, anonymizer = engines
    recognizers = load_recognizers(ROOT / "config" / "recognizers.yaml")
    fixture = _fixture("builtin_recall.yaml")
    operators = AppEntitiesConvertor.operators_config_from_json({"DEFAULT": {"type": "replace"}})
    for case in fixture["gaps"]:
        bare = engine.analyze(text=case["text"], language="en", score_threshold=0.4)
        assert not _span_hit(bare, case["text"], case["entity"], case["value"]), case
        parsed = AnalyzerRequest(
            {
                "text": case["text"],
                "language": "en",
                "score_threshold": 0.4,
                "ad_hoc_recognizers": list(recognizers.ad_hoc),
            }
        )
        hits = engine.analyze(
            text=case["text"],
            language="en",
            score_threshold=0.4,
            ad_hoc_recognizers=parsed.ad_hoc_recognizers,
        )
        results = AppEntitiesConvertor.analyzer_results_from_json([hit.to_dict() for hit in hits])
        rendered = json.loads(
            anonymizer.anonymize(text=case["text"], analyzer_results=results, operators=operators).to_json()
        )["text"]
        assert case["value"] not in rendered, case


def _checksum_npi() -> str:
    """One Luhn specimen. Not written into fixtures."""
    body = "100000002"
    for digit in "0123456789":
        candidate = body + digit
        prefixed = "80840" + candidate
        total = 0
        for index, char in enumerate(reversed(prefixed)):
            value = int(char)
            if index % 2 == 1:
                value *= 2
                if value > 9:
                    value -= 9
            total += value
        if total % 10 == 0:
            return candidate
    raise AssertionError("no checksum specimen")


def _serve_module():
    import sys

    deploy = str(ROOT / "deploy")
    if deploy not in sys.path:
        sys.path.append(deploy)
    import presidio.serve as serve

    return serve


@pytest.mark.native
def test_default_engine_omits_us_npi_and_serve_registers_it(engines):
    from presidio_analyzer.predefined_recognizers import UsNpiRecognizer

    engine, _anonymizer = engines
    assert "US_NPI" not in engine.get_supported_entities("en")
    assert "US_MBI" not in engine.get_supported_entities("en")
    candidate = _checksum_npi()
    text = f"provider {candidate}"
    hits = UsNpiRecognizer().analyze(text=text, entities=["US_NPI"])
    assert any(text[hit.start : hit.end] == candidate for hit in hits)
    default_hits = engine.analyze(text=text, language="en", score_threshold=0.4)
    assert not any(hit.entity_type == "US_NPI" for hit in default_hits)

    served = _serve_module().build_analyzer(nlp_engine=engine.nlp_engine)
    supported = set(served.get_supported_entities("en"))
    assert {"US_NPI", "US_MBI", "US_SSN", "US_BANK_NUMBER", "US_ITIN", "US_PASSPORT", "US_DRIVER_LICENSE"} <= supported
    served_hits = served.analyze(text=text, language="en", score_threshold=0.4)
    assert any(hit.entity_type == "US_NPI" and text[hit.start : hit.end] == candidate for hit in served_hits)
    assert sum(1 for item in served.registry.recognizers if item.__class__.__name__ == "UsNpiRecognizer") == 1


@pytest.mark.native
def test_analyze_http_returns_us_npi(engines):
    engine, _anonymizer = engines
    candidate = _checksum_npi()
    text = f"provider {candidate}"
    server = _serve_module().serve_in_thread(_serve_module().build_analyzer(nlp_engine=engine.nlp_engine))
    try:
        host, port = server.server_address
        base = f"http://{host}:{port}"
        health = httpx.get(f"{base}/health", timeout=10)
        assert health.status_code == 200
        assert health.json()["status"] == "ok"
        response = httpx.post(
            f"{base}/analyze",
            json={"text": text, "language": "en", "score_threshold": 0.4},
            timeout=60,
        )
        assert response.status_code == 200
        body = response.json()
        assert any(
            item["entity_type"] == "US_NPI" and text[item["start"] : item["end"]] == candidate for item in body
        )
        locked = httpx.post(
            f"{base}/analyze",
            json={
                "text": text,
                "language": "en",
                "entities": ["PERSON"],
                "score_threshold": 0.99,
                "ad_hoc_recognizers": [
                    {
                        "name": "evil",
                        "supported_language": "en",
                        "supported_entity": "MRN",
                        "patterns": [{"name": "all", "regex": "provider", "score": 0.99}],
                    }
                ],
            },
            timeout=60,
        )
        assert locked.status_code == 200
        locked_body = locked.json()
        assert any(item["entity_type"] == "US_NPI" for item in locked_body)
        assert not any(item["entity_type"] == "MRN" for item in locked_body)
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.native
def test_analyze_http_hides_internal_errors(engines, monkeypatch):
    import io
    from contextlib import redirect_stderr

    serve = _serve_module()
    engine, _anonymizer = engines

    def boom(_engine, _payload):
        raise RuntimeError("MRN-SYN-0001234")

    monkeypatch.setattr(serve, "_analyze", boom)
    server = serve.serve_in_thread(serve.build_analyzer(nlp_engine=engine.nlp_engine))
    try:
        host, port = server.server_address
        response = httpx.post(
            f"http://{host}:{port}/analyze",
            json={"text": "provider", "language": "en"},
            timeout=30,
        )
        assert response.status_code == 500
        assert response.json() == {"error": "internal"}
        assert "MRN-SYN-0001234" not in response.text
    finally:
        server.shutdown()
        server.server_close()

    handler_cls = serve._handler(object())
    handler = handler_cls.__new__(handler_cls)
    buffer = io.StringIO()
    with redirect_stderr(buffer):
        try:
            raise RuntimeError("MRN-SYN-0001234")
        except RuntimeError:
            handler.handle_error()
    assert buffer.getvalue().strip() == "RuntimeError"


@pytest.mark.native
def test_double_agrees_with_presidio_on_ip_and_dob(engines):
    import json as json_module

    from tests.presidio_double import PresidioDouble

    engine, _anonymizer = engines
    double = PresidioDouble()
    samples = [
        ("from 192.0.2.10 today", "IP_ADDRESS", "192.0.2.10"),
        ("dob 1900-01-01", "DATE_TIME", "1900-01-01"),
        ("dob 1901-02-02", "DATE_TIME", "1901-02-02"),
    ]
    for text, entity, value in samples:
        request = httpx.Request(
            "POST",
            "http://presidio.test/analyze",
            json={"text": text, "language": "en", "score_threshold": 0.4, "ad_hoc_recognizers": []},
        )
        doubled = json_module.loads(double.handle(request).read().decode())
        assert any(item["entity_type"] == entity and text[item["start"] : item["end"]] == value for item in doubled)
        live = engine.analyze(text=text, language="en", score_threshold=0.4)
        assert _span_hit(live, text, entity, value), (entity, value)


@pytest.mark.native
def test_corpus_recall_through_real_presidio_per_entity(engines):
    from presidio_analyzer import AnalyzerRequest
    from presidio_anonymizer.services.app_entities_convertor import AppEntitiesConvertor
    from presidio_redaction_mcp.recognizers import load_recognizers

    engine, anonymizer = engines
    recognizers = load_recognizers(ROOT / "config" / "recognizers.yaml")
    floors = yaml.safe_load((ROOT / "config" / "recall-floors.yaml").read_text(encoding="utf-8"))
    corpus = _fixture("synthetic_corpus.yaml")
    operators = AppEntitiesConvertor.operators_config_from_json({"DEFAULT": {"type": "replace"}})
    caught: dict[str, list[bool]] = {entity: [] for entity in floors["entities"]}
    for case in corpus["cases"]:
        if case.get("form") in {"base64", "json_key"}:
            continue
        text = f"note {case['value']} end"
        parsed = AnalyzerRequest(
            {
                "text": text,
                "language": "en",
                "score_threshold": 0.4,
                "ad_hoc_recognizers": list(recognizers.ad_hoc),
            }
        )
        hits = engine.analyze(
            text=text,
            language="en",
            score_threshold=0.4,
            ad_hoc_recognizers=parsed.ad_hoc_recognizers,
        )
        results = AppEntitiesConvertor.analyzer_results_from_json([hit.to_dict() for hit in hits])
        rendered = json.loads(
            anonymizer.anonymize(text=text, analyzer_results=results, operators=operators).to_json()
        )["text"]
        caught[case["entity"]].append(case["value"] not in rendered)
    for entity, results in caught.items():
        assert results, entity
        assert sum(results) / len(results) >= floors["canonical_floor"], entity


@pytest.mark.native
def test_proxy_round_trip_uses_the_real_engines(engines, tmp_path, monkeypatch):
    engine, anonymizer = engines
    transport = NativeTransport(engine, anonymizer)
    runtime = build_test_runtime(tmp_path, monkeypatch, transport)
    try:
        with TestClient(runtime.vpn_app, base_url="http://testserver") as vpn:
            masked = mcp_call(
                vpn,
                SECRETS["claude_local_token"],
                "stackjack_search_docs",
                {"query": "status for Testy McFakerson MRN: 0001234", "limit": 1},
            )
            assert masked.status_code == 200
            forwarded = json.dumps(runtime.upstreams["stackjack"].calls[-1].arguments)
            assert "Testy McFakerson" not in forwarded
            assert "0001234" not in forwarded
            assert "<PERSON>" in forwarded
            assert "<MRN>" in forwarded
            before = len(runtime.upstreams["stackjack"].calls)
            blocked = grok_call(
                {"vpn": vpn, "runtime": runtime},
                "stackjack_search_docs",
                {"query": SECRET, "limit": 1},
            )
            assert "phi_in_cloudflare_tool_args" in tool_text(blocked)
            assert len(runtime.upstreams["stackjack"].calls) == before
            outbound = mcp_call(vpn, SECRETS["open_webui_token"], "stackjack_health_check", {"limit": 1})
            text = tool_text(outbound)
            assert SECRET not in text
            assert "Testy McFakerson" not in text
            assert "phi_in_non_baa_tool_result" in text
    finally:
        import asyncio

        asyncio.run(runtime.presidio.aclose())
    anonymize_bodies = [body for path, body in transport.bodies if path.endswith("/anonymize")]
    assert anonymize_bodies
    for body in anonymize_bodies:
        default = body["anonymizers"]["DEFAULT"]
        assert default["type"] == "replace"
        assert "new_value" not in default
        for result in body["analyzer_results"]:
            assert {"entity_type", "start", "end", "score"} <= set(result)
