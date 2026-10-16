"""In-process Presidio HTTP double. Applies the ad-hoc recognizers the proxy sends."""

from __future__ import annotations

import json
import re
from typing import Any

import httpx


class PresidioDouble:
    def __init__(self) -> None:
        self.mode = "ok"
        self.calls: list[tuple[str, str]] = []

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        text = str(body.get("text", ""))
        path = request.url.path
        self.calls.append((path, text))
        fault = self._fault(path, text)
        if fault == "timeout":
            raise httpx.TimeoutException("timed out")
        if fault == "down":
            raise httpx.ConnectError("down")
        if fault == "truncated":
            raise httpx.RemoteProtocolError("truncated")
        if fault == "http_500":
            return httpx.Response(500, json={"error": "down"}, headers={"content-type": "application/json"})
        if fault == "malformed":
            return httpx.Response(200, content=b"{", headers={"content-type": "application/json"})
        if fault == "wrong_type":
            return httpx.Response(200, content=b"[]", headers={"content-type": "text/plain"})
        if path.endswith("/anonymize"):
            rewritten = _apply(text, body.get("analyzer_results") or [])
            return httpx.Response(200, json={"text": rewritten})
        threshold = float(body.get("score_threshold") or 0)
        spans = [span for span in _detect(text, body.get("ad_hoc_recognizers") or []) if span["score"] >= threshold]
        return httpx.Response(200, json=spans)

    def _fault(self, path: str, text: str) -> str | None:
        if self.mode == "ok":
            return None
        kind, _, detail = self.mode.partition(":")
        marker = "MRN-SYN-"
        if kind == "fail_all":
            return detail or "down"
        if marker not in text:
            return None
        if kind == "fail_analyzer_on_marker" and path.endswith("/analyze"):
            return detail or "down"
        if kind == "fail_anonymizer_on_marker" and path.endswith("/anonymize"):
            return detail or "down"
        if kind.endswith("_on_marker"):
            return detail or "down"
        return None


def _detect(text: str, recognizers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    spans: list[dict[str, Any]] = []
    lowered = text.lower()
    for recognizer in recognizers:
        entity = str(recognizer.get("supported_entity") or "")
        for pattern in recognizer.get("patterns") or []:
            expression = str(pattern["regex"])
            score = float(pattern.get("score") or 0)
            for match in re.finditer(expression, text):
                spans.append(
                    {
                        "entity_type": entity,
                        "start": match.start(),
                        "end": match.end(),
                        "score": score,
                    }
                )
        for term in recognizer.get("deny_list") or []:
            needle = str(term).lower()
            start = 0
            while True:
                index = lowered.find(needle, start)
                if index < 0:
                    break
                spans.append(
                    {
                        "entity_type": entity,
                        "start": index,
                        "end": index + len(term),
                        "score": 0.95,
                    }
                )
                start = index + len(needle)
    spans.sort(key=lambda item: (item["start"], -(item["end"] - item["start"])))
    kept: list[dict[str, Any]] = []
    cursor = -1
    for span in spans:
        if span["start"] < cursor:
            continue
        kept.append(span)
        cursor = span["end"]
    return kept


def _apply(text: str, spans: list[dict[str, Any]]) -> str:
    ordered = sorted(spans, key=lambda item: item["start"], reverse=True)
    for span in ordered:
        text = text[: span["start"]] + f"<{span['entity_type']}>" + text[span["end"] :]
    return text
