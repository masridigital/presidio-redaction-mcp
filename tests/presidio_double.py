"""In-process Presidio HTTP double. Applies the ad-hoc recognizers the proxy sends."""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

import httpx

# Same shapes Presidio 2.2.362 scores at 0.6: IpRecognizer IPv4 and
# DateRecognizer yyyy-mm-dd. The unit job does not install Presidio, so the
# patterns live here and the native test checks them against the real engine.
_IPV4 = re.compile(
    r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    r"\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    r"\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    r"\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
_ISO_DATE = re.compile(
    r"\b(\d{4}-(?:[1-9]|0[1-9]|1[0-2])-(?:[1-9]|0[1-9]|[1-2][0-9]|3[0-1]))\b"
)


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
            # Same rule as Presidio 2.2.362 Replace: a provided new_value is
            # literal; an omitted one becomes "<ENTITY>".
            default = ((body.get("anonymizers") or {}).get("DEFAULT") or {})
            new_value = default.get("new_value")
            rewritten = _apply(text, body.get("analyzer_results") or [], new_value)
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


def _builtin_spans(text: str) -> list[dict[str, Any]]:
    """IP_ADDRESS and DATE_TIME hits Presidio's built-ins return at score 0.6."""
    spans: list[dict[str, Any]] = []
    for match in _IPV4.finditer(text):
        try:
            ipaddress.ip_address(match.group(0))
        except ValueError:
            continue
        spans.append(
            {
                "entity_type": "IP_ADDRESS",
                "start": match.start(),
                "end": match.end(),
                "score": 0.6,
            }
        )
    for match in _ISO_DATE.finditer(text):
        spans.append(
            {
                "entity_type": "DATE_TIME",
                "start": match.start(1),
                "end": match.end(1),
                "score": 0.6,
            }
        )
    return spans


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
    spans.extend(_builtin_spans(text))
    spans.sort(key=lambda item: (item["start"], -(item["end"] - item["start"])))
    kept: list[dict[str, Any]] = []
    cursor = -1
    for span in spans:
        if span["start"] < cursor:
            continue
        kept.append(span)
        cursor = span["end"]
    return kept


def _apply(text: str, spans: list[dict[str, Any]], new_value: str | None = None) -> str:
    ordered = sorted(spans, key=lambda item: item["start"], reverse=True)
    for span in ordered:
        token = new_value if new_value else f"<{span['entity_type']}>"
        text = text[: span["start"]] + token + text[span["end"] :]
    return text
