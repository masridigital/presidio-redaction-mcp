"""HTTP client for Presidio. Any error, timeout, or unexpected body fails closed."""

from __future__ import annotations

import json
from typing import Any

import httpx

from presidio_redaction_mcp.errors import FailClosed
from presidio_redaction_mcp.recognizers import RecognizerSet

_ENTITY = __import__("re").compile(r"^[A-Z][A-Z0-9_]{0,63}$")


class PresidioClient:
    def __init__(
        self,
        *,
        analyzer_url: str,
        anonymizer_url: str,
        recognizers: RecognizerSet,
        timeout_seconds: float,
        score_threshold: float,
        egress_check: Any,
        transport: httpx.AsyncBaseTransport | None = None,
        ca_file: str | None = None,
        require_https: bool = False,
    ) -> None:
        self.analyzer_url = analyzer_url
        self.anonymizer_url = anonymizer_url
        self.recognizers = recognizers
        self.score_threshold = score_threshold
        self._egress_check = egress_check
        self._require_https = require_https
        if require_https and (not analyzer_url.startswith("https://") or not anonymizer_url.startswith("https://")):
            raise FailClosed("presidio_must_be_https")
        self._egress_check(analyzer_url, purpose="presidio")
        self._egress_check(anonymizer_url, purpose="presidio")
        verify: bool | str = ca_file if ca_file else True
        self._client = httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(timeout_seconds),
            verify=verify,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def anonymize_text(self, text: str) -> tuple[str, dict[str, int]]:
        analyze_body = {
            "text": text,
            "language": "en",
            "score_threshold": self.score_threshold,
            "ad_hoc_recognizers": list(self.recognizers.ad_hoc),
        }
        analyzed = await self._post(self.analyzer_url, analyze_body)
        results = self._parse_analyzer(analyzed, text)
        # Mask every detection. There is no pass band between scores.
        anonymize_body = {
            "text": text,
            "analyzer_results": results,
            "anonymizers": {"DEFAULT": {"type": "replace", "new_value": "<{entity_type}>"}},
        }
        anonymized = await self._post(self.anonymizer_url, anonymize_body)
        if not isinstance(anonymized, dict) or not isinstance(anonymized.get("text"), str):
            raise FailClosed("presidio_malformed")
        output = anonymized["text"]
        if results and output == text:
            raise FailClosed("presidio_anonymizer_ineffective")
        counts: dict[str, int] = {}
        for item in results:
            counts[item["entity_type"]] = counts.get(item["entity_type"], 0) + 1
        return output, counts

    async def _post(self, url: str, payload: dict[str, Any]) -> Any:
        self._egress_check(url, purpose="presidio")
        try:
            response = await self._client.post(url, json=payload, headers={"Accept": "application/json"})
        except httpx.TimeoutException:
            raise FailClosed("presidio_timeout") from None
        except httpx.RemoteProtocolError:
            raise FailClosed("presidio_stream_interrupted") from None
        except httpx.HTTPError:
            raise FailClosed("presidio_unreachable") from None
        try:
            chunks: list[bytes] = []
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > 1_000_000:
                    raise FailClosed("presidio_payload_too_large")
                chunks.append(chunk)
            raw = b"".join(chunks)
        except FailClosed:
            raise
        except httpx.RemoteProtocolError:
            raise FailClosed("presidio_stream_interrupted") from None
        except httpx.HTTPError:
            raise FailClosed("presidio_stream_interrupted") from None
        if response.status_code >= 400:
            raise FailClosed("presidio_http_error")
        content_type = response.headers.get("content-type", "")
        if "application/json" not in content_type:
            raise FailClosed("presidio_malformed")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            raise FailClosed("presidio_malformed") from None

    def _parse_analyzer(self, payload: Any, text: str) -> list[dict[str, Any]]:
        if not isinstance(payload, list):
            raise FailClosed("presidio_malformed")
        cleaned: list[dict[str, Any]] = []
        for item in payload:
            if not isinstance(item, dict):
                raise FailClosed("presidio_malformed")
            entity = item.get("entity_type")
            start = item.get("start")
            end = item.get("end")
            score = item.get("score")
            if not isinstance(entity, str) or _ENTITY.match(entity) is None:
                raise FailClosed("presidio_malformed")
            if not isinstance(start, int) or not isinstance(end, int) or isinstance(start, bool):
                raise FailClosed("presidio_malformed")
            if not isinstance(score, (int, float)) or isinstance(score, bool):
                raise FailClosed("presidio_malformed")
            if start < 0 or end > len(text) or start >= end:
                raise FailClosed("presidio_malformed")
            cleaned.append(
                {"entity_type": entity, "start": start, "end": end, "score": float(score)}
            )
        return cleaned
