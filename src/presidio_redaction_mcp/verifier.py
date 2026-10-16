"""Second-pass PHI check against the Anthropic Messages API.

Claude's output is untrusted. A schema-valid ``clear`` is the only result that
continues. Timeouts, errors, uncertainty, echoes, and instruction overrides
fail closed. The client pins ``POST /v1/messages`` and never sends a beta header.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from presidio_redaction_mcp.errors import FailClosed
from presidio_redaction_mcp.verifier_policy import (
    ALLOWED_BODY_KEYS,
    ANTHROPIC_VERSION,
    BEGIN,
    END,
    ENTITY_TYPES,
    FORBIDDEN_BODY_KEYS,
    MESSAGES_URL,
    SYSTEM_PROMPT,
    instruction_override,
    verdict_schema,
)

_ALLOWED_HEADERS = frozenset({"content-type", "x-api-key", "anthropic-version", "accept"})
_TOKEN = re.compile(r"[A-Za-z0-9]{8,}")


class SpanVerdict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    start: int
    end: int
    entity_type: str

    @field_validator("start", "end")
    @classmethod
    def _offset(cls, value: int) -> int:
        if isinstance(value, bool) or value < 0:
            raise ValueError("offset")
        return value

    @field_validator("entity_type")
    @classmethod
    def _entity(cls, value: str) -> str:
        if value not in ENTITY_TYPES:
            raise ValueError("entity_type")
        return value


class Verdict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    verdict: str
    spans: list[SpanVerdict]

    @field_validator("verdict")
    @classmethod
    def _verdict(cls, value: str) -> str:
        if value not in {"clear", "phi", "uncertain"}:
            raise ValueError("verdict")
        return value

    @field_validator("spans")
    @classmethod
    def _cap(cls, value: list[SpanVerdict]) -> list[SpanVerdict]:
        if len(value) > 32:
            raise ValueError("spans")
        return value

    def entity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for span in self.spans:
            counts[span.entity_type] = counts.get(span.entity_type, 0) + 1
        return counts


class ClaudeVerifier:
    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        timeout_seconds: float,
        max_tokens: int,
        egress_check: Any,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if not api_key or "replace-with" in api_key:
            raise FailClosed("anthropic_key_missing")
        self.model = model
        self.max_tokens = max_tokens
        self._api_key = api_key
        self._egress_check = egress_check
        self._egress_check(MESSAGES_URL, purpose="verifier")
        self._client = httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def verify(self, text: str) -> Verdict:
        if instruction_override(text):
            raise FailClosed("verifier_instruction_override")
        delimited = f"{BEGIN}\n{text}\n{END}"
        body = _request_body(self.model, self.max_tokens, delimited)
        raw, payload = await self._post(body)
        if _echoes(text, raw):
            raise FailClosed("verifier_echo")
        return _parse_verdict(payload, text)

    async def _post(self, body: dict[str, Any]) -> tuple[str, Any]:
        self._egress_check(MESSAGES_URL, purpose="verifier")
        try:
            response = await self._client.post(MESSAGES_URL, json=body, headers=_headers(self._api_key))
        except httpx.TimeoutException:
            raise FailClosed("verifier_timeout") from None
        except httpx.HTTPError:
            raise FailClosed("verifier_unreachable") from None
        if response.status_code >= 400 or response.is_redirect:
            raise FailClosed("verifier_http_error")
        content_type = response.headers.get("content-type", "")
        if "application/json" not in content_type:
            raise FailClosed("verifier_malformed")
        try:
            size = 0
            chunks: list[bytes] = []
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > 1_000_000:
                    raise FailClosed("verifier_malformed")
                chunks.append(chunk)
            raw = b"".join(chunks).decode("utf-8")
            payload = json.loads(raw)
        except FailClosed:
            raise
        except (UnicodeError, json.JSONDecodeError, httpx.HTTPError):
            raise FailClosed("verifier_malformed") from None
        if not isinstance(payload, dict):
            raise FailClosed("verifier_malformed")
        return raw, payload


def _request_body(model: str, max_tokens: int, delimited: str) -> dict[str, Any]:
    body = {
        "model": model,
        "max_tokens": max_tokens,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": delimited}],
        "output_config": {"format": {"type": "json_schema", "schema": verdict_schema()}},
    }
    present = set(body)
    if present - ALLOWED_BODY_KEYS or present & FORBIDDEN_BODY_KEYS:
        raise FailClosed("verifier_malformed")
    return body


def _headers(api_key: str) -> dict[str, str]:
    headers = {
        "content-type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": ANTHROPIC_VERSION,
        "accept": "application/json",
    }
    lowered = {name.lower() for name in headers}
    if lowered - _ALLOWED_HEADERS or any(name.startswith("anthropic-beta") for name in lowered):
        raise FailClosed("verifier_malformed")
    return headers


def _parse_verdict(payload: dict[str, Any], source: str) -> Verdict:
    if payload.get("stop_reason") != "end_turn":
        raise FailClosed("verifier_malformed")
    content = payload.get("content")
    if not isinstance(content, list) or len(content) != 1 or not isinstance(content[0], dict):
        raise FailClosed("verifier_malformed")
    block = content[0]
    if block.get("type") != "text" or not isinstance(block.get("text"), str):
        raise FailClosed("verifier_malformed")
    text = block["text"].strip()
    if not text.startswith("{") or not text.endswith("}"):
        raise FailClosed("verifier_malformed")
    try:
        parsed = json.loads(text)
        verdict = Verdict.model_validate(parsed)
    except (json.JSONDecodeError, ValidationError, ValueError):
        raise FailClosed("verifier_malformed") from None
    if _echoes(source, text):
        raise FailClosed("verifier_echo")
    _check_spans(verdict, source)
    return verdict


def _check_spans(verdict: Verdict, source: str) -> None:
    if verdict.verdict == "clear":
        if verdict.spans:
            raise FailClosed("verifier_malformed")
        return
    if verdict.verdict == "uncertain":
        return
    if not verdict.spans:
        raise FailClosed("verifier_malformed")
    for span in verdict.spans:
        if span.start >= span.end or span.end > len(source):
            raise FailClosed("verifier_malformed")


def _echoes(source: str, response_text: str) -> bool:
    """Reject a response that repeats a substantive token from the submitted data.

    JSON encoding escapes quotes, so a raw substring compare is not enough.
    Alphanumeric runs of 8 or more still show up after that escaping.
    """
    if len(source) >= 8 and source in response_text:
        return True
    for match in _TOKEN.finditer(source):
        if match.group(0) in response_text:
            return True
    return False
