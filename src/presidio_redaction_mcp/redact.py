"""Walk tool args and results. Field allowlists run before Presidio. Unanalyzable content blocks."""

from __future__ import annotations

import base64
import json
import re
from typing import Any

from presidio_redaction_mcp.errors import FailClosed
from presidio_redaction_mcp.presidio_client import PresidioClient
from presidio_redaction_mcp.recognizers import RecognizerSet

_BASE64 = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_UNANALYZABLE = frozenset(
    {"blob", "image", "audio", "file", "attachment", "pdf", "bytes", "resource", "embedded"}
)
_SENSITIVE_FIELDS = frozenset(
    {
        "mrn",
        "ssn",
        "email",
        "phone",
        "dob",
        "patient",
        "patient_name",
        "account",
        "account_number",
        "npi",
        "address",
        "name",
        "friendly_name",
        "url",
        "alert_contacts",
        "alert_contact",
    }
)


class Redactor:
    def __init__(
        self,
        client: PresidioClient,
        recognizers: RecognizerSet,
        max_payload_bytes: int,
        *,
        max_depth: int = 6,
        max_nodes: int = 200,
        max_strings: int = 80,
        max_list_items: int = 20,
        max_presidio_calls: int = 400,
    ) -> None:
        self.client = client
        self.recognizers = recognizers
        self.max_payload_bytes = max_payload_bytes
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.max_strings = max_strings
        self.max_list_items = max_list_items
        self.max_presidio_calls = max_presidio_calls
        self._presidio_calls = 0

    async def redact(self, value: Any) -> tuple[Any, dict[str, int]]:
        encoded = json.dumps(value, sort_keys=True, default=str).encode("utf-8")
        if len(encoded) > self.max_payload_bytes:
            raise FailClosed("payload_too_large")
        self._measure(value, depth=0, nodes=[0], strings=[0])
        self._presidio_calls = 0
        # One full-document call first, so an outage cannot be skipped on an empty walk.
        _, probe_counts = await self._anonymize(encoded.decode("utf-8"))
        rewritten, walk_counts = await self._walk(value)
        counts = _merge(probe_counts, walk_counts)
        rendered = json.dumps(rewritten, sort_keys=True, default=str)
        if self.recognizers.find_spans(rendered):
            raise FailClosed("presidio_anonymizer_ineffective")
        return rewritten, counts

    async def _walk(self, value: Any) -> tuple[Any, dict[str, int]]:
        if isinstance(value, dict):
            counts: dict[str, int] = {}
            output: dict[str, Any] = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise FailClosed("unanalyzable_content")
                if key.lower() in _UNANALYZABLE:
                    raise FailClosed("unanalyzable_content")
                _, key_counts = await self._anonymize(key)
                if key_counts or self.recognizers.find_spans(key):
                    raise FailClosed("pii_in_key")
                if key.lower() in _SENSITIVE_FIELDS:
                    output[key] = "<REDACTED>"
                    counts["FIELD_MASK"] = counts.get("FIELD_MASK", 0) + 1
                    continue
                rewritten, item_counts = await self._walk(item)
                output[key] = rewritten
                counts = _merge(counts, item_counts)
            return output, counts
        if isinstance(value, list):
            if len(value) > self.max_list_items:
                raise FailClosed("list_too_long")
            counts = {}
            output_list = []
            for item in value:
                rewritten, item_counts = await self._walk(item)
                output_list.append(rewritten)
                counts = _merge(counts, item_counts)
            return output_list, counts
        if isinstance(value, str):
            if _looks_encoded_value(value, self.recognizers):
                raise FailClosed("unanalyzable_content")
            anonymized, counts = await self._anonymize(value)
            if self.recognizers.find_spans(anonymized):
                raise FailClosed("presidio_anonymizer_ineffective")
            return anonymized, counts
        if isinstance(value, bool) or value is None:
            return value, {}
        if isinstance(value, (int, float)):
            rendered = str(value)
            _, counts = await self._anonymize(rendered)
            if counts or self.recognizers.find_spans(rendered):
                raise FailClosed("unmaskable_scalar")
            return value, {}
        raise FailClosed("unanalyzable_content")

    async def _anonymize(self, text: str) -> tuple[str, dict[str, int]]:
        self._presidio_calls += 1
        if self._presidio_calls > self.max_presidio_calls:
            raise FailClosed("presidio_fanout_exceeded")
        return await self.client.anonymize_text(text)

    def _measure(self, value: Any, *, depth: int, nodes: list[int], strings: list[int]) -> None:
        if depth > self.max_depth:
            raise FailClosed("nesting_too_deep")
        nodes[0] += 1
        if nodes[0] > self.max_nodes:
            raise FailClosed("payload_too_complex")
        if isinstance(value, dict):
            for item in value.values():
                self._measure(item, depth=depth + 1, nodes=nodes, strings=strings)
            return
        if isinstance(value, list):
            if len(value) > self.max_list_items:
                raise FailClosed("list_too_long")
            for item in value:
                self._measure(item, depth=depth + 1, nodes=nodes, strings=strings)
            return
        if isinstance(value, str):
            strings[0] += 1
            if strings[0] > self.max_strings:
                raise FailClosed("payload_too_complex")


def filter_fields(value: Any, allowed: set[str]) -> Any:
    if isinstance(value, dict):
        return {key: filter_fields(item, allowed) for key, item in value.items() if key in allowed}
    if isinstance(value, list):
        return [filter_fields(item, allowed) for item in value]
    return value


def drop_denied_fields(value: Any, denied: set[str]) -> Any:
    """Remove caller-denied fields before Presidio sees them."""
    if isinstance(value, dict):
        return {
            key: drop_denied_fields(item, denied)
            for key, item in value.items()
            if key not in denied
        }
    if isinstance(value, list):
        return [drop_denied_fields(item, denied) for item in value]
    return value


def count_items(value: Any) -> int:
    if isinstance(value, dict) and isinstance(value.get("items"), list):
        return len(value["items"])
    if isinstance(value, list):
        return len(value)
    return 1


def _looks_encoded_value(value: str, recognizers: RecognizerSet) -> bool:
    compact = "".join(value.split())
    if len(compact) < 16 or len(compact) % 4 != 0 or _BASE64.match(compact) is None:
        return False
    if len(compact) >= 40:
        return True
    try:
        decoded = base64.b64decode(compact, validate=True)
        text = decoded.decode("utf-8")
    except (ValueError, UnicodeError):
        return False
    return bool(recognizers.find_spans(text))


def _merge(left: dict[str, int], right: dict[str, int]) -> dict[str, int]:
    merged = dict(left)
    for key, count in right.items():
        merged[key] = merged.get(key, 0) + count
    return merged
