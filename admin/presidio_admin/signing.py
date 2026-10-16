"""HMAC signatures for version records, proposals, and the active pointer.

The signature covers the canonical JSON with the signature field removed.
A writer who can change the files but does not hold the store key cannot
produce a document the proxy will load.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


def canonical(payload: dict[str, Any]) -> bytes:
    body = {key: value for key, value in payload.items() if key != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_document(payload: dict[str, Any], key: bytes) -> dict[str, Any]:
    signed = {key_name: value for key_name, value in payload.items() if key_name != "signature"}
    signed["signature"] = hmac.new(key, canonical(signed), hashlib.sha256).hexdigest()
    return signed


def signature_ok(payload: dict[str, Any], key: bytes) -> bool:
    presented = payload.get("signature")
    if not isinstance(presented, str) or len(presented) != 64:
        return False
    expected = hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, presented)
