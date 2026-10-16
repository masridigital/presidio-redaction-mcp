"""Audit log and a PHI-free view of it.

The proxy tool-call log stays an HMAC chain. The admin config chain is signed
with the config key. The proxy verifies that signature and does not hold it.
Rendering keeps an allowlist of metadata fields and drops everything else.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from presidio_admin.signing import ConfigSigner, canonical, sha256_hex

GENESIS = "0" * 64

ALLOWED_FIELDS = frozenset(
    {
        "ts",
        "event",
        "caller",
        "ingress",
        "phi_capable",
        "upstream",
        "tool",
        "args_hmac",
        "entity_counts",
        "decision",
        "reason_code",
        "latency_ms",
        "config_sha256",
        "published_sha256",
        "prev_hash",
        "row_hash",
        "actor_oid",
        "action",
        "proposal_id",
        "version_id",
        "risk_flags",
        "upn_domain",
    }
)

# Names that must never be rendered, even if a writer put them on a row.
FORBIDDEN_FIELDS = frozenset(
    {
        "payload",
        "arguments",
        "args",
        "result",
        "results",
        "content",
        "text",
        "body",
        "token",
        "secret",
        "password",
        "authorization",
        "phi",
        "patient",
        "mrn",
        "ssn",
        "email",
        "query",
        "message",
        "prompt",
        "input",
        "output",
        "document",
        "note",
        "name",
        "address",
        "phone",
    }
)

_SENSITIVE = re.compile(
    r"(?i)("
    r"\bmrn[\s-]*syn[\s-]*\d{7}\b|"
    r"\brec-syn-\d{6}\b|"
    r"\bacct-syn-\d{8}\b|"
    r"\bnpi-syn-\d{10}\b|"
    r"\b\d{3}-\d{2}-\d{4}\b|"
    r"\b\d{3}\.\d{2}\.\d{4}\b|"
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|"
    r"\b(?:bearer|sk-|api[_-]?key|secret)\b|"
    r"\b4111[ -]?1111[ -]?1111[ -]?1111\b|"
    r"123 fake street"
    r")"
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
REDACTED = "[redacted]"


def canonical_body(row: dict[str, Any]) -> bytes:
    body = {key: value for key, value in row.items() if key != "row_hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def row_hmac(key: bytes, row: dict[str, Any]) -> str:
    return hmac.new(key, canonical_body(row), hashlib.sha256).hexdigest()


def verify_lines(lines: list[str], key: bytes) -> bool:
    previous = GENESIS
    for line in lines:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            return False
        if not isinstance(row, dict):
            return False
        presented = row.get("row_hash")
        if row.get("prev_hash") != previous or not isinstance(presented, str):
            return False
        expected = row_hmac(key, row)
        if not hmac.compare_digest(expected, presented):
            return False
        previous = presented
    return True


def project_row(row: dict[str, Any]) -> dict[str, Any]:
    """Copy metadata only. Forbidden keys and sensitive values are removed."""
    projected: dict[str, Any] = {}
    for key, value in row.items():
        if key not in ALLOWED_FIELDS or key.lower() in FORBIDDEN_FIELDS:
            continue
        projected[key] = _scrub(key, value)
    return projected


def render_lines(lines: list[str], key: bytes) -> dict[str, Any]:
    chain_valid = verify_lines(lines, key)
    rows: list[dict[str, Any]] = []
    for line in lines:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(project_row(row))
    return {"chain_valid": chain_valid, "rows": rows}


def read_lines(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


class AuditChain:
    """Append-only admin chain. Each row is signed. Payload fields are dropped first."""

    def __init__(self, signer: ConfigSigner, *, read_text: Any, write_text: Any) -> None:
        self.signer = signer
        self._read_text = read_text
        self._write_text = write_text
        self._lock = threading.Lock()
        self._prev = self._tail()

    def append(self, row: dict[str, Any]) -> None:
        with self._lock:
            clean = {
                key: value
                for key, value in row.items()
                if key in ALLOWED_FIELDS and key.lower() not in FORBIDDEN_FIELDS and key not in {"row_hash", "signature"}
            }
            clean["ts"] = datetime.now(UTC).isoformat()
            clean["prev_hash"] = self._prev
            line = seal_line(self.signer, clean)
            current = self._read_text()
            prefix = current if current.endswith("\n") or not current else current + "\n"
            self._write_text(prefix + line + "\n")
            self._prev = str(json.loads(line)["row_hash"])

    def verify(self) -> bool:
        return verify_signed_lines(self._lines(), self.signer)

    def render(self) -> dict[str, Any]:
        rows = []
        for line in self._lines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(project_row(row))
        return {"chain_valid": self.verify(), "rows": rows}

    def _lines(self) -> list[str]:
        return [line for line in self._read_text().splitlines() if line.strip()]

    def _tail(self) -> str:
        lines = self._lines()
        if not lines:
            return GENESIS
        try:
            row = json.loads(lines[-1])
        except json.JSONDecodeError:
            return GENESIS
        value = row.get("row_hash") if isinstance(row, dict) else None
        if isinstance(value, str) and _HEX64.match(value):
            return value
        return GENESIS


def seal_line(signer: ConfigSigner, row: dict[str, Any]) -> str:
    body = {key: value for key, value in row.items() if key not in {"signature", "row_hash"}}
    body["row_hash"] = sha256_hex(canonical(body))
    body["signature"] = {"alg": "PS256", "kid": signer.key_id, "sig": signer.sign(canonical(body))}
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def verify_signed_lines(lines: list[str], signer: ConfigSigner) -> bool:
    previous = GENESIS
    for line in lines:
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            return False
        if not isinstance(row, dict) or not _signed_row_ok(signer, row, previous):
            return False
        previous = str(row["row_hash"])
    return True


def _signed_row_ok(signer: ConfigSigner, row: dict[str, Any], previous: str) -> bool:
    signature = row.get("signature")
    if not isinstance(signature, dict) or signature.get("alg") != "PS256":
        return False
    kid = signature.get("kid")
    sig = signature.get("sig")
    if not isinstance(kid, str) or not isinstance(sig, str):
        return False
    body = {key: value for key, value in row.items() if key != "signature"}
    link = {key: value for key, value in body.items() if key != "row_hash"}
    if sha256_hex(canonical(link)) != body.get("row_hash"):
        return False
    if body.get("prev_hash") != previous:
        return False
    return signer.verify(canonical(body), sig, kid)


def _scrub(key: str, value: Any) -> Any:
    if key == "entity_counts":
        if not isinstance(value, dict):
            return {}
        cleaned: dict[str, int] = {}
        for name, count in value.items():
            if not isinstance(name, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", name):
                continue
            if isinstance(count, bool) or not isinstance(count, int):
                continue
            cleaned[name] = count
        return cleaned
    if key in {"prev_hash", "row_hash", "args_hmac", "config_sha256", "published_sha256"}:
        if isinstance(value, str) and _HEX64.match(value):
            return value
        return REDACTED
    if key in {"phi_capable"}:
        return bool(value) if isinstance(value, bool) else REDACTED
    if key in {"latency_ms", "version_id"}:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return REDACTED
        return value
    if isinstance(value, str):
        if _SENSITIVE.search(value):
            return REDACTED
        if len(value) > 200:
            return REDACTED
        return value
    if isinstance(value, list):
        items = []
        for item in value:
            if isinstance(item, str) and not _SENSITIVE.search(item) and len(item) <= 200:
                items.append(item)
        return items
    return REDACTED
