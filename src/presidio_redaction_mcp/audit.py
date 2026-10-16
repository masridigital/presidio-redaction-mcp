"""Hash-chained audit log. Payloads, tokens, and raw identifiers are not written."""

from __future__ import annotations

import hashlib
import hmac
import json
import syslog
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_GENESIS = "0" * 64


class AuditLog:
    def __init__(
        self,
        path: Path,
        state_path: Path,
        hmac_key: bytes,
        *,
        forward: str | None = None,
    ) -> None:
        if forward is not None and forward != "syslog" and not forward.startswith("file:"):
            raise ValueError("audit_forward_invalid")
        self.path = path
        self.state_path = state_path
        self.hmac_key = hmac_key
        self.forward = forward
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            self.path.chmod(0o600)
        else:
            self.path.touch(mode=0o600)
            self.path.chmod(0o600)
        self._prev = self._tail_hash()

    def note_config(
        self,
        config_sha256: str,
        *,
        version_id: int | None = None,
        published_sha256: str | None = None,
    ) -> None:
        marker = config_sha256 if version_id is None else f"{config_sha256}:{version_id}:{published_sha256 or ''}"
        previous = None
        if self.state_path.exists():
            previous = self.state_path.read_text(encoding="utf-8").strip() or None
        if previous != marker:
            row: dict[str, Any] = {
                "event": "config_change",
                "caller": "process",
                "decision": "recorded",
                "reason_code": "config_loaded",
                "previous_config_sha256": previous,
                "config_sha256": config_sha256,
            }
            if version_id is not None:
                row["version_id"] = version_id
            if published_sha256:
                row["published_sha256"] = published_sha256
            self._write(row)
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(marker + "\n", encoding="utf-8")
            self.state_path.chmod(0o600)

    def record(
        self,
        *,
        caller: str,
        ingress: str | None,
        phi_capable: bool | None,
        upstream: str | None,
        tool: str | None,
        args_hmac: str | None,
        entity_counts: dict[str, int] | None,
        decision: str,
        reason_code: str,
        latency_ms: float,
        config_sha256: str,
        event: str = "tool_call",
    ) -> None:
        self._write(
            {
                "event": event,
                "caller": caller,
                "ingress": ingress,
                "phi_capable": phi_capable,
                "upstream": upstream,
                "tool": tool,
                "args_hmac": args_hmac,
                "entity_counts": entity_counts or {},
                "decision": decision,
                "reason_code": reason_code,
                "latency_ms": round(latency_ms, 3),
                "config_sha256": config_sha256,
            }
        )

    def record_verifier(
        self,
        *,
        caller: str,
        ingress: str,
        upstream: str | None,
        tool: str | None,
        direction: str,
        decision: str,
        reason_code: str,
        verdict: str | None,
        entity_counts: dict[str, int],
        input_hmac: str,
        model: str | None,
        latency_ms: float,
        config_sha256: str,
    ) -> None:
        """Verifier decision. ``input_hmac`` covers the redacted text. The text is not stored."""
        self._write(
            {
                "event": "verifier_decision",
                "caller": caller,
                "ingress": ingress,
                "upstream": upstream,
                "tool": tool,
                "direction": direction,
                "decision": decision,
                "reason_code": reason_code,
                "verdict": verdict,
                "entity_counts": entity_counts,
                "input_hmac": input_hmac,
                "model": model,
                "latency_ms": round(latency_ms, 3),
                "config_sha256": config_sha256,
            }
        )

    def verify(self) -> bool:
        previous = _GENESIS
        for line in self._lines():
            row = json.loads(line)
            row_hash = row.pop("row_hash", "")
            if row.get("prev_hash") != previous:
                return False
            body = json.dumps(row, sort_keys=True, separators=(",", ":")).encode("utf-8")
            expected = hmac.new(self.hmac_key, body, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, str(row_hash)):
                return False
            previous = str(row_hash)
        return True

    def _write(self, row: dict[str, Any]) -> None:
        row["ts"] = datetime.now(UTC).isoformat()
        row["prev_hash"] = self._prev
        body = json.dumps(row, sort_keys=True, separators=(",", ":")).encode("utf-8")
        row_hash = hmac.new(self.hmac_key, body, hashlib.sha256).hexdigest()
        row["row_hash"] = row_hash
        line = json.dumps(row, sort_keys=True, separators=(",", ":"))
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        self.path.chmod(0o600)
        self._prev = row_hash
        self._forward(line)

    def _forward(self, line: str) -> None:
        if not self.forward:
            return
        if self.forward == "syslog":
            syslog.openlog("presidio-redaction-mcp", syslog.LOG_PID, syslog.LOG_AUTH)
            syslog.syslog(syslog.LOG_INFO, line)
            return
        destination = Path(self.forward.removeprefix("file:"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        destination.chmod(0o600)

    def rows(self) -> list[dict[str, Any]]:
        rows = []
        for line in self._lines():
            rows.append(json.loads(line))
        return rows

    def _lines(self) -> list[str]:
        if not self.path.exists():
            return []
        return [line for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def _tail_hash(self) -> str:
        lines = self._lines()
        if not lines:
            return _GENESIS
        try:
            row = json.loads(lines[-1])
        except json.JSONDecodeError:
            return _GENESIS
        value = row.get("row_hash")
        if isinstance(value, str) and len(value) == 64:
            return value
        return _GENESIS
