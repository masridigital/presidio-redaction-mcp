"""Structured audit log. Payloads, tokens, and raw identifiers are not written."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, path: Path, state_path: Path) -> None:
        self.path = path
        self.state_path = state_path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            self.path.chmod(0o600)
        else:
            self.path.touch(mode=0o600)
            self.path.chmod(0o600)

    def note_config(self, config_sha256: str) -> None:
        previous = None
        if self.state_path.exists():
            previous = self.state_path.read_text(encoding="utf-8").strip() or None
        if previous != config_sha256:
            self._write(
                {
                    "event": "config_change",
                    "caller": "process",
                    "decision": "recorded",
                    "reason_code": "config_loaded",
                    "previous_config_sha256": previous,
                    "config_sha256": config_sha256,
                }
            )
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(config_sha256 + "\n", encoding="utf-8")
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
    ) -> None:
        self._write(
            {
                "event": "tool_call",
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

    def _write(self, row: dict[str, Any]) -> None:
        row["ts"] = datetime.now(UTC).isoformat()
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        self.path.chmod(0o600)

    def rows(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        rows = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
        return rows
