"""Two-person approval for changes that widen access or weaken detection.

A single Admin may tighten a control. Enabling a tool, lowering a threshold,
raising the Presidio score floor, disabling the Claude verifier, disabling a
recognizer, or adding or re-enabling a client stays pending until a different
Admin approves it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Literal

from presidio_admin.authz import Principal
from presidio_admin.errors import ApprovalError, ConfigRejected
from presidio_admin.schema import PortalConfig, parse_config
from presidio_admin.store import ConfigStore, Proposal

RISKY_PREFIXES = (
    "enable_tool:",
    "enable_upstream:",
    "lower_threshold:",
    "weaken_detection:",
    "disable_verifier",
    "disable_recognizer:",
    "add_client:",
    "enable_client:",
)


def is_risky(flags: tuple[str, ...] | list[str]) -> bool:
    return any(flag == prefix or flag.startswith(prefix) for flag in flags for prefix in RISKY_PREFIXES)


@dataclass(frozen=True)
class ChangeResult:
    status: Literal["applied", "pending", "rejected", "withdrawn"]
    version_id: int | None
    proposal_id: str | None
    risk_flags: tuple[str, ...]


class ChangeService:
    def __init__(self, store: ConfigStore) -> None:
        self.store = store

    def submit(self, principal: Principal, patch: dict[str, Any]) -> ChangeResult:
        current = self.store.read_active()
        try:
            proposed = apply_patch(current.config, patch)
        except ConfigRejected as exc:
            raise ApprovalError(exc.reason_code) from exc
        if _canonical(current.config) == _canonical(proposed):
            raise ApprovalError("change_empty")
        flags = tuple(risk_flags(current.config, proposed))
        summary = flags or (f"tighten:{patch.get('op')}",)
        if flags:
            pending = [item for item in self.store.list_proposals() if item.status == "pending"]
            if pending:
                raise ApprovalError("proposal_pending")
            proposal = Proposal(
                proposal_id=str(uuid.uuid4()),
                proposer_oid=principal.oid,
                created_at=_now(),
                base_version_id=current.version_id,
                base_sha256=current.sha256,
                config_sha256=_sha(proposed),
                risk_flags=flags,
                summary=summary,
                status="pending",
                config=proposed,
            )
            self.store.save_proposal(proposal)
            self.store.audit.append(
                {
                    "event": "admin_change",
                    "actor_oid": principal.oid,
                    "action": "propose",
                    "proposal_id": proposal.proposal_id,
                    "version_id": current.version_id,
                    "decision": "pending",
                    "reason_code": "awaiting_second_admin",
                    "risk_flags": ",".join(flags),
                    "config_sha256": current.sha256,
                    "published_sha256": _sha(proposed),
                    "upn_domain": principal.upn_domain,
                }
            )
            return ChangeResult("pending", None, proposal.proposal_id, flags)
        record = self.store.publish(
            proposed,
            actor_oid=principal.oid,
            approver_oid=None,
            summary=list(summary),
            proposal_id="",
            action="publish",
        )
        self.store.mark_pending_stale()
        return ChangeResult("applied", record.version_id, None, ())

    def approve(self, principal: Principal, proposal_id: str) -> ChangeResult:
        proposal = self._pending(proposal_id)
        if proposal.proposer_oid == principal.oid:
            raise ApprovalError("self_approval_forbidden")
        current = self.store.read_active()
        if proposal.base_version_id != current.version_id or proposal.base_sha256 != current.sha256:
            proposal.status = "stale"
            self.store.save_proposal(proposal)
            raise ApprovalError("stale_proposal")
        if proposal.config_sha256 != _sha(proposal.config):
            raise ApprovalError("store_signature_invalid")
        flags = tuple(risk_flags(current.config, proposal.config))
        if tuple(proposal.risk_flags) != flags:
            raise ApprovalError("risk_flags_mismatch")
        record = self.store.publish(
            proposal.config,
            actor_oid=proposal.proposer_oid,
            approver_oid=principal.oid,
            summary=list(proposal.summary),
            proposal_id=proposal.proposal_id,
            action="approve",
        )
        proposal.status = "approved"
        proposal.approver_oid = principal.oid
        proposal.decided_at = _now()
        proposal.applied_version_id = record.version_id
        self.store.save_proposal(proposal)
        return ChangeResult("applied", record.version_id, proposal.proposal_id, flags)

    def reject(self, principal: Principal, proposal_id: str) -> ChangeResult:
        proposal = self._pending(proposal_id)
        if principal.oid != proposal.proposer_oid:
            proposal.status = "rejected"
            reason = "rejected"
            status: Literal["rejected", "withdrawn"] = "rejected"
        else:
            proposal.status = "withdrawn"
            reason = "withdrawn"
            status = "withdrawn"
        proposal.approver_oid = principal.oid
        proposal.decided_at = _now()
        self.store.save_proposal(proposal)
        self.store.audit.append(
            {
                "event": "admin_change",
                "actor_oid": principal.oid,
                "action": reason,
                "proposal_id": proposal.proposal_id,
                "version_id": proposal.base_version_id,
                "decision": reason,
                "reason_code": reason,
                "risk_flags": ",".join(proposal.risk_flags),
            }
        )
        return ChangeResult(status, None, proposal.proposal_id, proposal.risk_flags)

    def _pending(self, proposal_id: str) -> Proposal:
        try:
            proposal = self.store.get_proposal(proposal_id)
        except ConfigRejected as exc:
            raise ApprovalError("proposal_missing") from exc
        if proposal.status == "stale":
            raise ApprovalError("stale_proposal")
        if proposal.status != "pending":
            raise ApprovalError("proposal_not_pending")
        return proposal


def apply_patch(config: PortalConfig, patch: dict[str, Any]) -> PortalConfig:
    if not isinstance(patch, dict) or not isinstance(patch.get("op"), str):
        raise ConfigRejected("change_rejected")
    data = config.model_dump(mode="json")
    op = patch["op"]
    try:
        if op == "set_tool_enabled":
            tool = _tool(data, str(patch["upstream"]), str(patch["tool"]))
            tool["enabled"] = _bool(patch["enabled"])
        elif op == "set_upstream_enabled":
            data["upstreams"][str(patch["upstream"])]["enabled"] = _bool(patch["enabled"])
        elif op == "set_score_threshold":
            data["score_threshold"] = float(patch["value"])
        elif op == "set_pattern_score":
            pattern = _pattern(data, str(patch["recognizer"]), str(patch["pattern"]))
            pattern["score"] = float(patch["value"])
        elif op == "set_pattern_enabled":
            pattern = _pattern(data, str(patch["recognizer"]), str(patch["pattern"]))
            pattern["enabled"] = _bool(patch["enabled"])
        elif op == "set_verifier":
            data["claude_verifier_enabled"] = _bool(patch["enabled"])
        elif op == "add_client":
            data["clients"].append(
                {
                    "client_id": str(patch["client_id"]),
                    "display_name": str(patch["display_name"]),
                    "app_role": str(patch["app_role"]),
                    "enabled": True,
                }
            )
        elif op == "set_client_enabled":
            client = _client(data, str(patch["client_id"]))
            client["enabled"] = _bool(patch["enabled"])
        else:
            raise ConfigRejected("change_rejected")
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfigRejected("change_rejected") from exc
    return parse_config(data)


def risk_flags(before: PortalConfig, after: PortalConfig) -> list[str]:
    flags: list[str] = []
    for name, upstream in after.upstreams.items():
        previous = before.upstreams[name]
        if upstream.enabled and not previous.enabled:
            flags.append(f"enable_upstream:{name}")
        previous_tools = {tool.name: tool for tool in previous.tools}
        for tool in upstream.tools:
            old = previous_tools.get(tool.name)
            if tool.enabled and (old is None or not old.enabled):
                flags.append(f"enable_tool:{tool.name}")
    if after.score_threshold < before.score_threshold:
        flags.append(f"lower_threshold:score_threshold:{before.score_threshold}->{after.score_threshold}")
    if after.score_threshold > before.score_threshold:
        flags.append(
            f"weaken_detection:score_threshold:{before.score_threshold}->{after.score_threshold}"
        )
    before_patterns = {
        (recognizer.name, pattern.name): pattern
        for recognizer in before.recognizers
        for pattern in recognizer.patterns
    }
    for recognizer in after.recognizers:
        for pattern in recognizer.patterns:
            old = before_patterns[(recognizer.name, pattern.name)]
            if pattern.score < old.score:
                flags.append(f"lower_threshold:{pattern.name}:{old.score}->{pattern.score}")
            if old.enabled and not pattern.enabled:
                flags.append(f"disable_recognizer:{pattern.name}")
    if before.claude_verifier_enabled and not after.claude_verifier_enabled:
        flags.append("disable_verifier")
    before_clients = {client.client_id: client for client in before.clients}
    for client in after.clients:
        old = before_clients.get(client.client_id)
        if old is None:
            flags.append(f"add_client:{client.client_id}")
        elif client.enabled and not old.enabled:
            flags.append(f"enable_client:{client.client_id}")
    return flags


def _tool(data: dict[str, Any], upstream: str, name: str) -> dict[str, Any]:
    for tool in data["upstreams"][upstream]["tools"]:
        if tool["name"] == name:
            return tool
    raise KeyError(name)


def _pattern(data: dict[str, Any], recognizer: str, name: str) -> dict[str, Any]:
    for item in data["recognizers"]:
        if item["name"] != recognizer:
            continue
        for pattern in item["patterns"]:
            if pattern["name"] == name:
                return pattern
    raise KeyError(name)


def _client(data: dict[str, Any], client_id: str) -> dict[str, Any]:
    for client in data["clients"]:
        if client["client_id"] == client_id.lower():
            return client
    raise KeyError(client_id)


def _bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    raise ValueError("bool_required")


def describe_diff(before: PortalConfig, after: PortalConfig) -> list[str]:
    """Metadata-only lines an approver can read. No payloads and no regex text."""
    lines: list[str] = []
    if before.score_threshold != after.score_threshold:
        lines.append(f"score_threshold {before.score_threshold} -> {after.score_threshold}")
    if before.claude_verifier_enabled != after.claude_verifier_enabled:
        lines.append(
            f"verifier {'on' if before.claude_verifier_enabled else 'off'} -> "
            f"{'on' if after.claude_verifier_enabled else 'off'}"
        )
    for name, upstream in after.upstreams.items():
        previous = before.upstreams[name]
        if previous.enabled != upstream.enabled:
            lines.append(f"upstream {name} {'on' if previous.enabled else 'off'} -> {'on' if upstream.enabled else 'off'}")
        old_tools = {tool.name: tool.enabled for tool in previous.tools}
        for tool in upstream.tools:
            if old_tools.get(tool.name) != tool.enabled:
                lines.append(f"tool {tool.name} {'on' if old_tools.get(tool.name) else 'off'} -> {'on' if tool.enabled else 'off'}")
    before_patterns = {
        (recognizer.name, pattern.name): pattern
        for recognizer in before.recognizers
        for pattern in recognizer.patterns
    }
    for recognizer in after.recognizers:
        for pattern in recognizer.patterns:
            old = before_patterns[(recognizer.name, pattern.name)]
            if old.score != pattern.score or old.enabled != pattern.enabled:
                lines.append(
                    f"pattern {pattern.name} {old.score}/{'on' if old.enabled else 'off'} -> "
                    f"{pattern.score}/{'on' if pattern.enabled else 'off'}"
                )
    before_clients = {client.client_id: client for client in before.clients}
    for client in after.clients:
        old = before_clients.get(client.client_id)
        if old is None:
            lines.append(f"client {client.client_id} add {client.app_role}")
        elif old.enabled != client.enabled or old.app_role != client.app_role:
            lines.append(f"client {client.client_id} {old.app_role}/{'on' if old.enabled else 'off'} -> {client.app_role}/{'on' if client.enabled else 'off'}")
    return lines


def _sha(config: PortalConfig) -> str:
    import hashlib

    raw = json_dumps(config.model_dump(mode="json")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _canonical(config: PortalConfig) -> str:
    return json_dumps(config.model_dump(mode="json"))


def json_dumps(payload: dict[str, Any]) -> str:
    import json

    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _now() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()
