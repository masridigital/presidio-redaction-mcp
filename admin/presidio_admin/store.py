"""Signed, append-only config versions. The active pointer is HMAC-checked on read.

Version numbers only increase. A risky delta needs an approver who is not the
actor. The proxy also requires the active hash to sit on the verified audit chain.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from presidio_admin.audit_view import AuditChain
from presidio_admin.documents import AzureBlobDocuments, LocalDocuments
from presidio_admin.errors import ConfigRejected
from presidio_admin.floor import NullFloor, floor_separated
from presidio_admin.schema import PortalConfig, parse_config
from presidio_admin.signing import ConfigSigner, sign_document, signature_ok

_GUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_PUBLISH_ACTIONS = frozenset({"bootstrap", "publish", "approve"})


@dataclass(frozen=True)
class VersionRecord:
    version_id: int
    sha256: str
    created_at: str
    actor_oid: str
    approver_oid: str | None
    risk_flags: tuple[str, ...]
    summary: tuple[str, ...]
    config: PortalConfig


@dataclass
class Proposal:
    proposal_id: str
    proposer_oid: str
    created_at: str
    base_version_id: int
    base_sha256: str
    config_sha256: str
    risk_flags: tuple[str, ...]
    summary: tuple[str, ...]
    status: str
    config: PortalConfig
    approver_oid: str | None = None
    decided_at: str | None = None
    applied_version_id: int | None = None


class ConfigStore:
    def __init__(
        self,
        root: Path,
        *,
        signer: ConfigSigner,
        documents: LocalDocuments | AzureBlobDocuments | None = None,
        floor: Any = None,
        store_location: str | None = None,
    ) -> None:
        self.root = root
        self.signer = signer
        self.floor = floor or NullFloor()
        floor_separated(store_location if store_location is not None else str(root), self.floor)
        self.documents = documents or LocalDocuments(root)
        self.audit = AuditChain(signer, read_text=self._read_audit, write_text=self._write_audit)

    @classmethod
    def open(
        cls,
        location: str,
        *,
        signer: ConfigSigner,
        token_provider: Any = None,
        floor: Any = None,
    ) -> ConfigStore:
        if location.startswith("https://"):
            if token_provider is None:
                raise ConfigRejected("identity_token_rejected")
            documents = AzureBlobDocuments(location, token_provider=token_provider)
            return cls(Path("/"), signer=signer, documents=documents, floor=floor, store_location=location)
        return cls(Path(location), signer=signer, floor=floor)

    def bootstrap(self, config: PortalConfig, *, actor_oid: str = "bootstrap") -> VersionRecord:
        with self.documents.lease():
            if self._pointer_raw() is not None:
                raise ConfigRejected("already_bootstrapped")
            return self._publish(
                config,
                actor_oid=actor_oid,
                approver_oid=None,
                summary=("bootstrap",),
                proposal_id="",
                action="bootstrap",
                previous=None,
            )

    def read_active(self) -> VersionRecord:
        return self.verify_for_proxy()

    def verify_for_proxy(self) -> VersionRecord:
        """Signature, monotonic versions, approver, and the audit hash."""
        if not self.audit.verify():
            raise ConfigRejected("audit_chain_broken")
        records = self._signed_versions()
        if not records:
            raise ConfigRejected("published_config_missing")
        ids = [record.version_id for record in records]
        if ids != list(range(1, len(ids) + 1)):
            raise ConfigRejected("version_rollback")
        from presidio_admin.approval import is_risky, risk_flags
        from presidio_admin.schema import default_config

        first_flags = tuple(risk_flags(default_config(), records[0].config))
        if first_flags != records[0].risk_flags:
            raise ConfigRejected("risk_flags_mismatch")
        if is_risky(records[0].risk_flags):
            _require_other_approver(records[0].actor_oid, records[0].approver_oid)
        for previous, current in zip(records, records[1:]):
            if current.version_id <= previous.version_id:
                raise ConfigRejected("version_rollback")
            recomputed = tuple(risk_flags(previous.config, current.config))
            if recomputed != current.risk_flags:
                raise ConfigRejected("risk_flags_mismatch")
            if is_risky(current.risk_flags):
                _require_other_approver(current.actor_oid, current.approver_oid)
        active = self._signed_pointer()
        if active.version_id != records[-1].version_id or active.sha256 != records[-1].sha256:
            raise ConfigRejected("version_rollback")
        self._require_audit_anchor(active)
        return active

    def publish(
        self,
        config: PortalConfig,
        *,
        actor_oid: str,
        approver_oid: str | None,
        summary: list[str],
        proposal_id: str,
        action: str,
    ) -> VersionRecord:
        with self.documents.lease():
            previous = self._signed_pointer() if self._pointer_raw() is not None else None
            return self._publish(
                config,
                actor_oid=actor_oid,
                approver_oid=approver_oid,
                summary=tuple(summary),
                proposal_id=proposal_id,
                action=action,
                previous=previous,
            )

    def version(self, version_id: int) -> VersionRecord:
        raw = self._read_signed(self._version_name(version_id))
        if raw is None:
            raise ConfigRejected("published_config_missing")
        return _version_from(raw)

    def history(self) -> list[dict[str, Any]]:
        rows = []
        for record in self._signed_versions():
            rows.append(
                {
                    "version_id": record.version_id,
                    "sha256": record.sha256,
                    "created_at": record.created_at,
                    "actor_oid": record.actor_oid,
                    "approver_oid": record.approver_oid or "",
                    "risk_flags": list(record.risk_flags),
                    "summary": list(record.summary),
                }
            )
        return rows

    def save_proposal(self, proposal: Proposal) -> None:
        with self.documents.lease():
            self._write_json(self._proposal_name(proposal.proposal_id), _proposal_dict(proposal), create=False)

    def get_proposal(self, proposal_id: str) -> Proposal:
        raw = self._read_signed(self._proposal_name(proposal_id))
        if raw is None:
            raise ConfigRejected("proposal_missing")
        proposal = _proposal_from(raw)
        if proposal.config_sha256 != _sha(proposal.config.model_dump(mode="json")):
            raise ConfigRejected("store_signature_invalid")
        return proposal

    def list_proposals(self) -> list[Proposal]:
        found = []
        for name in self.documents.names("proposals"):
            if not name.endswith(".json"):
                continue
            raw = self._read_signed(name)
            if raw is None:
                continue
            found.append(_proposal_from(raw))
        return found

    def mark_pending_stale(self) -> None:
        for proposal in self.list_proposals():
            if proposal.status == "pending":
                proposal.status = "stale"
                self.save_proposal(proposal)

    def _publish(
        self,
        config: PortalConfig,
        *,
        actor_oid: str,
        approver_oid: str | None,
        summary: tuple[str, ...],
        proposal_id: str,
        action: str,
        previous: VersionRecord | None,
    ) -> VersionRecord:
        from presidio_admin.approval import is_risky, risk_flags

        checked = parse_config(config.model_dump(mode="json"))
        body = checked.model_dump(mode="json")
        digest = _sha(body)
        version_id = 1 if previous is None else previous.version_id + 1
        if previous is not None and version_id <= previous.version_id:
            raise ConfigRejected("version_rollback")
        from presidio_admin.schema import default_config

        baseline = default_config() if previous is None else previous.config
        flags = tuple(risk_flags(baseline, checked))
        if is_risky(flags):
            _require_other_approver(actor_oid, approver_oid)
        elif approver_oid is not None and approver_oid == actor_oid:
            raise ConfigRejected("self_approval_forbidden")
        record = {
            "version_id": version_id,
            "prev_version_id": 0 if previous is None else previous.version_id,
            "sha256": digest,
            "created_at": _now(),
            "actor_oid": actor_oid,
            "approver_oid": approver_oid or "",
            "risk_flags": list(flags),
            "summary": list(summary),
            "proposal_id": proposal_id,
            "config": body,
        }
        self._write_json(self._version_name(version_id), record, create=True)
        self.audit.append(
            {
                "event": "admin_change",
                "actor_oid": actor_oid,
                "action": action,
                "proposal_id": proposal_id,
                "version_id": version_id,
                "decision": "recorded",
                "reason_code": action,
                "risk_flags": ",".join(flags),
                "config_sha256": digest,
            }
        )
        if not self.audit.verify():
            raise ConfigRejected("audit_chain_broken")
        pointer_match = None if previous is None else self._pointer_raw()
        self._write_json(
            "active.json",
            {"version_id": version_id, "sha256": digest},
            create=previous is None,
            if_match=None if pointer_match is None else pointer_match.etag,
        )
        return self._signed_pointer()

    def _signed_versions(self) -> list[VersionRecord]:
        records = []
        for name in self.documents.names("versions"):
            if not name.endswith(".json"):
                continue
            raw = self._read_signed(name)
            if raw is None:
                raise ConfigRejected("store_signature_invalid")
            records.append(_version_from(raw))
        records.sort(key=lambda item: item.version_id)
        return records

    def _signed_pointer(self) -> VersionRecord:
        raw = self._read_signed("active.json")
        if raw is None:
            raise ConfigRejected("published_config_missing")
        try:
            version_id = int(raw["version_id"])
            expected = str(raw["sha256"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ConfigRejected("published_config_rejected") from exc
        version = self._read_signed(self._version_name(version_id))
        if version is None:
            raise ConfigRejected("published_config_rejected")
        record = _version_from(version)
        if record.sha256 != expected or record.version_id != version_id:
            raise ConfigRejected("store_signature_invalid")
        return record

    def _require_audit_anchor(self, active: VersionRecord) -> None:
        highest = 0
        anchored = False
        for line in self._read_audit().splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ConfigRejected("audit_chain_broken") from exc
            if not isinstance(row, dict):
                raise ConfigRejected("audit_chain_broken")
            version_id = row.get("version_id")
            if isinstance(version_id, int) and version_id > highest:
                highest = version_id
            if (
                row.get("action") in _PUBLISH_ACTIONS
                and row.get("config_sha256") == active.sha256
                and row.get("version_id") == active.version_id
            ):
                anchored = True
        if not anchored:
            raise ConfigRejected("audit_hash_missing")
        if active.version_id < highest:
            raise ConfigRejected("version_rollback")
        if active.version_id < self.floor.high_water():
            raise ConfigRejected("snapshot_replay")

    def _pointer_raw(self):
        return self.documents.read("active.json")

    def _read_signed(self, name: str) -> dict[str, Any] | None:
        body = self.documents.read(name)
        if body is None:
            return None
        try:
            payload = json.loads(body.data)
        except json.JSONDecodeError as exc:
            raise ConfigRejected("published_config_rejected") from exc
        if not isinstance(payload, dict) or not signature_ok(payload, self.signer):
            raise ConfigRejected("store_signature_invalid")
        return payload

    def _write_json(
        self,
        name: str,
        payload: dict[str, Any],
        *,
        create: bool,
        if_match: str | None = None,
    ) -> None:
        signed = sign_document(payload, self.signer)
        data = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.documents.write(name, data, if_match=if_match, create=create)

    def _read_audit(self) -> str:
        body = self.documents.read("audit.jsonl")
        if body is None:
            return ""
        return body.data.decode("utf-8")

    def _write_audit(self, text: str) -> None:
        current = self.documents.read("audit.jsonl")
        self.documents.write(
            "audit.jsonl",
            text.encode("utf-8"),
            if_match=None if current is None else current.etag,
            create=current is None,
        )

    @staticmethod
    def _version_name(version_id: int) -> str:
        if version_id < 1:
            raise ConfigRejected("version_rollback")
        return f"versions/{version_id:06d}.json"

    @staticmethod
    def _proposal_name(proposal_id: str) -> str:
        if not proposal_id.replace("-", "").isalnum():
            raise ConfigRejected("proposal_missing")
        return f"proposals/{proposal_id}.json"


def _require_other_approver(actor_oid: str, approver_oid: str | None) -> None:
    if not approver_oid or approver_oid == actor_oid or _GUID.match(approver_oid) is None:
        raise ConfigRejected("approver_required")


def _sha(config: dict[str, Any]) -> str:
    import hashlib

    raw = json.dumps(config, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _now() -> str:
    from datetime import UTC, datetime

    return datetime.now(UTC).isoformat()


def _version_from(raw: dict[str, Any]) -> VersionRecord:
    try:
        config = parse_config(raw["config"])
        digest = _sha(raw["config"])
    except (KeyError, TypeError, ConfigRejected) as exc:
        raise ConfigRejected("published_config_rejected") from exc
    if digest != raw.get("sha256"):
        raise ConfigRejected("store_signature_invalid")
    approver = raw.get("approver_oid") or None
    return VersionRecord(
        version_id=int(raw["version_id"]),
        sha256=digest,
        created_at=str(raw.get("created_at") or ""),
        actor_oid=str(raw.get("actor_oid") or ""),
        approver_oid=str(approver) if approver else None,
        risk_flags=tuple(str(item) for item in raw.get("risk_flags") or []),
        summary=tuple(str(item) for item in raw.get("summary") or []),
        config=config,
    )


def _proposal_dict(proposal: Proposal) -> dict[str, Any]:
    return {
        "proposal_id": proposal.proposal_id,
        "proposer_oid": proposal.proposer_oid,
        "created_at": proposal.created_at,
        "base_version_id": proposal.base_version_id,
        "base_sha256": proposal.base_sha256,
        "config_sha256": proposal.config_sha256,
        "risk_flags": list(proposal.risk_flags),
        "summary": list(proposal.summary),
        "status": proposal.status,
        "config": proposal.config.model_dump(mode="json"),
        "approver_oid": proposal.approver_oid or "",
        "decided_at": proposal.decided_at or "",
        "applied_version_id": proposal.applied_version_id or 0,
    }


def _proposal_from(raw: dict[str, Any]) -> Proposal:
    config = parse_config(raw["config"])
    return Proposal(
        proposal_id=str(raw["proposal_id"]),
        proposer_oid=str(raw["proposer_oid"]),
        created_at=str(raw["created_at"]),
        base_version_id=int(raw["base_version_id"]),
        base_sha256=str(raw["base_sha256"]),
        config_sha256=str(raw["config_sha256"]),
        risk_flags=tuple(str(item) for item in raw.get("risk_flags") or []),
        summary=tuple(str(item) for item in raw.get("summary") or []),
        status=str(raw["status"]),
        config=config,
        approver_oid=str(raw["approver_oid"]) if raw.get("approver_oid") else None,
        decided_at=str(raw["decided_at"]) if raw.get("decided_at") else None,
        applied_version_id=int(raw["applied_version_id"]) if raw.get("applied_version_id") else None,
    )
