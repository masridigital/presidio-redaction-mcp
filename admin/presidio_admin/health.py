"""Process health and counters. Labels stay numeric so they cannot carry PHI."""

from __future__ import annotations

from dataclasses import dataclass

from presidio_admin.store import ConfigStore


@dataclass(frozen=True)
class Snapshot:
    config_valid: bool
    chain_valid: bool
    version_id: int
    sha256: str
    tools_enabled: int
    clients: int
    verifier_enabled: bool
    proposals_pending: int
    score_threshold: float


def snapshot(store: ConfigStore) -> Snapshot:
    try:
        active = store.read_active()
    except Exception:
        return Snapshot(False, False, 0, "", 0, 0, False, 0, 0.0)
    pending = sum(1 for item in store.list_proposals() if item.status == "pending")
    return Snapshot(
        config_valid=True,
        chain_valid=store.audit.verify(),
        version_id=active.version_id,
        sha256=active.sha256,
        tools_enabled=len(active.config.enabled_tools()),
        clients=len(active.config.clients),
        verifier_enabled=active.config.claude_verifier_enabled,
        proposals_pending=pending,
        score_threshold=active.config.score_threshold,
    )


def render_metrics(item: Snapshot) -> str:
    lines = [
        "# HELP prm_admin_up Portal config loaded and the audit chain verifies.",
        "# TYPE prm_admin_up gauge",
        f"prm_admin_up {1 if item.config_valid and item.chain_valid else 0}",
        "# HELP prm_admin_config_version Published config version.",
        "# TYPE prm_admin_config_version gauge",
        f"prm_admin_config_version {item.version_id}",
        "# HELP prm_admin_chain_valid HMAC audit chain verification.",
        "# TYPE prm_admin_chain_valid gauge",
        f"prm_admin_chain_valid {1 if item.chain_valid else 0}",
        "# HELP prm_admin_tools_enabled Tools currently allowlisted.",
        "# TYPE prm_admin_tools_enabled gauge",
        f"prm_admin_tools_enabled {item.tools_enabled}",
        "# HELP prm_admin_clients Registered Entra clients.",
        "# TYPE prm_admin_clients gauge",
        f"prm_admin_clients {item.clients}",
        "# HELP prm_admin_verifier_enabled Claude verifier switch.",
        "# TYPE prm_admin_verifier_enabled gauge",
        f"prm_admin_verifier_enabled {1 if item.verifier_enabled else 0}",
        "# HELP prm_admin_proposals_pending Changes waiting for a second admin.",
        "# TYPE prm_admin_proposals_pending gauge",
        f"prm_admin_proposals_pending {item.proposals_pending}",
        "# HELP prm_admin_score_threshold Presidio minimum entity score.",
        "# TYPE prm_admin_score_threshold gauge",
        f"prm_admin_score_threshold {item.score_threshold}",
        "",
    ]
    return "\n".join(lines)
