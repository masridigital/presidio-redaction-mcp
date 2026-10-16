"""Load the admin portal's published config. Invalid stores fail closed.

The portal package owns the document. This module is the proxy's reader:
it refuses to start on a missing, tampered, or schema-invalid store, then
applies the published tool set, score threshold, and recognizer scores.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from pathlib import Path
from typing import Any

from presidio_redaction_mcp.config import Settings
from presidio_redaction_mcp.errors import ConfigError
from presidio_redaction_mcp.recognizers import DenyRule, PatternRule, RecognizerSet


def log_published(version_id: int | None, sha256: str) -> None:
    """Startup line. The same identity is also returned by ``/healthz``."""
    if version_id is None:
        return
    logging.getLogger("presidio_redaction_mcp").info(
        "published_config version_id=%s sha256=%s",
        version_id,
        sha256,
    )


def load_published_or_fail(
    store_dir: Path | str,
    *,
    verifier: Any,
    floor: Any = None,
    env: str | None = None,
) -> Any:
    """``env`` is ``Settings.env``. Pass it from the process that loaded settings."""
    try:
        from presidio_admin.errors import ConfigRejected
        from presidio_admin.proxy_loader import load_for_proxy

        return load_for_proxy(store_dir, verifier=verifier, floor=floor, env=env)
    except ConfigError:
        raise
    except ConfigRejected as exc:
        raise ConfigError(exc.reason_code) from exc
    except Exception as exc:
        raise ConfigError("published_config_rejected") from exc


def apply_published(settings: Settings, published: Any) -> Settings:
    """Narrow the running allowlist to the published document and enforce its controls."""
    try:
        document = published.config if hasattr(published, "config") else published
        state: dict[str, tuple[float, bool]] = document.pattern_state()
        yaml_names = {rule.name for rule in settings.recognizers.patterns}
        if set(state) != yaml_names:
            raise ConfigError("published_config_rejected")
        patterns: list[PatternRule] = []
        for rule in settings.recognizers.patterns:
            score, enabled = state[rule.name]
            if score < 0.75 or score > 1:
                raise ConfigError("published_config_rejected")
            if not enabled:
                continue
            patterns.append(replace(rule, score=score))
        recognizers = RecognizerSet(
            patterns=tuple(patterns),
            deny_lists=settings.recognizers.deny_lists,
            ad_hoc=_ad_hoc(patterns, settings.recognizers.deny_lists),
        )
        threshold = float(document.score_threshold)
        if threshold < 0.4 or threshold > 1:
            raise ConfigError("published_config_rejected")
        presidio = settings.allowlist.presidio.model_copy(update={"score_threshold": threshold})
        verifier = settings.allowlist.verifier.model_copy(update={"enabled": bool(document.claude_verifier_enabled)})
        allowlist = settings.allowlist.model_copy(update={"presidio": presidio, "verifier": verifier})
        from presidio_redaction_mcp.config import assert_verifier_permitted
        from presidio_redaction_mcp.entra import EntraClient

        draft = settings.model_copy(update={"allowlist": allowlist})
        assert_verifier_permitted(draft)
        entra_clients = settings.entra_clients
        baa_client_ids = settings.baa_client_ids
        enabled_clients = [client for client in document.clients if client.enabled]
        if enabled_clients or settings.auth_mode == "entra":
            if settings.auth_mode == "entra" and not enabled_clients:
                raise ConfigError("published_clients_missing")
            mapped = tuple(
                EntraClient(
                    name=client.display_name,
                    app_id=client.client_id,
                    phi_capable=client.app_role == "PHI",
                    human=client.app_role == "PHI",
                )
                for client in enabled_clients
            )
            entra_clients = mapped
            baa_client_ids = frozenset(client.app_id for client in mapped if client.phi_capable)
    except ConfigError:
        raise
    except Exception as exc:
        raise ConfigError("published_config_rejected") from exc
    return settings.model_copy(
        update={
            "allowlist": allowlist,
            "recognizers": recognizers,
            "entra_clients": entra_clients,
            "baa_client_ids": baa_client_ids,
            "published_version_id": getattr(published, "version_id", None),
            "published_sha256": str(getattr(published, "sha256", "")),
        }
    )


def _ad_hoc(patterns: list[PatternRule], deny_lists: tuple[DenyRule, ...]) -> tuple[dict[str, Any], ...]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for rule in patterns:
        grouped.setdefault(rule.entity, []).append(
            {"name": rule.name, "regex": rule.regex.pattern, "score": rule.score}
        )
    ad_hoc: list[dict[str, Any]] = []
    for entity, items in grouped.items():
        ad_hoc.append(
            {
                "name": f"published_{entity.lower()}",
                "supported_language": "en",
                "supported_entity": entity,
                "patterns": items,
            }
        )
    for rule in deny_lists:
        ad_hoc.append(
            {
                "name": f"deny_{rule.entity.lower()}",
                "supported_language": "en",
                "supported_entity": rule.entity,
                "deny_list": list(rule.terms),
            }
        )
    return tuple(ad_hoc)
