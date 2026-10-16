"""What the proxy calls. A missing, tampered, or unsigned document fails closed."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

from presidio_admin.documents import imds_token
from presidio_admin.errors import ConfigRejected
from presidio_admin.store import ConfigStore, VersionRecord


def load_for_proxy(
    store_dir: Path | str,
    *,
    store_key: bytes,
    audit_key: bytes,
    token_provider: Callable[[], str] | None = None,
) -> VersionRecord:
    if len(store_key) < 32 or len(audit_key) < 32:
        raise ConfigRejected("hmac_key_too_short")
    if store_key == audit_key:
        raise ConfigRejected("hmac_keys_must_differ")
    location = str(store_dir)
    if location.startswith("https://"):
        provider: Any = token_provider if token_provider is not None else _blob_token_provider()
        store = ConfigStore.open(location, store_key=store_key, audit_key=audit_key, token_provider=provider)
    else:
        if not (Path(location) / "active.json").is_file():
            raise ConfigRejected("published_config_missing")
        store = ConfigStore(Path(location), store_key=store_key, audit_key=audit_key)
    return store.verify_for_proxy()


def _blob_token_provider() -> Callable[[], str]:
    """System-assigned identity when no client id is set. User-assigned otherwise."""
    client_id = os.environ.get("PRM_STORE_MI_CLIENT_ID") or os.environ.get("PRM_ADMIN_MI_CLIENT_ID") or ""

    def provide() -> str:
        return imds_token(resource="https://storage.azure.com/", client_id=client_id)

    return provide
