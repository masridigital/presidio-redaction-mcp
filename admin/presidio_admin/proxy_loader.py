"""What the proxy calls. A missing, tampered, or unsigned document fails closed.

The verifier must not be able to sign. After a good load the proxy advances
the version floor, which the store writer cannot lower.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

from presidio_admin.documents import imds_token
from presidio_admin.errors import ConfigRejected
from presidio_admin.floor import NullFloor
from presidio_admin.signing import ConfigSigner
from presidio_admin.store import ConfigStore, VersionRecord


def load_for_proxy(
    store_dir: Path | str,
    *,
    verifier: ConfigSigner,
    floor: Any = None,
    token_provider: Callable[[], str] | None = None,
) -> VersionRecord:
    if verifier.allow_sign:
        raise ConfigRejected("sign_not_permitted")
    mark = floor or NullFloor()
    location = str(store_dir)
    if location.startswith("https://"):
        provider: Any = token_provider if token_provider is not None else _blob_token_provider()
        store = ConfigStore.open(location, signer=verifier, token_provider=provider, floor=mark)
    else:
        if not (Path(location) / "active.json").is_file():
            raise ConfigRejected("published_config_missing")
        store = ConfigStore(Path(location), signer=verifier, floor=mark)
    record = store.verify_for_proxy()
    mark.advance(record.version_id, record.sha256)
    return record


def _blob_token_provider() -> Callable[[], str]:
    """System-assigned identity when no client id is set. User-assigned otherwise."""
    client_id = os.environ.get("PRM_STORE_MI_CLIENT_ID") or os.environ.get("PRM_ADMIN_MI_CLIENT_ID") or ""

    def provide() -> str:
        return imds_token(resource="https://storage.azure.com/", client_id=client_id)

    return provide
