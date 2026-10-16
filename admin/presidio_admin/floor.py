"""High-water mark for the published version.

The mark lives outside the config store. The identity that writes versions
cannot lower it. Blob versioning keeps the old bytes. This floor stops the
proxy from loading a signed older snapshot after a higher version was seen.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlparse

import httpx

from presidio_admin.errors import ConfigRejected

_BLOB_API = "2023-11-03"
_FLOOR_BLOB = "floor.jsonl"


class NullFloor:
    def present(self) -> bool:
        return False

    def high_water(self) -> int:
        return 0

    def advance(self, version_id: int, sha256: str) -> None:
        del version_id, sha256


class LocalVersionFloor:
    """Append-only file. A line that decreases the mark fails closed."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def present(self) -> bool:
        return self.path.is_file()

    def high_water(self) -> int:
        if not self.path.is_file():
            return 0
        return _highest(self.path.read_text(encoding="utf-8"))

    def advance(self, version_id: int, sha256: str) -> None:
        current = self.high_water()
        if version_id < current:
            raise ConfigRejected("snapshot_replay")
        if version_id == current:
            return
        if len(sha256) != 64:
            raise ConfigRejected("version_floor_rejected")
        self.path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        line = json.dumps({"sha256": sha256, "version_id": version_id}, separators=(",", ":"))
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        self.path.chmod(0o600)


class BlobVersionFloor:
    """Append blob. Shared-key auth is not used. The config container is a different URL."""

    def __init__(self, container_url: str, *, token_provider: object, client: httpx.Client | None = None) -> None:
        parsed = urlparse(container_url)
        if parsed.scheme != "https" or not parsed.netloc.endswith(".blob.core.windows.net"):
            raise ConfigRejected("version_floor_rejected")
        if parsed.username or parsed.password or parsed.query or parsed.path.strip("/").count("/") != 0:
            raise ConfigRejected("version_floor_rejected")
        if not parsed.path.strip("/"):
            raise ConfigRejected("version_floor_rejected")
        self.container_url = container_url.rstrip("/")
        self._token = token_provider
        self._client = client or httpx.Client(timeout=10)

    def present(self) -> bool:
        _current, _offset, exists = self._snapshot()
        return exists

    def high_water(self) -> int:
        current, _offset, exists = self._snapshot()
        if not exists:
            return 0
        return current

    def advance(self, version_id: int, sha256: str) -> None:
        """Append at the current length. A replica that lost the race retries."""
        if len(sha256) != 64:
            raise ConfigRejected("version_floor_rejected")
        line = json.dumps({"sha256": sha256, "version_id": version_id}, separators=(",", ":")) + "\n"
        for _attempt in range(5):
            current, offset, exists = self._snapshot()
            if exists and version_id < current:
                raise ConfigRejected("snapshot_replay")
            if exists and version_id == current:
                return
            if not exists:
                self._ensure_append_blob()
                continue
            headers = self._headers()
            headers["Content-Type"] = "text/plain"
            headers["x-ms-blob-condition-appendpos"] = str(offset)
            response = self._client.put(
                self._blob_url() + "?comp=appendblock",
                content=line.encode("utf-8"),
                headers=headers,
            )
            if response.status_code in {201, 200}:
                return
            if response.status_code == 412:
                continue
            raise ConfigRejected("version_floor_rejected")
        raise ConfigRejected("version_floor_rejected")

    def _snapshot(self) -> tuple[int, int, bool]:
        response = self._client.get(self._blob_url(), headers=self._headers())
        if response.status_code == 404:
            return 0, 0, False
        if response.status_code != 200:
            raise ConfigRejected("version_floor_rejected")
        return _highest(response.text), len(response.content), True

    def _ensure_append_blob(self) -> None:
        probe = self._client.get(self._blob_url(), headers=self._headers())
        if probe.status_code == 200:
            return
        if probe.status_code != 404:
            raise ConfigRejected("version_floor_rejected")
        headers = self._headers()
        headers["x-ms-blob-type"] = "AppendBlob"
        headers["Content-Length"] = "0"
        created = self._client.put(self._blob_url(), headers=headers)
        if created.status_code not in {201, 200, 409}:
            raise ConfigRejected("version_floor_rejected")

    def _blob_url(self) -> str:
        return f"{self.container_url}/{_FLOOR_BLOB}"

    def _headers(self) -> dict[str, str]:
        import time

        token = self._token() if callable(self._token) else self._token
        if not isinstance(token, str) or token.count(".") < 2 or " " in token:
            raise ConfigRejected("identity_token_rejected")
        return {
            "Authorization": f"Bearer {token}",
            "x-ms-version": _BLOB_API,
            "x-ms-date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
        }


def floor_separated(store_location: str, floor: object) -> None:
    """The floor must not be a path or container the store writer controls."""
    if isinstance(floor, NullFloor) or floor is None:
        return
    if isinstance(floor, LocalVersionFloor):
        if store_location.startswith("https://"):
            return
        root = Path(store_location).resolve()
        path = floor.path.resolve()
        if path == root or root in path.parents:
            raise ConfigRejected("version_floor_inside_store")
        return
    if isinstance(floor, BlobVersionFloor):
        if store_location.rstrip("/") == floor.container_url:
            raise ConfigRejected("version_floor_inside_store")
        return
    raise ConfigRejected("version_floor_rejected")


def _highest(text: str) -> int:
    highest = 0
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
            version_id = int(row["version_id"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ConfigRejected("version_floor_rejected") from exc
        if version_id < highest:
            raise ConfigRejected("snapshot_replay")
        highest = version_id
    return highest
