"""Where version files live. Local disk for tests. Blob with a managed identity in Azure.

Container Apps cannot mount Azure Files with a managed identity. The portal
therefore uses a blob container and disables shared keys. See
``docs/best-practices-compliance.md``.
"""

from __future__ import annotations

import hashlib
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlparse

import httpx

from presidio_admin.errors import ConfigRejected

_BLOB_API = "2023-11-03"


@dataclass(frozen=True)
class ObjectBody:
    data: bytes
    etag: str


class LocalDocuments:
    """One directory. The lease file and content ETag stop a second writer."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, mode=0o700, exist_ok=True)

    def read(self, name: str) -> ObjectBody | None:
        path = self._path(name)
        if not path.is_file():
            return None
        data = path.read_bytes()
        return ObjectBody(data, hashlib.sha256(data).hexdigest())

    def write(self, name: str, data: bytes, *, if_match: str | None = None, create: bool = False) -> str:
        path = self._path(name)
        current = self.read(name)
        if create and current is not None:
            raise ConfigRejected("store_conflict")
        if if_match is not None and (current is None or current.etag != if_match):
            raise ConfigRejected("store_conflict")
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_bytes(data)
        temporary.chmod(0o600)
        os.replace(temporary, path)
        path.chmod(0o600)
        return hashlib.sha256(data).hexdigest()

    def append(self, name: str, data: bytes) -> None:
        """Add bytes. This does not replace a blob the immutability policy would reject."""
        if not data:
            raise ConfigRejected("config_store_rejected")
        path = self._path(name)
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        with path.open("ab") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(0o600)

    def names(self, prefix: str) -> list[str]:
        base = self.root / prefix
        if not base.exists():
            return []
        found = [str(path.relative_to(self.root)) for path in base.rglob("*") if path.is_file()]
        return sorted(found)

    @contextmanager
    def lease(self) -> Iterator[None]:
        path = self.root / "lease"
        self._clear_stale_lease(path)
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise ConfigRejected("store_lease_held") from exc
        try:
            os.write(fd, str(time.time()).encode("ascii"))
            os.close(fd)
            yield
        finally:
            path.unlink(missing_ok=True)

    def _path(self, name: str) -> Path:
        if name.startswith("/") or ".." in name.split("/"):
            raise ConfigRejected("published_config_rejected")
        return self.root / name

    @staticmethod
    def _clear_stale_lease(path: Path) -> None:
        if not path.exists():
            return
        age = time.time() - path.stat().st_mtime
        if age > 60:
            path.unlink(missing_ok=True)


class AzureBlobDocuments:
    """Block blobs. Authorization is a managed-identity bearer token, never an account key."""

    def __init__(self, container_url: str, *, token_provider: Any, client: httpx.Client | None = None) -> None:
        parsed = urlparse(container_url)
        if parsed.scheme != "https" or not parsed.netloc.endswith(".blob.core.windows.net"):
            raise ConfigRejected("config_store_rejected")
        if parsed.username or parsed.password or parsed.query:
            raise ConfigRejected("config_store_rejected")
        self.container_url = container_url.rstrip("/")
        self._token = token_provider
        self._client = client or httpx.Client(timeout=10)

    def read(self, name: str) -> ObjectBody | None:
        response = self._client.get(self._url(name), headers=self._headers())
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise ConfigRejected("config_store_rejected")
        etag = response.headers.get("etag", "").strip('"')
        if not etag:
            raise ConfigRejected("config_store_rejected")
        return ObjectBody(response.content, etag)

    def write(self, name: str, data: bytes, *, if_match: str | None = None, create: bool = False) -> str:
        headers = self._headers()
        headers["x-ms-blob-type"] = "BlockBlob"
        headers["Content-Type"] = "application/json"
        if create:
            headers["If-None-Match"] = "*"
        if if_match is not None:
            headers["If-Match"] = f'"{if_match}"'
        response = self._client.put(self._url(name), content=data, headers=headers)
        if response.status_code == 412:
            raise ConfigRejected("store_conflict")
        if response.status_code not in {201, 200}:
            raise ConfigRejected("config_store_rejected")
        etag = response.headers.get("etag", "").strip('"')
        if not etag:
            raise ConfigRejected("config_store_rejected")
        return etag

    def append(self, name: str, data: bytes) -> None:
        """Append block with the current length as a condition. A 412 is a conflict."""
        if not data:
            raise ConfigRejected("config_store_rejected")
        self._ensure_append_blob(name)
        current = self.read(name)
        offset = 0 if current is None else len(current.data)
        headers = self._headers()
        headers["Content-Type"] = "text/plain"
        headers["x-ms-blob-condition-appendpos"] = str(offset)
        response = self._client.put(self._url(name) + "?comp=appendblock", content=data, headers=headers)
        if response.status_code == 412:
            raise ConfigRejected("store_conflict")
        if response.status_code not in {201, 200}:
            raise ConfigRejected("config_store_rejected")

    def _ensure_append_blob(self, name: str) -> None:
        probe = self._client.get(self._url(name), headers=self._headers())
        if probe.status_code == 200:
            return
        if probe.status_code != 404:
            raise ConfigRejected("config_store_rejected")
        headers = self._headers()
        headers["x-ms-blob-type"] = "AppendBlob"
        headers["Content-Length"] = "0"
        created = self._client.put(self._url(name), headers=headers)
        if created.status_code not in {201, 200, 409}:
            raise ConfigRejected("config_store_rejected")

    def names(self, prefix: str) -> list[str]:
        response = self._client.get(
            self.container_url,
            params={"restype": "container", "comp": "list", "prefix": prefix},
            headers=self._headers(),
        )
        if response.status_code != 200:
            raise ConfigRejected("config_store_rejected")
        text = response.text
        found = []
        for part in text.split("<Name>")[1:]:
            name = part.split("</Name>", 1)[0]
            if name and ".." not in name.split("/"):
                found.append(name)
        return sorted(found)

    @contextmanager
    def lease(self) -> Iterator[None]:
        headers = self._headers()
        headers["x-ms-lease-action"] = "acquire"
        headers["x-ms-lease-duration"] = "60"
        response = self._client.put(self._url("writer.lock") + "?comp=lease", headers=headers)
        if response.status_code == 404:
            self.write("writer.lock", b"{}", create=True)
            response = self._client.put(self._url("writer.lock") + "?comp=lease", headers=headers)
        if response.status_code != 201:
            raise ConfigRejected("store_lease_held")
        lease_id = response.headers.get("x-ms-lease-id", "")
        if not lease_id:
            raise ConfigRejected("store_lease_held")
        try:
            yield
        finally:
            release = self._headers()
            release["x-ms-lease-action"] = "release"
            release["x-ms-lease-id"] = lease_id
            self._client.put(self._url("writer.lock") + "?comp=lease", headers=release)

    def _url(self, name: str) -> str:
        if name.startswith("/") or ".." in name.split("/"):
            raise ConfigRejected("published_config_rejected")
        return f"{self.container_url}/{name}"

    def _headers(self) -> dict[str, str]:
        token = self._token()
        if not isinstance(token, str) or token.count(".") < 2 or " " in token:
            raise ConfigRejected("identity_token_rejected")
        return {
            "Authorization": f"Bearer {token}",
            "x-ms-version": _BLOB_API,
            "x-ms-date": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime()),
        }


def imds_token(*, resource: str, client_id: str = "") -> str:
    """Managed-identity token from the instance metadata service.

    Omit ``client_id`` for a system-assigned identity. A user-assigned identity
    passes its client id. This never uses a storage account key.
    """
    params = {"api-version": "2018-02-01", "resource": resource}
    if client_id:
        params["client_id"] = client_id
    response = httpx.get(
        "http://169.254.169.254/metadata/identity/oauth2/token",
        params=params,
        headers={"Metadata": "true"},
        timeout=5,
    )
    if response.status_code != 200:
        raise ConfigRejected("identity_token_rejected")
    token = response.json().get("access_token")
    if not isinstance(token, str):
        raise ConfigRejected("identity_token_rejected")
    return token
