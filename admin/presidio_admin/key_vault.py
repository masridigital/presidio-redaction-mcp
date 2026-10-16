"""Key Vault sign for the portal, and verify-only for the proxy.

The signing key is generated in Key Vault. It is not a deployment parameter.
The session HMAC is created in the vault on first start. Production refuses
a session key passed in the environment.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path
from typing import Any, Callable

import httpx
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric import rsa

from presidio_admin.documents import imds_token
from presidio_admin.errors import ConfigRejected
from presidio_admin.signing import (
    ConfigSigner,
    RsaConfigSigner,
    VerifyOnlySigner,
    _b64url,
    _verify_rsa,
    b64url_int,
)

_API = "7.4"
SESSION_SECRET_NAME = "session-hmac-key"


class KeyVaultSigner(ConfigSigner):
    """Sign via the Key Vault REST API. Verify with the public key only."""

    def __init__(
        self,
        key_url: str,
        token_provider: Callable[[], str],
        *,
        allow_sign: bool,
        client: httpx.Client | None = None,
    ) -> None:
        if not key_url.startswith("https://") or "/keys/" not in key_url:
            raise ConfigRejected("config_store_rejected")
        if any(token in key_url for token in ("@", "?", "PRIVATE")):
            raise ConfigRejected("config_store_rejected")
        self.key_url = key_url.rstrip("/")
        self.allow_sign = allow_sign
        self._token = token_provider
        self._client = client or httpx.Client(timeout=10)
        self._keys: dict[str, RSAPublicKey] = {}
        self.key_id = ""
        self.refresh()

    def refresh(self) -> None:
        headers = self._headers()
        listed = self._client.get(f"{self.key_url}/versions", params={"api-version": _API}, headers=headers)
        if listed.status_code != 200:
            raise ConfigRejected("config_store_rejected")
        versions = listed.json().get("value")
        if not isinstance(versions, list) or not versions:
            raise ConfigRejected("config_store_rejected")
        keys: dict[str, RSAPublicKey] = {}
        latest_kid = ""
        latest_created = -1
        for item in versions:
            if not isinstance(item, dict):
                continue
            attributes = item.get("attributes") if isinstance(item.get("attributes"), dict) else {}
            if attributes.get("enabled") is False:
                continue
            kid = item.get("kid")
            if not isinstance(kid, str) or not kid.startswith(self.key_url):
                continue
            material = self._client.get(kid, params={"api-version": _API}, headers=headers)
            if material.status_code != 200:
                raise ConfigRejected("config_store_rejected")
            public = _public_key(material.json())
            keys[kid] = public
            created = int(attributes.get("created") or 0)
            if created >= latest_created:
                latest_created = created
                latest_kid = kid
        if not keys or not latest_kid:
            raise ConfigRejected("config_store_rejected")
        self._keys = keys
        self.key_id = latest_kid

    def sign(self, message: bytes) -> str:
        if not self.allow_sign:
            raise ConfigRejected("sign_not_permitted")
        digest = hashlib.sha256(message).digest()
        response = self._client.post(
            f"{self.key_url}/sign",
            params={"api-version": _API},
            headers={**self._headers(), "Content-Type": "application/json"},
            json={"alg": "PS256", "value": _b64url(digest)},
        )
        if response.status_code != 200:
            raise ConfigRejected("config_store_rejected")
        body = response.json()
        kid = body.get("kid")
        value = body.get("value")
        if not isinstance(kid, str) or not isinstance(value, str):
            raise ConfigRejected("config_store_rejected")
        self.key_id = kid
        return value

    def verify(self, message: bytes, signature: str, key_id: str) -> bool:
        public = self._keys.get(key_id)
        if public is None:
            return False
        return _verify_rsa(public, message, signature)

    def _headers(self) -> dict[str, str]:
        token = self._token()
        if not isinstance(token, str) or token.count(".") < 2 or " " in token:
            raise ConfigRejected("identity_token_rejected")
        return {"Authorization": f"Bearer {token}"}


def signer_from_env(*, allow_sign: bool, token_provider: Callable[[], str] | None = None) -> ConfigSigner:
    """Production loads the vault key. A private key on the proxy is refused."""
    if os.environ.get("PRM_STORE_HMAC_KEY") or os.environ.get("PRM_ADMIN_AUDIT_HMAC_KEY"):
        raise SystemExit(1)
    if not allow_sign and os.environ.get("PRM_SIGNING_KEY_FILE"):
        raise SystemExit(1)
    production = os.environ.get("PRM_ENV") == "production"
    if production and os.environ.get("PRM_SIGNING_KEY_FILE"):
        raise SystemExit(1)
    key_url = os.environ.get("PRM_SIGNING_KEY_URL", "")
    if key_url:
        provider = token_provider or _vault_token
        return KeyVaultSigner(key_url, provider, allow_sign=allow_sign)
    if production:
        raise SystemExit(1)
    if allow_sign:
        path = os.environ.get("PRM_SIGNING_KEY_FILE", "")
        if not path:
            raise SystemExit(1)
        return RsaConfigSigner.from_pem(Path(path).read_bytes())
    path = os.environ.get("PRM_SIGNING_PUBLIC_KEY_FILE", "")
    if not path:
        raise SystemExit(1)
    return VerifyOnlySigner.from_pem(Path(path).read_bytes())


def load_session_key(
    *,
    token_provider: Callable[[], str] | None = None,
    client: httpx.Client | None = None,
) -> bytes:
    if os.environ.get("PRM_STORE_HMAC_KEY") or os.environ.get("PRM_ADMIN_AUDIT_HMAC_KEY"):
        raise SystemExit(1)
    if os.environ.get("PRM_ENV") == "production":
        if os.environ.get("PRM_ADMIN_SESSION_HMAC_KEY"):
            raise SystemExit(1)
        vault = os.environ.get("PRM_KEY_VAULT_URL", "")
        if not vault:
            raise SystemExit(1)
        return session_key_from_vault(vault, token_provider or _vault_token, client)
    file_path = os.environ.get("PRM_ADMIN_SESSION_HMAC_KEY_FILE")
    if file_path:
        raw = Path(file_path).read_bytes().strip()
    else:
        raw = os.environ.get("PRM_ADMIN_SESSION_HMAC_KEY", "").encode("utf-8")
    if len(raw) < 32 or raw.startswith(b"replace-with"):
        raise SystemExit(1)
    return raw


def session_key_from_vault(vault_url: str, token_provider: Callable[[], str], client: httpx.Client | None = None) -> bytes:
    if not vault_url.startswith("https://") or "/secrets/" in vault_url or "@" in vault_url:
        raise ConfigRejected("session_key_rejected")
    http = client or httpx.Client(timeout=10)
    headers = {"Authorization": f"Bearer {token_provider()}"}
    url = vault_url.rstrip("/") + f"/secrets/{SESSION_SECRET_NAME}"
    response = http.get(url, params={"api-version": _API}, headers=headers)
    if response.status_code == 404:
        raw = secrets.token_urlsafe(32)
        created = http.put(
            url,
            params={"api-version": _API},
            headers={**headers, "Content-Type": "application/json"},
            json={"value": raw},
        )
        if created.status_code not in {200, 201}:
            raise ConfigRejected("session_key_rejected")
        return raw.encode("utf-8")
    if response.status_code != 200:
        raise ConfigRejected("session_key_rejected")
    value = response.json().get("value")
    if not isinstance(value, str) or len(value.encode("utf-8")) < 32 or value.startswith("replace-with"):
        raise ConfigRejected("session_key_rejected")
    return value.encode("utf-8")


def _vault_token() -> str:
    client_id = os.environ.get("PRM_ADMIN_MI_CLIENT_ID") or os.environ.get("PRM_STORE_MI_CLIENT_ID") or ""
    return imds_token(resource="https://vault.azure.net", client_id=client_id)


def _public_key(payload: dict[str, Any]) -> RSAPublicKey:
    key = payload.get("key") if isinstance(payload, dict) else None
    if not isinstance(key, dict) or key.get("kty") != "RSA":
        raise ConfigRejected("config_store_rejected")
    n = key.get("n")
    e = key.get("e")
    if not isinstance(n, str) or not isinstance(e, str):
        raise ConfigRejected("config_store_rejected")
    numbers = rsa.RSAPublicNumbers(b64url_int(e), b64url_int(n))
    return numbers.public_key()
