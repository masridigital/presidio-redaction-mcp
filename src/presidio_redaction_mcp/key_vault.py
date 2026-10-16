"""Anthropic API key from Azure Key Vault or a 0600 LoadCredential file.

The key is never read from the allowlist. A plaintext environment variable is
not accepted. Key Vault calls use the instance metadata service and reject any
host that is not ``*.vault.azure.net``.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

from presidio_redaction_mcp.config import Settings
from presidio_redaction_mcp.errors import ConfigError

_IMDS = "http://169.254.169.254/metadata/identity/oauth2/token"
_IMDS_QUERY = "api-version=2018-02-01&resource=https://vault.azure.net"
_API = "7.4"


class KeyVaultClient:
    def __init__(
        self,
        egress_check: Any,
        *,
        transport: httpx.BaseTransport | None = None,
        token_provider: Callable[[], str] | None = None,
    ) -> None:
        self._egress_check = egress_check
        self._token_provider = token_provider
        self._client = httpx.Client(transport=transport, timeout=httpx.Timeout(10.0), follow_redirects=False)

    def close(self) -> None:
        self._client.close()

    def get_secret(self, vault_url: str, name: str) -> str:
        self._egress_check(vault_url, purpose="key_vault")
        token = self._token()
        url = f"{vault_url.rstrip('/')}/secrets/{quote(name, safe='')}?api-version={_API}"
        self._egress_check(url, purpose="key_vault")
        try:
            response = self._client.get(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        except httpx.HTTPError as exc:
            raise ConfigError("key_vault_unreachable") from exc
        if response.status_code >= 400 or response.is_redirect:
            raise ConfigError("key_vault_http_error")
        try:
            payload = response.json()
        except (ValueError, UnicodeError) as exc:
            raise ConfigError("key_vault_malformed") from exc
        value = payload.get("value") if isinstance(payload, dict) else None
        if not isinstance(value, str) or not value.strip() or "replace-with" in value:
            raise ConfigError("anthropic_key_missing")
        return value.strip()

    def _token(self) -> str:
        if self._token_provider is not None:
            token = self._token_provider()
            if not token:
                raise ConfigError("key_vault_token_missing")
            return token
        try:
            response = self._client.get(
                f"{_IMDS}?{_IMDS_QUERY}",
                headers={"Metadata": "true"},
            )
        except httpx.HTTPError as exc:
            raise ConfigError("key_vault_unreachable") from exc
        if response.status_code >= 400 or response.is_redirect:
            raise ConfigError("key_vault_token_missing")
        try:
            payload = response.json()
        except ValueError as exc:
            raise ConfigError("key_vault_malformed") from exc
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise ConfigError("key_vault_token_missing")
        return token


def read_key_file(path: Path) -> str:
    if not path.is_file():
        raise ConfigError("anthropic_key_missing")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode not in {0o600, 0o400}:
        raise ConfigError("anthropic_key_file_mode")
    value = path.read_text(encoding="utf-8").strip()
    if not value or "replace-with" in value:
        raise ConfigError("anthropic_key_rejected")
    return value


def resolve_verifier_key(
    settings: Settings,
    *,
    transport: httpx.BaseTransport | None = None,
    token_provider: Callable[[], str] | None = None,
) -> str:
    """Load the key for an enabled verifier. Caller must already have passed the BAA guard."""
    file_override = os.environ.get("PRM_SECRET_FILE_ANTHROPIC_API_KEY")
    if file_override:
        return read_key_file(Path(file_override))
    spec = settings.allowlist.verifier
    vault_url = os.environ.get("PRM_KEY_VAULT_URL") or spec.key_vault_url
    secret_name = os.environ.get("PRM_KEY_VAULT_SECRET") or spec.key_vault_secret
    if not vault_url or not secret_name:
        raise ConfigError("anthropic_key_missing")
    client = KeyVaultClient(settings.egress.check, transport=transport, token_provider=token_provider)
    try:
        return client.get_secret(vault_url, secret_name)
    finally:
        client.close()
