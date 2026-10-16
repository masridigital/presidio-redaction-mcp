"""Entra ID access-token checks for the Azure container.

API Management may validate the same token. This process validates it again.
Caller identity comes only from the verified JWT. Gateway headers are not read.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import jwt
from jwt import PyJWK

from presidio_redaction_mcp.errors import AuthError

PINNED_TENANT_ID = "f7812296-5bce-41dc-8102-b1b270e7c4c7"
SCOPE = "access_as_user"
PHI_ROLE = "Phi.Caller"
NONPHI_ROLE = "NonPhi.Caller"
_REJECTED_TENANTS = frozenset({"common", "organizations", "consumers"})


def pinned_issuer(tenant_id: str = PINNED_TENANT_ID) -> str:
    return f"https://login.microsoftonline.com/{tenant_id}/v2.0"


@dataclass(frozen=True)
class EntraClient:
    name: str
    app_id: str
    phi_capable: bool
    human: bool


@dataclass(frozen=True)
class EntraPrincipal:
    name: str
    phi_capable: bool
    app_id: str
    human: bool


class EntraTokenVerifier:
    def __init__(
        self,
        *,
        audience: str,
        clients: tuple[EntraClient, ...],
        jwks_fetcher: Callable[[], dict[str, Any]],
        tenant_id: str = PINNED_TENANT_ID,
        cache_ttl_seconds: int = 3600,
        now: Callable[[], float] | None = None,
    ) -> None:
        if tenant_id.lower() in _REJECTED_TENANTS or tenant_id.lower() != PINNED_TENANT_ID:
            raise AuthError("entra_tenant_unpinned")
        if not audience or "common" in audience.lower() or "organizations" in audience.lower():
            raise AuthError("entra_audience_invalid")
        if len({client.app_id.lower() for client in clients}) != len(clients) or not clients:
            raise AuthError("entra_clients_invalid")
        self.audience = audience
        self.tenant_id = PINNED_TENANT_ID
        self.issuer = pinned_issuer(self.tenant_id)
        self._clients = {client.app_id.lower(): client for client in clients}
        self._fetcher = jwks_fetcher
        self._ttl = cache_ttl_seconds
        self._now = now or time.monotonic
        self._cache: dict[str, Any] | None = None
        self._cache_until = 0.0
        # Unknown-kid refreshes are limited to one per cache TTL. A later
        # successful lookup does not clear this deadline.
        self._miss_refresh_not_before = 0.0

    def verify(self, token: str | None) -> EntraPrincipal:
        if not token or token.count(".") != 2:
            raise AuthError("invalid_token")
        header = _header(token)
        if header.get("alg") != "RS256" or not header.get("kid"):
            raise AuthError("invalid_token")
        key = self._key_for(str(header["kid"]))
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "nbf", "iss", "aud"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthError("token_expired") from exc
        except jwt.ImmatureSignatureError as exc:
            raise AuthError("token_not_yet_valid") from exc
        except jwt.InvalidAudienceError as exc:
            raise AuthError("audience_mismatch") from exc
        except jwt.InvalidIssuerError as exc:
            raise AuthError("issuer_mismatch") from exc
        except jwt.PyJWTError as exc:
            raise AuthError("invalid_token") from exc
        self._reject_unpinned_issuer(claims)
        if claims.get("ver") != "2.0":
            raise AuthError("token_version_rejected")
        if claims.get("aud") != self.audience:
            raise AuthError("audience_mismatch")
        if str(claims.get("tid", "")).lower() != self.tenant_id:
            raise AuthError("tenant_mismatch")
        client = self._client(claims)
        phi_capable = _role(claims, client)
        if client.human:
            _require_delegated(claims)
        else:
            _require_workload(claims)
            if phi_capable:
                raise AuthError("phi_role_on_machine_client")
        return EntraPrincipal(
            name=client.name,
            phi_capable=phi_capable,
            app_id=client.app_id,
            human=client.human,
        )

    def _reject_unpinned_issuer(self, claims: dict[str, Any]) -> None:
        issuer = str(claims.get("iss", "")).lower().rstrip("/")
        if issuer != self.issuer.lower():
            raise AuthError("issuer_mismatch")
        if any(part in issuer for part in ("/common", "/organizations", "/consumers")):
            raise AuthError("issuer_mismatch")
        if "sts.windows.net" in issuer:
            raise AuthError("token_version_rejected")

    def _client(self, claims: dict[str, Any]) -> EntraClient:
        azp = claims.get("azp")
        appid = claims.get("appid")
        if azp is not None and not isinstance(azp, str):
            raise AuthError("unknown_client")
        if appid is not None and not isinstance(appid, str):
            raise AuthError("unknown_client")
        if azp and appid and azp.lower() != appid.lower():
            raise AuthError("unknown_client")
        presented = (azp or appid or "").lower()
        client = self._clients.get(presented)
        if client is None:
            raise AuthError("unknown_client")
        return client

    def _key_for(self, kid: str) -> Any:
        """Use the cached JWKS. On an unknown kid, refresh once, then wait out the TTL."""
        try:
            return _signing_key(self._jwks(), kid)
        except AuthError as exc:
            if exc.reason_code != "jwks_key_missing":
                raise
            now = self._now()
            if now < self._miss_refresh_not_before:
                raise
            self._miss_refresh_not_before = now + self._ttl
            self._cache = None
            self._cache_until = 0.0
            return _signing_key(self._jwks(force=True), kid)

    def _jwks(self, *, force: bool = False) -> dict[str, Any]:
        now = self._now()
        if not force and self._cache is not None and now < self._cache_until:
            return self._cache
        try:
            payload = self._fetcher()
        except AuthError:
            self._cache = None
            raise
        except Exception as exc:
            self._cache = None
            raise AuthError("jwks_fetch_failed") from exc
        if not isinstance(payload, dict) or not payload.get("keys"):
            self._cache = None
            raise AuthError("jwks_fetch_failed")
        self._cache = payload
        self._cache_until = now + self._ttl
        return payload


def protected_resource_metadata(*, resource: str) -> dict[str, Any]:
    return {
        "resource": resource,
        "authorization_servers": [pinned_issuer()],
        "scopes_supported": [SCOPE],
        "bearer_methods_supported": ["header"],
    }


def _header(token: str) -> dict[str, Any]:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise AuthError("invalid_token") from exc
    if not isinstance(header, dict):
        raise AuthError("invalid_token")
    return header


def _signing_key(jwks: dict[str, Any], kid: str) -> Any:
    keys = jwks.get("keys")
    if not isinstance(keys, list):
        raise AuthError("jwks_fetch_failed")
    for item in keys:
        if isinstance(item, dict) and item.get("kid") == kid:
            try:
                return PyJWK.from_dict(item).key
            except jwt.PyJWTError as exc:
                raise AuthError("invalid_token") from exc
    raise AuthError("jwks_key_missing")


def _role(claims: dict[str, Any], client: EntraClient) -> bool:
    roles = claims.get("roles")
    if not isinstance(roles, list):
        raise AuthError("role_missing")
    phi = PHI_ROLE in roles
    nonphi = NONPHI_ROLE in roles
    if phi and nonphi:
        raise AuthError("role_conflict")
    if not phi and not nonphi:
        raise AuthError("role_missing")
    if phi and not client.phi_capable:
        raise AuthError("role_client_mismatch")
    return bool(phi and client.phi_capable)


def _require_delegated(claims: dict[str, Any]) -> None:
    if claims.get("idtyp") == "app":
        raise AuthError("machine_token_not_allowed")
    scp = claims.get("scp")
    if not isinstance(scp, str) or SCOPE not in scp.split():
        raise AuthError("scope_missing")
    if not _mfa(claims):
        raise AuthError("mfa_required")


def _require_workload(claims: dict[str, Any]) -> None:
    if claims.get("scp"):
        raise AuthError("workload_identity_required")
    if claims.get("idtyp") not in {None, "app"}:
        raise AuthError("workload_identity_required")


def _mfa(claims: dict[str, Any]) -> bool:
    amr = _str_list(claims.get("amr"))
    acrs = _str_list(claims.get("acrs"))
    if "mfa" in amr:
        return True
    return bool(set(acrs) & {"c1", "mfa"})


def _str_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return []
