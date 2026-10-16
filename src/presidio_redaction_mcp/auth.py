"""Per-caller bearer tokens bound to an ingress. Comparisons are constant-time."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from presidio_redaction_mcp.errors import AuthError


@dataclass(frozen=True)
class CallerIdentity:
    name: str
    phi_capable: bool
    ingress: str


@dataclass(frozen=True)
class CallerSecret:
    name: str
    phi_capable: bool
    allowed_ingress: frozenset[str]
    token_sha256: bytes
    cf_client_id_sha256: bytes | None = None
    cf_client_secret_sha256: bytes | None = None


def digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def _equals(presented: str, expected: bytes) -> bool:
    return hmac.compare_digest(digest(presented), expected)


def authenticate(
    callers: tuple[CallerSecret, ...],
    *,
    ingress: str,
    authorization: str | None,
    cf_client_id: str | None,
    cf_client_secret: str | None,
) -> CallerIdentity:
    presented = ""
    if authorization and authorization.lower().startswith("bearer "):
        presented = authorization[7:]
    matched: CallerSecret | None = None
    # Always walk every caller so a miss does not reveal which token matched.
    for caller in callers:
        if _equals(presented, caller.token_sha256) and presented != "":
            matched = caller
    if matched is None:
        raise AuthError("invalid_token")
    if ingress not in matched.allowed_ingress:
        raise AuthError("ingress_not_allowed")
    if ingress == "cloudflare":
        if matched.cf_client_id_sha256 is None or matched.cf_client_secret_sha256 is None:
            raise AuthError("cf_service_token_required")
        if not cf_client_id or not cf_client_secret:
            raise AuthError("cf_service_token_required")
        id_ok = _equals(cf_client_id, matched.cf_client_id_sha256)
        secret_ok = _equals(cf_client_secret, matched.cf_client_secret_sha256)
        if not (id_ok and secret_ok):
            raise AuthError("cf_service_token_required")
    return CallerIdentity(name=matched.name, phi_capable=matched.phi_capable, ingress=ingress)
