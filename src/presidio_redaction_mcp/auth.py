"""Lab bearer tokens, and Entra JWTs on the private Azure ingress.

Cloudflare Access JWTs are not accepted. API Management headers are not identity.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from presidio_redaction_mcp.entra import EntraTokenVerifier
from presidio_redaction_mcp.errors import AuthError


@dataclass(frozen=True)
class CallerIdentity:
    name: str
    phi_capable: bool
    ingress: str
    authn: str = "bearer"
    client_id: str | None = None


@dataclass(frozen=True)
class CallerSecret:
    name: str
    phi_capable: bool
    allowed_ingress: frozenset[str]
    token_sha256: bytes


def digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def _equals(presented: str, expected: bytes) -> bool:
    return hmac.compare_digest(digest(presented), expected)


def _bearer(authorization: str | None) -> str:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def authenticate(
    callers: tuple[CallerSecret, ...],
    *,
    ingress: str,
    authorization: str | None,
    entra: EntraTokenVerifier | None = None,
) -> CallerIdentity:
    if ingress == "private":
        if entra is None:
            raise AuthError("entra_required")
        principal = entra.verify(_bearer(authorization))
        return CallerIdentity(
            name=principal.name,
            phi_capable=principal.phi_capable,
            ingress="private",
            authn="entra",
            client_id=principal.app_id,
        )
    presented = _bearer(authorization)
    matched: CallerSecret | None = None
    for caller in callers:
        if presented and _equals(presented, caller.token_sha256):
            matched = caller
    if matched is None:
        raise AuthError("invalid_token")
    if ingress not in matched.allowed_ingress:
        raise AuthError("ingress_not_allowed")
    # Lab bearer is the VPN listener only. external-nonphi is a policy mark, not a door.
    if ingress != "vpn":
        raise AuthError("ingress_not_allowed")
    return CallerIdentity(
        name=matched.name,
        phi_capable=matched.phi_capable,
        ingress=ingress,
        authn="bearer",
    )
