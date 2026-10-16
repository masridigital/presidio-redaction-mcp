"""Microsoft Entra ID access tokens for the admin portal.

The portal accepts a v2 access token for the configured app registration only
when all of the following hold:

- ``tid`` is the Masri tenant
- ``roles`` contains the ``Admin`` app role
- ``amr`` contains ``mfa`` or ``ngcmfa`` (a password alone is not enough)
- ``acrs`` contains the Conditional Access authentication-context id

Conditional Access is what forces MFA. Checking ``amr`` and ``acrs`` is the
in-app confirmation that the policy ran. See ``docs/best-practices-compliance.md``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from typing import Any

import jwt
from jwt import PyJWK

from presidio_admin.errors import AuthzError

TENANT_ID = "f7812296-5bce-41dc-8102-b1b270e7c4c7"
ADMIN_ROLE = "Admin"
# ``mfa`` is the method reference Microsoft documents for multifactor.
# ``ngcmfa`` is the equivalent for some advanced credentials.
# ``wiaormfa`` is ambiguous (Windows integrated auth OR MFA) and is not accepted.
MFA_AMR = frozenset({"mfa", "ngcmfa"})
DEFAULT_ACRS = "c1"
MAX_TOKEN_SECONDS = 5400
SESSION_IDLE_SECONDS = 900
_GUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_DISPLAY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}$")


@dataclass(frozen=True)
class Principal:
    oid: str
    display_label: str
    tenant_id: str
    roles: tuple[str, ...]
    amr: tuple[str, ...]
    acrs: tuple[str, ...]
    expires_at: int
    upn_domain: str = ""


def issuer_for(tenant_id: str) -> str:
    return f"https://login.microsoftonline.com/{tenant_id}/v2.0"


def jwks_url(tenant_id: str) -> str:
    return f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"


def authorize_claims(
    claims: dict[str, Any],
    *,
    audience: str,
    tenant_id: str = TENANT_ID,
    required_acrs: str = DEFAULT_ACRS,
) -> Principal:
    if not isinstance(claims, dict):
        raise AuthzError("token_invalid")
    if claims.get("tid") != tenant_id:
        raise AuthzError("tenant_mismatch")
    aud = claims.get("aud")
    if isinstance(aud, list):
        aud_ok = audience in aud
    else:
        aud_ok = aud == audience
    if not aud_ok:
        raise AuthzError("audience_mismatch")
    if claims.get("iss") != issuer_for(tenant_id):
        raise AuthzError("issuer_mismatch")
    roles = claims.get("roles")
    if not isinstance(roles, list) or ADMIN_ROLE not in roles:
        raise AuthzError("admin_role_required")
    if any(not isinstance(role, str) for role in roles):
        raise AuthzError("admin_role_required")
    amr = claims.get("amr")
    if not isinstance(amr, list) or not (set(amr) & MFA_AMR):
        raise AuthzError("mfa_amr_required")
    acrs = claims.get("acrs")
    if not isinstance(acrs, list) or required_acrs not in acrs:
        raise AuthzError("acrs_required")
    oid = claims.get("oid")
    if not isinstance(oid, str) or _GUID.match(oid) is None:
        raise AuthzError("oid_required")
    try:
        issued = int(claims["iat"])
        expires = int(claims["exp"])
        not_before = int(claims["nbf"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthzError("token_invalid") from exc
    if expires <= issued or expires - issued > MAX_TOKEN_SECONDS:
        raise AuthzError("token_lifetime_exceeded")
    now = int(time.time())
    if not_before > now + 60:
        raise AuthzError("token_not_yet_valid")
    if expires <= now:
        raise AuthzError("token_expired")
    seen = claims.get("seen")
    if seen is not None:
        try:
            last_seen = int(seen)
        except (TypeError, ValueError) as exc:
            raise AuthzError("session_idle") from exc
        if now - last_seen > SESSION_IDLE_SECONDS:
            raise AuthzError("session_idle")
    return Principal(
        oid=oid.lower(),
        display_label=_label(claims.get("name")),
        tenant_id=tenant_id,
        roles=tuple(str(role) for role in roles),
        amr=tuple(str(item) for item in amr),
        acrs=tuple(str(item) for item in acrs),
        expires_at=expires,
        upn_domain=_upn_domain(claims),
    )


class EntraVerifier:
    """RS256 verification against a pinned JWKS. ``none`` and HMAC algs are rejected."""

    def __init__(
        self,
        *,
        jwks: dict[str, Any],
        audience: str,
        tenant_id: str = TENANT_ID,
        required_acrs: str = DEFAULT_ACRS,
    ) -> None:
        keys = jwks.get("keys") if isinstance(jwks, dict) else None
        if not audience or not isinstance(keys, list) or not keys:
            raise AuthzError("jwks_invalid")
        self._keys = {
            str(item.get("kid")): item
            for item in keys
            if isinstance(item, dict) and item.get("kid") and item.get("kty") == "RSA"
        }
        if not self._keys:
            raise AuthzError("jwks_invalid")
        self.audience = audience
        self.tenant_id = tenant_id
        self.required_acrs = required_acrs

    def verify(self, token: str | None) -> Principal:
        if not token or token.count(".") != 2:
            raise AuthzError("token_invalid")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise AuthzError("token_invalid") from exc
        if header.get("alg") != "RS256":
            raise AuthzError("token_invalid")
        jwk = self._keys.get(str(header.get("kid")))
        if not isinstance(jwk, dict):
            raise AuthzError("token_invalid")
        try:
            key = PyJWK.from_dict(jwk).key
            claims = jwt.decode(
                token,
                key=key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=issuer_for(self.tenant_id),
                leeway=60,
                options={"require": ["exp", "iat", "nbf", "iss", "aud"]},
            )
        except jwt.PyJWTError as exc:
            raise AuthzError("token_invalid") from exc
        return authorize_claims(
            claims,
            audience=self.audience,
            tenant_id=self.tenant_id,
            required_acrs=self.required_acrs,
        )


def seal_session(principal: Principal, csrf: str, key: bytes, *, audience: str, seen: int | None = None) -> str:
    now = int(time.time())
    issued = min(now, principal.expires_at - 60)
    payload = {
        "acrs": list(principal.acrs),
        "amr": list(principal.amr),
        "aud": audience,
        "csrf": csrf,
        "exp": principal.expires_at,
        "iat": issued,
        "iss": issuer_for(principal.tenant_id),
        "name": principal.display_label,
        "nbf": issued,
        "oid": principal.oid,
        "roles": list(principal.roles),
        "seen": now if seen is None else seen,
        "tid": principal.tenant_id,
        "upn_domain": principal.upn_domain,
    }
    return _sign(payload, key)


def touch_session(value: str | None, key: bytes) -> str | None:
    """Refresh the idle clock without rotating the CSRF token."""
    payload = _open(value, key)
    if payload is None:
        return None
    payload["seen"] = int(time.time())
    return _sign(payload, key)


def open_session(
    value: str | None,
    key: bytes,
    *,
    audience: str,
    tenant_id: str,
    required_acrs: str,
) -> tuple[Principal, str] | None:
    payload = _open(value, key)
    if payload is None:
        return None
    try:
        principal = authorize_claims(
            payload,
            audience=audience,
            tenant_id=tenant_id,
            required_acrs=required_acrs,
        )
    except AuthzError as exc:
        if exc.reason_code in {"session_idle", "token_not_yet_valid", "token_expired"}:
            raise
        return None
    csrf = payload.get("csrf")
    if not isinstance(csrf, str) or len(csrf) < 16:
        return None
    return principal, csrf


def authorize_redirect(
    *,
    tenant_id: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
) -> str:
    """Authorization-code URL. The client secret is never placed on this URL."""
    from urllib.parse import urlencode

    query = urlencode(
        {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "response_mode": "query",
            "scope": "openid profile",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize?{query}"


def _upn_domain(claims: dict[str, Any]) -> str:
    raw = claims.get("preferred_username") or claims.get("upn") or claims.get("upn_domain") or ""
    if not isinstance(raw, str) or "@" not in raw:
        if isinstance(raw, str) and re.fullmatch(r"[A-Za-z0-9.-]{1,80}", raw) and "." in raw:
            return raw.lower()
        return ""
    domain = raw.rsplit("@", 1)[1].lower()
    if re.fullmatch(r"[a-z0-9.-]{1,80}", domain) is None or "." not in domain:
        return ""
    return domain


def _label(name: object) -> str:
    if isinstance(name, str) and _DISPLAY.match(name) and "@" not in name:
        return name
    return "admin"


def _sign(payload: dict[str, Any], key: bytes) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    body = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    signature = hmac.new(key, body.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{body}.{signature}"


def _open(value: str | None, key: bytes) -> dict[str, Any] | None:
    if not value or value.count(".") != 1:
        return None
    body, signature = value.split(".", 1)
    expected = hmac.new(key, body.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return None
    padded = body + "=" * (-len(body) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    return payload
