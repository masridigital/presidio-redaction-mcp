"""Confidential-client authentication without a client secret.

Production uses the portal's user-assigned managed identity as a federated
credential. A certificate assertion is the other accepted credential. The
token request never sends ``client_secret``.
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
from collections.abc import Callable
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from presidio_admin.documents import imds_token
from presidio_admin.errors import AuthzError

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def assertion_from_env(*, client_id: str, tenant_id: str) -> Callable[[], str] | None:
    mode = os.environ.get("PRM_ADMIN_ASSERTION", "")
    if mode == "managed_identity":
        managed_client = os.environ.get("PRM_ADMIN_MI_CLIENT_ID", "")
        if not managed_client:
            return None

        def provide() -> str:
            return imds_token(resource="api://AzureADTokenExchange", client_id=managed_client)

        return provide
    if mode == "certificate":
        cert_path = os.environ.get("PRM_ADMIN_CLIENT_CERT_FILE", "")
        key_path = os.environ.get("PRM_ADMIN_CLIENT_KEY_FILE", "")
        if not cert_path or not key_path:
            return None
        return lambda: certificate_assertion(
            client_id=client_id,
            tenant_id=tenant_id,
            cert_pem=Path(cert_path).read_bytes(),
            key_pem=Path(key_path).read_bytes(),
        )
    return None


def certificate_assertion(*, client_id: str, tenant_id: str, cert_pem: bytes, key_pem: bytes) -> str:
    thumbprint = _x5t(cert_pem)
    now = int(time.time())
    claims = {
        "aud": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
        "iss": client_id,
        "sub": client_id,
        "jti": hashlib.sha256(os.urandom(16)).hexdigest(),
        "nbf": now,
        "iat": now,
        "exp": now + 300,
    }
    key = load_pem_private_key(key_pem, password=None)
    token = jwt.encode(claims, key, algorithm="RS256", headers={"x5t": thumbprint, "typ": "JWT"})
    if not isinstance(token, str):
        raise AuthzError("auth_not_configured")
    return token


def token_request_form(*, client_id: str, code: str, redirect_uri: str, code_verifier: str, assertion: str) -> dict[str, str]:
    form = {
        "client_id": client_id,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
        "client_assertion_type": ASSERTION_TYPE,
        "client_assertion": assertion,
    }
    if "client_secret" in form:
        raise AuthzError("auth_not_configured")
    return form


def _x5t(cert_pem: bytes) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    certificate = x509.load_pem_x509_certificate(cert_pem)
    digest = hashlib.sha1(certificate.public_bytes(Encoding.DER), usedforsecurity=False).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
