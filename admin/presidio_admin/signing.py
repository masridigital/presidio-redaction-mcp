"""Asymmetric signatures for versions, proposals, and the admin audit.

The proxy verifies with a public key. It has no sign operation. A symmetric
HMAC for those documents would let the proxy forge a snapshot.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

from presidio_admin.errors import ConfigRejected

_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)


def canonical(payload: dict[str, Any]) -> bytes:
    body = {key: value for key, value in payload.items() if key != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_document(payload: dict[str, Any], signer: ConfigSigner) -> dict[str, Any]:
    body = {key: value for key, value in payload.items() if key != "signature"}
    body["signature"] = _signature_object(signer, canonical(body))
    return body


def signature_ok(payload: dict[str, Any], signer: ConfigSigner) -> bool:
    presented = payload.get("signature")
    if not isinstance(presented, dict) or presented.get("alg") != "PS256":
        return False
    kid = presented.get("kid")
    sig = presented.get("sig")
    if not isinstance(kid, str) or not isinstance(sig, str) or not kid or not sig:
        return False
    return signer.verify(canonical(payload), sig, kid)


class ConfigSigner:
    """Sign and verify. ``allow_sign`` is false for the proxy."""

    allow_sign = False
    key_id = ""

    def sign(self, message: bytes) -> str:
        raise ConfigRejected("sign_not_permitted")

    def verify(self, message: bytes, signature: str, key_id: str) -> bool:
        raise ConfigRejected("config_store_rejected")


class RsaConfigSigner(ConfigSigner):
    """Local RSA key for tests and a developer portal. Production uses Key Vault."""

    allow_sign = True

    def __init__(self, private_key: RSAPrivateKey, *, key_id: str = "local") -> None:
        self._private = private_key
        self._public = private_key.public_key()
        self.key_id = key_id

    @classmethod
    def from_pem(cls, pem: bytes, *, key_id: str = "local") -> RsaConfigSigner:
        if b"PRIVATE KEY" not in pem:
            raise ConfigRejected("sign_not_permitted")
        key = load_pem_private_key(pem, password=None)
        if not isinstance(key, RSAPrivateKey):
            raise ConfigRejected("sign_not_permitted")
        return cls(key, key_id=key_id)

    @classmethod
    def generate(cls, *, key_id: str = "local") -> RsaConfigSigner:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return cls(key, key_id=key_id)

    def sign(self, message: bytes) -> str:
        raw = self._private.sign(message, _PSS, hashes.SHA256())
        return _b64url(raw)

    def verify(self, message: bytes, signature: str, key_id: str) -> bool:
        if key_id != self.key_id:
            return False
        return _verify_rsa(self._public, message, signature)

    def public_verifier(self) -> VerifyOnlySigner:
        return VerifyOnlySigner({self.key_id: self._public})


class VerifyOnlySigner(ConfigSigner):
    """Public keys only. ``sign`` is refused."""

    allow_sign = False

    def __init__(self, public_keys: dict[str, RSAPublicKey]) -> None:
        if not public_keys:
            raise ConfigRejected("config_store_rejected")
        self._keys = dict(public_keys)
        self.key_id = next(iter(self._keys))

    @classmethod
    def from_pem(cls, pem: bytes, *, key_id: str = "local") -> VerifyOnlySigner:
        if b"PRIVATE KEY" in pem:
            raise ConfigRejected("sign_not_permitted")
        key = load_pem_public_key(pem)
        if not isinstance(key, RSAPublicKey):
            raise ConfigRejected("config_store_rejected")
        return cls({key_id: key})

    def sign(self, message: bytes) -> str:
        raise ConfigRejected("sign_not_permitted")

    def verify(self, message: bytes, signature: str, key_id: str) -> bool:
        public = self._keys.get(key_id)
        if public is None:
            return False
        return _verify_rsa(public, message, signature)


def _signature_object(signer: ConfigSigner, message: bytes) -> dict[str, str]:
    return {"alg": "PS256", "kid": signer.key_id, "sig": signer.sign(message)}


def _verify_rsa(public: RSAPublicKey, message: bytes, signature: str) -> bool:
    try:
        public.verify(_b64url_decode(signature), message, _PSS, hashes.SHA256())
    except Exception:
        return False
    return True


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def b64url_int(value: str) -> int:
    return int.from_bytes(_b64url_decode(value), "big")


def sha256_hex(message: bytes) -> str:
    return hashlib.sha256(message).hexdigest()
