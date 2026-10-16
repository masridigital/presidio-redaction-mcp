from __future__ import annotations

import json
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from starlette.testclient import TestClient

from presidio_admin.app import Portal, create_app
from presidio_admin.approval import ChangeService
from presidio_admin.authz import TENANT_ID, EntraVerifier, issuer_for
from presidio_admin.schema import default_config
from presidio_admin.signing import RsaConfigSigner
from presidio_admin.store import ConfigStore

AUDIENCE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
PROPOSER = "11111111-1111-4111-8111-111111111111"
APPROVER = "22222222-2222-4222-8222-222222222222"


class Tokens:
    def __init__(self, private_key, verifier: EntraVerifier) -> None:
        self.private_key = private_key
        self.verifier = verifier

    def token(self, oid: str = PROPOSER, **overrides: object) -> str:
        now = int(time.time())
        claims: dict[str, object] = {
            "iss": issuer_for(TENANT_ID),
            "aud": AUDIENCE,
            "tid": TENANT_ID,
            "oid": oid,
            "roles": ["Admin"],
            "amr": ["mfa"],
            "acrs": ["c1"],
            "iat": now,
            "nbf": now,
            "exp": now + 600,
            "name": "Synthetic Admin",
        }
        claims.update(overrides)
        return jwt.encode(claims, self.private_key, algorithm="RS256", headers={"kid": "test-key"})

    def auth(self, oid: str = PROPOSER, **overrides: object) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token(oid, **overrides)}"}


@pytest.fixture
def hmac_key() -> bytes:
    return b"s" * 32


@pytest.fixture
def audit_key() -> bytes:
    return b"a" * 32


@pytest.fixture
def session_key() -> bytes:
    return b"e" * 32


@pytest.fixture
def signer() -> RsaConfigSigner:
    return RsaConfigSigner.generate(key_id="test-key")


@pytest.fixture
def store(tmp_path: Path, signer: RsaConfigSigner) -> ConfigStore:
    created = ConfigStore(tmp_path / "store", signer=signer)
    created.bootstrap(default_config())
    return created


@pytest.fixture
def changes(store: ConfigStore) -> ChangeService:
    return ChangeService(store)


@pytest.fixture
def tokens() -> Tokens:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk.update({"kid": "test-key", "alg": "RS256", "use": "sig"})
    verifier = EntraVerifier(jwks={"keys": [jwk]}, audience=AUDIENCE)
    return Tokens(private_key, verifier)


@pytest.fixture
def portal(store: ConfigStore, session_key: bytes, tokens: Tokens) -> Portal:
    return Portal(
        store=store,
        changes=ChangeService(store),
        verifier=tokens.verifier,
        session_key=session_key,
        cookie_secure=False,
    )


@pytest.fixture
def client(portal: Portal) -> TestClient:
    return TestClient(create_app(portal))
