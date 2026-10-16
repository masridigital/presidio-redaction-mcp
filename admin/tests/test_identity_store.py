"""Blob access uses a bearer token. The admin client sends an assertion, not a secret."""

from __future__ import annotations

import hashlib
import json

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils

from presidio_admin.client_auth import ASSERTION_TYPE, token_request_form
from presidio_admin.documents import AzureBlobDocuments
from presidio_admin.errors import ConfigRejected
from presidio_admin.floor import BlobVersionFloor, floor_separated
from presidio_admin.key_vault import KeyVaultSigner, session_key_from_vault
from presidio_admin.signing import RsaConfigSigner, _b64url, _b64url_decode


def test_token_form_carries_an_assertion() -> None:
    form = token_request_form(
        client_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        code="synthetic-code",
        redirect_uri="https://admin.internal/auth/callback",
        code_verifier="synthetic-verifier-value",
        assertion="header.payload.signature",
    )
    assert "client_secret" not in form
    assert form["client_assertion"] == "header.payload.signature"
    assert form["client_assertion_type"] == ASSERTION_TYPE


def test_blob_client_sends_a_bearer_token() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["Authorization"])
        assert "SharedKey" not in request.headers["Authorization"]
        assert request.headers["x-ms-version"]
        if request.method == "GET":
            return httpx.Response(404)
        return httpx.Response(201, headers={"etag": '"abc"'})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    documents = AzureBlobDocuments(
        "https://prm.blob.core.windows.net/prm-config",
        token_provider=lambda: "header.payload.signature",
        client=client,
    )
    assert documents.read("active.json") is None
    documents.write("active.json", b"{}", create=True)
    assert seen[0] == "Bearer header.payload.signature"
    assert seen[1].startswith("Bearer ")
    with pytest.raises(ConfigRejected) as caught:
        AzureBlobDocuments(
            "https://name:account-key@prm.blob.core.windows.net/prm-config",
            token_provider=lambda: "header.payload.signature",
        )
    assert caught.value.reason_code == "config_store_rejected"


def _jwk(signer: RsaConfigSigner) -> dict[str, str]:
    numbers = signer._public.public_numbers()

    def enc(value: int) -> str:
        length = (value.bit_length() + 7) // 8
        return _b64url(value.to_bytes(length, "big"))

    return {"kty": "RSA", "n": enc(numbers.n), "e": enc(numbers.e)}


def test_key_vault_signs_and_a_verify_only_caller_does_not() -> None:
    signer = RsaConfigSigner.generate(key_id="vault")
    key_url = "https://example.vault.azure.net/keys/prm-config-signing"
    kid = key_url + "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    posted: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer aaa.bbb.ccc"
        assert "SharedKey" not in request.headers["Authorization"]
        if request.url.path.endswith("/versions"):
            return httpx.Response(
                200,
                json={"value": [{"kid": kid, "attributes": {"enabled": True, "created": 10}}]},
            )
        if request.method == "GET":
            return httpx.Response(200, json={"key": _jwk(signer)})
        body = json.loads(request.content)
        posted.append(body)
        digest = _b64url_decode(body["value"])
        signature = signer._private.sign(
            digest,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH),
            utils.Prehashed(hashes.SHA256()),
        )
        return httpx.Response(200, json={"kid": kid, "value": _b64url(signature)})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    portal = KeyVaultSigner(key_url, lambda: "aaa.bbb.ccc", allow_sign=True, client=client)
    message = b'{"version_id":2}'
    signature = portal.sign(message)
    assert posted[0]["alg"] == "PS256"
    assert posted[0]["value"] == _b64url(hashlib.sha256(message).digest())
    assert portal.verify(message, signature, kid) is True
    assert portal.verify(message, signature, kid + "-other") is False

    calls: list[str] = []

    def verify_handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method + " " + request.url.path)
        if request.method == "POST":
            return httpx.Response(500)
        if request.url.path.endswith("/versions"):
            return httpx.Response(
                200,
                json={"value": [{"kid": kid, "attributes": {"enabled": True, "created": 10}}]},
            )
        return httpx.Response(200, json={"key": _jwk(signer)})

    reader = KeyVaultSigner(
        key_url,
        lambda: "aaa.bbb.ccc",
        allow_sign=False,
        client=httpx.Client(transport=httpx.MockTransport(verify_handler)),
    )
    assert reader.verify(message, signature, kid) is True
    with pytest.raises(ConfigRejected) as caught:
        reader.sign(message)
    assert caught.value.reason_code == "sign_not_permitted"
    assert all(not item.endswith("/sign") for item in calls)


def test_session_secret_is_created_in_the_vault_when_missing() -> None:
    created: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/secrets/session-hmac-key")
        if request.method == "GET":
            return httpx.Response(404)
        body = json.loads(request.content)
        created.append(body["value"])
        return httpx.Response(200)

    raw = session_key_from_vault(
        "https://example.vault.azure.net",
        lambda: "aaa.bbb.ccc",
        httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert raw.decode("utf-8") == created[0]
    assert len(raw) >= 32


def test_blob_floor_appends_and_rejects_a_lower_version() -> None:
    state = {"text": None}
    auths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        auths.append(request.headers["Authorization"])
        assert "SharedKey" not in request.headers["Authorization"]
        if request.method == "GET":
            if state["text"] is None:
                return httpx.Response(404)
            return httpx.Response(200, text=state["text"])
        if "comp=appendblock" in str(request.url):
            state["text"] = (state["text"] or "") + request.content.decode("utf-8")
            return httpx.Response(201)
        assert request.headers["x-ms-blob-type"] == "AppendBlob"
        state["text"] = ""
        return httpx.Response(201)

    floor = BlobVersionFloor(
        "https://prm.blob.core.windows.net/prm-floor",
        token_provider=lambda: "aaa.bbb.ccc",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    assert floor.high_water() == 0
    digest = "ab" * 32
    floor.advance(2, digest)
    assert floor.high_water() == 2
    floor.advance(2, digest)
    with pytest.raises(ConfigRejected) as caught:
        floor.advance(1, digest)
    assert caught.value.reason_code == "snapshot_replay"
    assert auths[0].startswith("Bearer ")
    with pytest.raises(ConfigRejected) as same:
        floor_separated("https://prm.blob.core.windows.net/prm-floor", floor)
    assert same.value.reason_code == "version_floor_inside_store"
