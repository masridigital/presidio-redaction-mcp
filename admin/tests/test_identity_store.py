"""Blob access uses a bearer token. The admin client sends an assertion, not a secret."""

from __future__ import annotations

import httpx
import pytest

from presidio_admin.client_auth import ASSERTION_TYPE, token_request_form
from presidio_admin.documents import AzureBlobDocuments
from presidio_admin.errors import ConfigRejected


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
