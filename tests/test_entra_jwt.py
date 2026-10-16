"""Entra v2 tokens: pinned tenant, audience, scope, client allowlist, MFA, JWKS fail-closed."""

from __future__ import annotations

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from starlette.testclient import TestClient

from presidio_redaction_mcp.entra import (
    PINNED_TENANT_ID,
    PHI_ROLE,
    NONPHI_ROLE,
    EntraClient,
    EntraTokenVerifier,
    pinned_issuer,
)
from presidio_redaction_mcp.errors import AuthError
from tests.conftest import build_test_runtime

AUD = "api://presidio-redaction-mcp"
CLAUDE = "11111111-1111-4111-8111-111111111111"
WEBUI = "22222222-2222-4222-8222-222222222222"
GROK = "33333333-3333-4333-8333-333333333333"
OTHER = "44444444-4444-4444-8444-444444444444"
CLIENTS = (
    EntraClient("claude-local", CLAUDE, True, True),
    EntraClient("open-webui", WEBUI, True, True),
    EntraClient("grok-bot", GROK, False, False),
)


def _key_and_jwks():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "k1", "use": "sig", "alg": "RS256"})
    return key, {"keys": [jwk]}


def _encode(key, **overrides) -> str:
    now = int(time.time())
    claims = {
        "iss": pinned_issuer(),
        "aud": AUD,
        "iat": now,
        "nbf": now - 5,
        "exp": now + 600,
        "ver": "2.0",
        "tid": PINNED_TENANT_ID,
        "azp": CLAUDE,
        "scp": "access_as_user",
        "roles": [PHI_ROLE],
        "amr": ["mfa"],
    }
    header_kid = str(overrides.pop("kid", "k1"))
    claims.update(overrides)
    claims = {name: value for name, value in claims.items() if value is not None}
    token = jwt.encode(claims, key, algorithm="RS256", headers={"kid": header_kid})
    return token if isinstance(token, str) else token.decode("ascii")


def _verifier(jwks, *, fetcher=None, ttl=3600, now=None) -> EntraTokenVerifier:
    return EntraTokenVerifier(
        audience=AUD,
        clients=CLIENTS,
        jwks_fetcher=fetcher or (lambda: jwks),
        cache_ttl_seconds=ttl,
        now=now,
    )


def test_pinned_issuer_audience_scope_and_phi_role():
    key, jwks = _key_and_jwks()
    principal = _verifier(jwks).verify(_encode(key))
    assert principal.name == "claude-local"
    assert principal.phi_capable is True
    assert principal.app_id == CLAUDE


def test_non_phi_role_cannot_become_a_phi_caller():
    key, jwks = _key_and_jwks()
    principal = _verifier(jwks).verify(_encode(key, roles=[NONPHI_ROLE], amr=["pwd"], acrs=["c1"]))
    assert principal.phi_capable is False
    assert principal.name == "claude-local"


def test_grok_workload_token_stays_non_phi():
    key, jwks = _key_and_jwks()
    principal = _verifier(jwks).verify(
        _encode(key, azp=GROK, scp=None, roles=[NONPHI_ROLE], idtyp="app", amr=None)
    )
    assert principal.name == "grok-bot"
    assert principal.phi_capable is False


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"aud": "api://other"}, "audience_mismatch"),
        ({"exp": int(time.time()) - 30}, "token_expired"),
        ({"nbf": int(time.time()) + 600, "exp": int(time.time()) + 900}, "token_not_yet_valid"),
        ({"iss": "https://login.microsoftonline.com/common/v2.0"}, "issuer_mismatch"),
        ({"iss": "https://login.microsoftonline.com/organizations/v2.0"}, "issuer_mismatch"),
        ({"iss": f"https://sts.windows.net/{PINNED_TENANT_ID}/"}, "issuer_mismatch"),
        ({"tid": "common"}, "tenant_mismatch"),
        ({"ver": "1.0"}, "token_version_rejected"),
        ({"azp": OTHER}, "unknown_client"),
        ({"appid": OTHER}, "unknown_client"),
        ({"scp": "User.Read"}, "scope_missing"),
        ({"amr": ["pwd"], "acrs": []}, "mfa_required"),
        ({"roles": ["Phi.Caller", "NonPhi.Caller"]}, "role_conflict"),
        ({"azp": GROK, "roles": [PHI_ROLE], "scp": None, "idtyp": "app"}, "role_client_mismatch"),
    ],
)
def test_token_claims_fail_closed(overrides, reason):
    key, jwks = _key_and_jwks()
    claims = dict(overrides)
    if "acrs" in claims and claims["acrs"] == []:
        claims["acrs"] = []
    with pytest.raises(AuthError) as caught:
        _verifier(jwks).verify(_encode(key, **claims))
    assert caught.value.reason_code == reason


def test_acrs_satisfies_the_mfa_check_when_amr_is_password_only():
    key, jwks = _key_and_jwks()
    principal = _verifier(jwks).verify(_encode(key, amr=["pwd"], acrs=["c1"]))
    assert principal.phi_capable is True


def test_jwks_fetch_errors_fail_closed_and_drop_the_cache():
    key, jwks = _key_and_jwks()
    state = {"calls": 0, "fail": False, "now": 0.0}

    def fetcher():
        state["calls"] += 1
        if state["fail"]:
            raise RuntimeError("jwks down")
        return jwks

    verifier = _verifier(jwks, fetcher=fetcher, ttl=10, now=lambda: state["now"])
    verifier.verify(_encode(key))
    verifier.verify(_encode(key))
    assert state["calls"] == 1
    state["now"] = 11
    state["fail"] = True
    with pytest.raises(AuthError) as caught:
        verifier.verify(_encode(key))
    assert caught.value.reason_code == "jwks_fetch_failed"
    state["fail"] = False
    recovered = verifier.verify(_encode(key))
    assert recovered.name == "claude-local"
    assert state["calls"] == 3


def test_unknown_kid_refreshes_jwks_once():
    key, current = _key_and_jwks()
    stale = {"keys": [{**current["keys"][0], "kid": "old"}]}
    state = {"calls": 0}

    def fetcher():
        state["calls"] += 1
        return stale if state["calls"] == 1 else current

    principal = _verifier(current, fetcher=fetcher).verify(_encode(key))
    assert principal.name == "claude-local"
    assert state["calls"] == 2


def test_unknown_kid_refresh_does_not_loop():
    key, missing = _key_and_jwks()
    missing = {"keys": [{**missing["keys"][0], "kid": "other"}]}
    state = {"calls": 0}

    def fetcher():
        state["calls"] += 1
        return missing

    verifier = _verifier(missing, fetcher=fetcher)
    with pytest.raises(AuthError) as caught:
        verifier.verify(_encode(key))
    assert caught.value.reason_code == "jwks_key_missing"
    assert state["calls"] == 2
    with pytest.raises(AuthError) as again:
        verifier.verify(_encode(key))
    assert again.value.reason_code == "jwks_key_missing"
    assert state["calls"] == 2


def test_unknown_kid_cooldown_is_not_cleared_by_a_good_lookup():
    key, current = _key_and_jwks()
    clock = {"now": 0.0}
    state = {"calls": 0}

    def fetcher():
        state["calls"] += 1
        return current

    verifier = _verifier(current, fetcher=fetcher, ttl=10, now=lambda: clock["now"])
    assert verifier.verify(_encode(key)).name == "claude-local"
    assert state["calls"] == 1

    with pytest.raises(AuthError) as first:
        verifier.verify(_encode(key, kid="gone"))
    assert first.value.reason_code == "jwks_key_missing"
    assert state["calls"] == 2
    assert verifier._miss_refresh_not_before == 10.0

    assert verifier.verify(_encode(key)).name == "claude-local"
    assert state["calls"] == 2
    assert verifier._miss_refresh_not_before == 10.0

    with pytest.raises(AuthError) as during:
        verifier.verify(_encode(key, kid="gone"))
    assert during.value.reason_code == "jwks_key_missing"
    assert state["calls"] == 2

    clock["now"] = 10.0
    with pytest.raises(AuthError) as later:
        verifier.verify(_encode(key, kid="gone"))
    assert later.value.reason_code == "jwks_key_missing"
    assert state["calls"] == 4
    assert verifier._miss_refresh_not_before == 20.0
    with pytest.raises(AuthError) as held:
        verifier.verify(_encode(key, kid="gone"))
    assert held.value.reason_code == "jwks_key_missing"
    assert state["calls"] == 4


def test_empty_jwks_document_fails_closed():
    key, _jwks = _key_and_jwks()
    with pytest.raises(AuthError) as caught:
        _verifier({"keys": []}).verify(_encode(key))
    assert caught.value.reason_code == "jwks_fetch_failed"


def test_common_tenant_cannot_construct_a_verifier():
    _key, jwks = _key_and_jwks()
    with pytest.raises(AuthError) as caught:
        EntraTokenVerifier(audience=AUD, clients=CLIENTS, jwks_fetcher=lambda: jwks, tenant_id="common")
    assert caught.value.reason_code == "entra_tenant_unpinned"


def test_private_listener_revalidates_and_ignores_apim_headers(tmp_path, monkeypatch):
    key, jwks = _key_and_jwks()
    runtime = build_test_runtime(tmp_path, monkeypatch, entra=_verifier(jwks))
    token = _encode(key)
    try:
        assert runtime.private_app is not None
        with TestClient(runtime.private_app, base_url="http://testserver") as client:
            spoofed = client.post(
                "/mcp/",
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                    "X-MS-CLIENT-PRINCIPAL": "claude-local",
                    "X-APIM-CLIENT-ID": CLAUDE,
                    "Cf-Access-Jwt-Assertion": token,
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "stackjack_health_check", "arguments": {"limit": 1}},
                },
            )
            assert spoofed.status_code == 401
            assert spoofed.json()["reason_code"] == "invalid_token"
            accepted = client.post(
                "/mcp/",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                    "X-MS-CLIENT-PRINCIPAL": "grok-bot",
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "stackjack_health_check", "arguments": {"limit": 1}},
                },
            )
            assert accepted.status_code == 200
            metadata = client.get("/.well-known/oauth-protected-resource")
            body = metadata.json()
            assert pinned_issuer() in body["authorization_servers"]
            assert "common" not in body["authorization_servers"][0]
        blob = runtime.audit.path.read_text(encoding="utf-8")
        assert token not in blob
        assert "auth_ok" in blob
        assert "grok-bot" not in blob
    finally:
        import asyncio

        asyncio.run(runtime.presidio.aclose())
