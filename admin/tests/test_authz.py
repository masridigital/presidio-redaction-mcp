from __future__ import annotations

import base64
import json
import time

import jwt
import pytest

from presidio_admin.authz import (
    SESSION_IDLE_SECONDS,
    TENANT_ID,
    AuthzError,
    Principal,
    authorize_claims,
    authorize_redirect,
    issuer_for,
    open_session,
    seal_session,
)

AUDIENCE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
PROPOSER = "11111111-1111-4111-8111-111111111111"
APPROVER = "22222222-2222-4222-8222-222222222222"


def test_admin_with_mfa_and_acrs_is_accepted(tokens) -> None:
    principal = tokens.verifier.verify(tokens.token())
    assert principal.oid == PROPOSER
    assert "Admin" in principal.roles
    assert "mfa" in principal.amr
    assert "c1" in principal.acrs


def test_ngcmfa_satisfies_the_amr_check(tokens) -> None:
    principal = tokens.verifier.verify(tokens.token(amr=["ngcmfa"]))
    assert "ngcmfa" in principal.amr


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"roles": ["PHI"]}, "admin_role_required"),
        ({"roles": "Admin"}, "admin_role_required"),
        ({"amr": ["pwd"]}, "mfa_amr_required"),
        ({"amr": ["wiaormfa"]}, "mfa_amr_required"),
        ({"amr": "mfa"}, "mfa_amr_required"),
        ({"acrs": ["c2"]}, "acrs_required"),
        ({"acrs": "c1"}, "acrs_required"),
        ({"tid": "00000000-0000-0000-0000-000000000000"}, "tenant_mismatch"),
        ({"aud": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"}, "token_invalid"),
        ({"iss": "https://login.microsoftonline.com/common/v2.0"}, "token_invalid"),
        ({"exp": int(time.time()) - 10, "iat": int(time.time()) - 20}, "token_expired"),
        ({"exp": int(time.time()) + 9000, "iat": int(time.time())}, "token_lifetime_exceeded"),
    ],
)
def test_authz_rejects_incomplete_tokens(tokens, overrides: dict, reason: str) -> None:
    with pytest.raises(AuthzError) as caught:
        tokens.verifier.verify(tokens.token(**overrides))
    assert caught.value.reason_code == reason


def test_claim_policy_rejects_wrong_issuer_and_audience() -> None:
    now = int(time.time())
    base = {
        "iss": issuer_for(TENANT_ID),
        "aud": AUDIENCE,
        "tid": TENANT_ID,
        "oid": PROPOSER,
        "roles": ["Admin"],
        "amr": ["mfa"],
        "acrs": ["c1"],
        "iat": now,
        "nbf": now,
        "exp": now + 600,
    }
    missing_nbf = dict(base)
    del missing_nbf["nbf"]
    with pytest.raises(AuthzError) as immature:
        authorize_claims(missing_nbf, audience=AUDIENCE)
    assert immature.value.reason_code == "token_invalid"
    wrong_issuer = dict(base, iss="https://login.microsoftonline.com/common/v2.0")
    with pytest.raises(AuthzError) as issuer:
        authorize_claims(wrong_issuer, audience=AUDIENCE)
    assert issuer.value.reason_code == "issuer_mismatch"
    wrong_audience = dict(base, aud="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
    with pytest.raises(AuthzError) as audience:
        authorize_claims(wrong_audience, audience=AUDIENCE)
    assert audience.value.reason_code == "audience_mismatch"


def test_hmac_and_none_algorithms_are_rejected(tokens) -> None:
    now = int(time.time())
    claims = {
        "iss": issuer_for(TENANT_ID),
        "aud": AUDIENCE,
        "tid": TENANT_ID,
        "oid": APPROVER,
        "roles": ["Admin"],
        "amr": ["mfa"],
        "acrs": ["c1"],
        "iat": now,
        "exp": now + 600,
    }
    hmac_token = jwt.encode(claims, "s" * 32, algorithm="HS256", headers={"kid": "test-key"})
    with pytest.raises(AuthzError) as caught:
        tokens.verifier.verify(hmac_token)
    assert caught.value.reason_code == "token_invalid"
    unsigned = _unsigned(claims)
    with pytest.raises(AuthzError):
        tokens.verifier.verify(unsigned)


def _unsigned(claims: dict) -> str:
    def encode(value: dict) -> str:
        raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return encode({"alg": "none", "kid": "test-key"}) + "." + encode(claims) + "."


def test_missing_and_garbled_tokens_are_rejected(tokens) -> None:
    with pytest.raises(AuthzError):
        tokens.verifier.verify(None)
    with pytest.raises(AuthzError):
        tokens.verifier.verify("not-a-jwt")


def test_authorize_url_pins_tenant_and_omits_secrets() -> None:
    url = authorize_redirect(
        tenant_id=TENANT_ID,
        client_id=AUDIENCE,
        redirect_uri="https://admin.internal/auth/callback",
        state="synthetic-state",
        code_challenge="synthetic-challenge",
    )
    assert f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/authorize?" in url
    assert f"client_id={AUDIENCE}" in url
    assert "code_challenge=synthetic-challenge" in url
    assert "client_secret" not in url


def test_http_requires_admin_mfa_and_acrs(client, tokens) -> None:
    missing = client.get("/api/config")
    assert missing.status_code == 401
    assert missing.json()["error"] == "token_missing"

    role = client.get("/api/config", headers=tokens.auth(roles=["PHI"]))
    assert role.status_code == 403
    assert role.json()["error"] == "admin_role_required"

    amr = client.get("/api/config", headers=tokens.auth(amr=["pwd"]))
    assert amr.status_code == 403
    assert amr.json()["error"] == "mfa_amr_required"

    acrs = client.get("/api/config", headers=tokens.auth(acrs=[]))
    assert acrs.status_code == 403
    assert acrs.json()["error"] == "acrs_required"

    allowed = client.get("/api/config", headers=tokens.auth())
    assert allowed.status_code == 200
    assert allowed.json()["config"]["upstreams"].keys() == {"stackjack", "composio"}


def test_session_goes_idle_after_fifteen_minutes(session_key: bytes) -> None:
    now = int(time.time())
    principal = Principal(
        oid=PROPOSER,
        display_label="Synthetic Admin",
        tenant_id=TENANT_ID,
        roles=("Admin",),
        amr=("mfa",),
        acrs=("c1",),
        expires_at=now + 3600,
        upn_domain="example.com",
    )
    sealed = seal_session(
        principal,
        "c" * 16,
        session_key,
        audience=AUDIENCE,
        seen=now - SESSION_IDLE_SECONDS - 5,
    )
    with pytest.raises(AuthzError) as caught:
        open_session(
            sealed,
            session_key,
            audience=AUDIENCE,
            tenant_id=TENANT_ID,
            required_acrs="c1",
        )
    assert caught.value.reason_code == "session_idle"
    fresh = seal_session(principal, "c" * 16, session_key, audience=AUDIENCE, seen=now)
    opened = open_session(fresh, session_key, audience=AUDIENCE, tenant_id=TENANT_ID, required_acrs="c1")
    assert opened is not None
    assert opened[0].upn_domain == "example.com"


def test_login_redirects_to_entra_without_a_secret(client) -> None:
    response = client.get("/auth/login", follow_redirects=False)
    assert response.status_code == 302
    location = response.headers["location"]
    assert TENANT_ID in location
    assert "client_secret" not in location
    assert "code_challenge=" in location
    callback = client.get("/auth/callback", params={"code": "synthetic", "state": "nope"})
    assert callback.status_code == 503
    assert callback.json()["error"] == "auth_not_configured"
