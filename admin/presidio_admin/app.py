"""HTTP portal. Browser sessions and bearer tokens share one authorization check."""

from __future__ import annotations

import logging
import os
import secrets
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route

from presidio_admin.approval import ChangeService, describe_diff
from presidio_admin.audit_view import read_lines, render_lines
from presidio_admin.authz import (
    TENANT_ID,
    EntraVerifier,
    Principal,
    authorize_redirect,
    open_session,
    seal_session,
    touch_session,
)
from presidio_admin.client_auth import assertion_from_env, token_request_form
from presidio_admin.errors import ApprovalError, AuthzError, ConfigRejected
from presidio_admin.health import render_metrics, snapshot
from presidio_admin.schema import default_config
from presidio_admin.store import ConfigStore
from presidio_admin.ui import esc, hidden, login_page, metrics_cards, page

_principal: ContextVar[Principal | None] = ContextVar("admin_principal", default=None)
_csrf: ContextVar[str] = ContextVar("admin_csrf", default="")

PUBLIC = frozenset({"/healthz", "/auth/login", "/auth/callback"})
_AUTHZ_STATUS = {
    "token_missing": 401,
    "token_invalid": 401,
    "token_expired": 401,
    "token_not_yet_valid": 401,
    "session_idle": 401,
}
NOTICES = {
    "applied": "Change published.",
    "pending": "Waiting for a second Admin. You cannot approve your own change.",
    "rejected": "Proposal rejected. The published config did not change.",
    "withdrawn": "Proposal withdrawn.",
    "config_rejected": "That change is not valid. The published config did not change.",
    "change_rejected": "That change is not valid. The published config did not change.",
    "change_empty": "Nothing changed.",
    "self_approval_forbidden": "A different Admin has to approve this change.",
    "stale_proposal": "The proposal is stale because the published config moved.",
    "proposal_pending": "Another change is already waiting for approval.",
    "proposal_missing": "That proposal does not exist.",
    "proposal_not_pending": "That proposal is no longer pending.",
    "admin_role_required": "The Admin app role is required.",
    "mfa_amr_required": "The token has no MFA amr value.",
    "acrs_required": "The token is missing the required authentication context.",
    "tenant_mismatch": "The token is for a different tenant.",
}


@dataclass
class Portal:
    store: ConfigStore
    changes: ChangeService
    verifier: EntraVerifier
    session_key: bytes
    cookie_secure: bool = False
    redirect_uri: str = ""
    assertion: object | None = None
    proxy_audit_key: bytes = b""


def create_app(portal: Portal) -> Starlette:
    async def healthz(_: Request) -> Response:
        item = snapshot(portal.store)
        code = 200 if item.config_valid and item.chain_valid else 503
        return JSONResponse(
            {
                "status": "ok" if code == 200 else "unavailable",
                "config_valid": item.config_valid,
                "version_id": item.version_id,
                "sha256": item.sha256,
            },
            status_code=code,
        )

    async def metrics(request: Request) -> Response:
        _require(request)
        return PlainTextResponse(render_metrics(snapshot(portal.store)))

    async def overview(request: Request) -> Response:
        principal = _require(request)
        item = snapshot(portal.store)
        active = portal.store.read_active()
        body = metrics_cards(_snap(item))
        body += f"<p class='meta'>Published sha256 <code>{esc(active.sha256)}</code></p>"
        body += "<p class='meta'>Tools are off until an Admin enables one and a second Admin approves it.</p>"
        return _html("Overview", principal, body, request)

    async def upstreams(request: Request) -> Response:
        principal = _require(request)
        config = portal.store.read_active().config
        sections = []
        for name, upstream in config.upstreams.items():
            rows = []
            for tool in upstream.tools:
                nxt = "false" if tool.enabled else "true"
                label = "Disable" if tool.enabled else "Enable"
                form = (
                    f"<form class='inline' method='post' action='/actions'>"
                    f"{hidden(_csrf.get(), op='set_tool_enabled', upstream=name, tool=tool.name, enabled=nxt)}"
                    f"<button class='quiet' type='submit'>{label}</button></form>"
                )
                state = "on" if tool.enabled else "off"
                rows.append(
                    "<tr>"
                    f"<td><code>{esc(tool.name)}</code></td>"
                    f"<td>{esc(state)}</td>"
                    f"<td>{esc(tool.max_items)}</td>"
                    f"<td>{form}</td>"
                    "</tr>"
                )
            up_next = "false" if upstream.enabled else "true"
            up_label = "Disable upstream" if upstream.enabled else "Enable upstream"
            toggle = (
                f"<form class='inline' method='post' action='/actions'>"
                f"{hidden(_csrf.get(), op='set_upstream_enabled', upstream=name, enabled=up_next)}"
                f"<button type='submit'>{up_label}</button></form>"
            )
            sections.append(
                f"<h2>{esc(name)} <span class='meta'>{'enabled' if upstream.enabled else 'disabled'}</span></h2>"
                f"<p>{toggle}</p>"
                "<table><tr><th>Tool</th><th>Allowlist</th><th>Max items</th><th></th></tr>"
                + "".join(rows)
                + "</table>"
            )
        return _html("Upstreams", principal, "".join(sections), request)

    async def clients(request: Request) -> Response:
        principal = _require(request)
        config = portal.store.read_active().config
        rows = []
        for client in config.clients:
            nxt = "false" if client.enabled else "true"
            label = "Disable" if client.enabled else "Enable"
            form = (
                f"<form class='inline' method='post' action='/actions'>"
                f"{hidden(_csrf.get(), op='set_client_enabled', client_id=client.client_id, enabled=nxt)}"
                f"<button class='quiet' type='submit'>{label}</button></form>"
            )
            if client.app_role != "PHI":
                form += (
                    f"<form class='inline' method='post' action='/actions'>"
                    f"{hidden(_csrf.get(), op='set_client_role', client_id=client.client_id, app_role='PHI')}"
                    f"<button class='quiet' type='submit'>Grant PHI</button></form>"
                )
            rows.append(
                "<tr>"
                f"<td><code>{esc(client.client_id)}</code></td>"
                f"<td>{esc(client.display_name)}</td>"
                f"<td>{esc(client.app_role)}</td>"
                f"<td>{'on' if client.enabled else 'off'}</td>"
                f"<td>{form}</td>"
                "</tr>"
            )
        table = (
            "<table><tr><th>Client id</th><th>Name</th><th>App role</th><th></th><th></th></tr>"
            + "".join(rows)
            + "</table>"
        )
        form = (
            f"<h2>Register a client</h2>"
            f"<p class='meta'>Pre-registered Entra app only. No client secret is stored. Adding a client needs a second Admin.</p>"
            f"<form method='post' action='/actions'>"
            f"{hidden(_csrf.get(), op='add_client')}"
            f"<p><label>Display name <input name='display_name' required maxlength='80'></label></p>"
            f"<p><label>Client id <input name='client_id' required size='40'></label></p>"
            f"<p><label>App role <select name='app_role'>"
            f"<option value='NonPHI'>NonPHI</option><option value='PHI'>PHI</option>"
            f"</select></label></p>"
            f"<button type='submit'>Submit for approval</button></form>"
        )
        return _html("Clients", principal, table + form, request)

    async def recognizers(request: Request) -> Response:
        principal = _require(request)
        config = portal.store.read_active().config
        threshold = (
            f"<form method='post' action='/actions'>"
            f"{hidden(_csrf.get(), op='set_score_threshold')}"
            f"<label>Presidio score threshold "
            f"<input name='value' value='{esc(config.score_threshold)}' required></label> "
            f"<button type='submit'>Update threshold</button></form>"
            f"<p class='meta'>Lowering a score, or raising this floor, waits for a second Admin. "
            f"The floor cannot go below 0.4.</p>"
        )
        rows = []
        for recognizer in config.recognizers:
            for pattern in recognizer.patterns:
                score_form = (
                    f"<form class='inline' method='post' action='/actions'>"
                    f"{hidden(_csrf.get(), op='set_pattern_score', recognizer=recognizer.name, pattern=pattern.name)}"
                    f"<input name='value' value='{esc(pattern.score)}' size='6'> "
                    f"<button class='quiet' type='submit'>Save</button></form>"
                )
                nxt = "false" if pattern.enabled else "true"
                flag = "Disable" if pattern.enabled else "Enable"
                toggle = (
                    f"<form class='inline' method='post' action='/actions'>"
                    f"{hidden(_csrf.get(), op='set_pattern_enabled', recognizer=recognizer.name, pattern=pattern.name, enabled=nxt)}"
                    f"<button class='quiet' type='submit'>{flag}</button></form>"
                )
                rows.append(
                    "<tr>"
                    f"<td>{esc(recognizer.entity)}</td>"
                    f"<td><code>{esc(pattern.name)}</code></td>"
                    f"<td>{'on' if pattern.enabled else 'off'}</td>"
                    f"<td>{score_form}</td>"
                    f"<td>{toggle}</td>"
                    "</tr>"
                )
        table = (
            "<table><tr><th>Entity</th><th>Pattern</th><th></th><th>Score</th><th></th></tr>"
            + "".join(rows)
            + "</table>"
        )
        return _html("Recognizers", principal, threshold + table, request)

    async def verifier(request: Request) -> Response:
        principal = _require(request)
        enabled = portal.store.read_active().config.claude_verifier_enabled
        nxt = "false" if enabled else "true"
        label = "Turn verifier off" if enabled else "Turn verifier on"
        body = (
            f"<p>Claude verifier is <strong>{'on' if enabled else 'off'}</strong>.</p>"
            f"<p class='meta'>Turning it off requires a second Admin. The proxy does not send payloads to Claude.</p>"
            f"<form method='post' action='/actions'>"
            f"{hidden(_csrf.get(), op='set_verifier', enabled=nxt)}"
            f"<button type='submit'>{label}</button></form>"
        )
        return _html("Verifier", principal, body, request)

    async def audit(request: Request) -> Response:
        principal = _require(request)
        rendered = portal.store.audit.render()
        extra = os.environ.get("PRM_AUDIT_PATH")
        proxy_note = ""
        if extra and portal.proxy_audit_key:
            proxy_view = render_lines(read_lines(Path(extra)), portal.proxy_audit_key)
            rendered = {
                "chain_valid": rendered["chain_valid"] and proxy_view["chain_valid"],
                "rows": proxy_view["rows"] + rendered["rows"],
            }
            proxy_note = "<p class='meta'>Proxy audit file included. Payload fields are not shown.</p>"
        state = "valid" if rendered["chain_valid"] else "broken"
        klass = "ok" if rendered["chain_valid"] else "bad"
        rows = []
        for row in rendered["rows"]:
            cells = "".join(f"<td>{esc(row.get(key, ''))}</td>" for key in ("ts", "event", "action", "decision", "reason_code", "actor_oid", "tool", "risk_flags"))
            rows.append(f"<tr>{cells}</tr>")
        body = (
            f"<p class='{klass}'>HMAC chain {state}.</p>{proxy_note}"
            "<table><tr><th>When</th><th>Event</th><th>Action</th><th>Decision</th><th>Reason</th>"
            "<th>Actor</th><th>Tool</th><th>Flags</th></tr>"
            + "".join(rows)
            + "</table>"
        )
        return _html("Audit", principal, body, request)

    async def history(request: Request) -> Response:
        principal = _require(request)
        rows = []
        for item in portal.store.history():
            rows.append(
                "<tr>"
                f"<td>{esc(item['version_id'])}</td>"
                f"<td><code>{esc(item['sha256'][:12])}</code></td>"
                f"<td>{esc(item['actor_oid'])}</td>"
                f"<td>{esc(item['approver_oid'])}</td>"
                f"<td>{esc(', '.join(item['summary']))}</td>"
                "</tr>"
            )
        body = (
            "<table><tr><th>Version</th><th>SHA</th><th>Actor</th><th>Approver</th><th>Summary</th></tr>"
            + "".join(rows)
            + "</table>"
        )
        return _html("History", principal, body, request)

    async def proposals(request: Request) -> Response:
        principal = _require(request)
        rows = []
        for item in portal.store.list_proposals():
            try:
                base = portal.store.version(item.base_version_id)
                diff = describe_diff(base.config, item.config)
            except ConfigRejected:
                diff = ["diff unavailable"]
            actions = ""
            if item.status == "pending":
                actions = (
                    f"<form class='inline' method='post' action='/actions'>"
                    f"{hidden(_csrf.get(), op='approve', proposal_id=item.proposal_id)}"
                    f"<button type='submit'>Approve</button></form> "
                    f"<form class='inline' method='post' action='/actions'>"
                    f"{hidden(_csrf.get(), op='reject', proposal_id=item.proposal_id)}"
                    f"<button class='quiet' type='submit'>Reject</button></form>"
                )
            rows.append(
                "<tr>"
                f"<td><code>{esc(item.proposal_id)}</code></td>"
                f"<td>{esc(item.status)}</td>"
                f"<td>{esc(item.proposer_oid)}</td>"
                f"<td><code>{esc(item.base_sha256)}</code><br><code>{esc(item.config_sha256)}</code></td>"
                f"<td>{esc('; '.join(diff))}</td>"
                f"<td>{esc(', '.join(item.risk_flags))}</td>"
                f"<td>{actions}</td>"
                "</tr>"
            )
        body = (
            "<p class='meta'>The Admin who proposed a risky change cannot approve it. "
            "Approve the signed diff and the proposed hash, not a later edit.</p>"
            "<table><tr><th>Proposal</th><th>Status</th><th>Proposer</th><th>Base hash / proposed hash</th>"
            "<th>Diff</th><th>Risk</th><th></th></tr>"
            + "".join(rows)
            + "</table>"
        )
        return _html("Approvals", principal, body, request)

    async def health_page(request: Request) -> Response:
        principal = _require(request)
        item = snapshot(portal.store)
        body = metrics_cards(_snap(item)) + "<p><a href='/metrics'>Metrics</a></p>"
        return _html("Health", principal, body, request)

    async def actions(request: Request) -> Response:
        principal = _require(request)
        form = await request.form()
        if not _csrf_ok(request, str(form.get("csrf") or "")):
            return _html("Rejected", principal, "<p>The form token did not match this session.</p>", request, status=403)
        try:
            patch = _patch_from_form(form)
        except (ApprovalError, TypeError, ValueError):
            return RedirectResponse("/?notice=change_rejected", status_code=303)
        try:
            if patch["op"] == "approve":
                result = portal.changes.approve(principal, str(form.get("proposal_id") or ""))
            elif patch["op"] == "reject":
                result = portal.changes.reject(principal, str(form.get("proposal_id") or ""))
            else:
                result = portal.changes.submit(principal, patch)
            notice = result.status
        except (ApprovalError, ConfigRejected) as exc:
            notice = exc.reason_code
        target = _return_to(str(form.get("op") or ""))
        response = RedirectResponse(f"{target}?notice={notice}", status_code=303)
        return response

    async def api_config(request: Request) -> Response:
        _require(request)
        active = portal.store.read_active()
        return JSONResponse(
            {
                "version_id": active.version_id,
                "sha256": active.sha256,
                "config": active.config.model_dump(mode="json"),
            }
        )

    async def api_change(request: Request) -> Response:
        principal = _require(request)
        if not _csrf_ok(request, request.headers.get("x-csrf-token", "")):
            return JSONResponse({"error": "token_invalid"}, status_code=403)
        patch = await request.json()
        try:
            result = portal.changes.submit(principal, patch)
        except (ApprovalError, ConfigRejected) as exc:
            return JSONResponse({"error": exc.reason_code}, status_code=400)
        return JSONResponse(
            {
                "status": result.status,
                "version_id": result.version_id,
                "proposal_id": result.proposal_id,
                "risk_flags": list(result.risk_flags),
            }
        )

    async def api_approve(request: Request) -> Response:
        principal = _require(request)
        if not _csrf_ok(request, request.headers.get("x-csrf-token", "")):
            return JSONResponse({"error": "token_invalid"}, status_code=403)
        proposal_id = request.path_params["proposal_id"]
        try:
            result = portal.changes.approve(principal, proposal_id)
        except ApprovalError as exc:
            code = 403 if exc.reason_code == "self_approval_forbidden" else 400
            return JSONResponse({"error": exc.reason_code}, status_code=code)
        return JSONResponse({"status": result.status, "version_id": result.version_id})

    async def api_reject(request: Request) -> Response:
        principal = _require(request)
        if not _csrf_ok(request, request.headers.get("x-csrf-token", "")):
            return JSONResponse({"error": "token_invalid"}, status_code=403)
        try:
            result = portal.changes.reject(principal, request.path_params["proposal_id"])
        except ApprovalError as exc:
            return JSONResponse({"error": exc.reason_code}, status_code=400)
        return JSONResponse({"status": result.status})

    async def api_audit(request: Request) -> Response:
        _require(request)
        return JSONResponse(portal.store.audit.render())

    async def api_history(request: Request) -> Response:
        _require(request)
        return JSONResponse({"versions": portal.store.history()})

    async def login(_: Request) -> Response:
        verifier_secret = secrets.token_urlsafe(32)
        challenge = _code_challenge(verifier_secret)
        state = secrets.token_urlsafe(24)
        url = authorize_redirect(
            tenant_id=portal.verifier.tenant_id,
            client_id=portal.verifier.audience,
            redirect_uri=portal.redirect_uri or "https://admin.internal/auth/callback",
            state=state,
            code_challenge=challenge,
        )
        if "client_secret" in url:
            return JSONResponse({"error": "auth_not_configured"}, status_code=503)
        response = RedirectResponse(url, status_code=302)
        response.set_cookie(
            "prm_admin_pkce",
            seal_pkce(portal.session_key, state, verifier_secret),
            httponly=True,
            secure=portal.cookie_secure,
            samesite="strict",
            max_age=600,
            path="/auth",
        )
        return response

    async def callback(request: Request) -> Response:
        if portal.assertion is None:
            return JSONResponse({"error": "auth_not_configured"}, status_code=503)
        opened = open_pkce(request.cookies.get("prm_admin_pkce"), portal.session_key)
        if opened is None or opened[0] != request.query_params.get("state"):
            return JSONResponse({"error": "token_invalid"}, status_code=401)
        code = request.query_params.get("code")
        if not code:
            return JSONResponse({"error": "token_invalid"}, status_code=401)
        token = await _exchange(portal, code, opened[1])
        try:
            principal = portal.verifier.verify(token)
        except AuthzError as exc:
            status = _AUTHZ_STATUS.get(exc.reason_code, 403)
            return JSONResponse({"error": exc.reason_code}, status_code=status)
        return _session_response(portal, principal, RedirectResponse("/", status_code=303))

    async def session(request: Request) -> Response:
        principal = _require(request)
        return _session_response(portal, principal, JSONResponse({"status": "signed_in", "oid": principal.oid}))

    routes = [
        Route("/healthz", healthz),
        Route("/metrics", metrics),
        Route("/", overview),
        Route("/upstreams", upstreams),
        Route("/clients", clients),
        Route("/recognizers", recognizers),
        Route("/verifier", verifier),
        Route("/audit", audit),
        Route("/history", history),
        Route("/proposals", proposals),
        Route("/health", health_page),
        Route("/actions", actions, methods=["POST"]),
        Route("/api/config", api_config),
        Route("/api/changes", api_change, methods=["POST"]),
        Route("/api/proposals/{proposal_id}/approve", api_approve, methods=["POST"]),
        Route("/api/proposals/{proposal_id}/reject", api_reject, methods=["POST"]),
        Route("/api/audit", api_audit),
        Route("/api/history", api_history),
        Route("/auth/login", login),
        Route("/auth/callback", callback),
        Route("/auth/session", session, methods=["POST"]),
    ]
    app = Starlette(routes=routes)
    app.add_middleware(_AuthMiddleware, portal=portal)
    return app


def create_app_from_env() -> Starlette:
    from presidio_admin.key_vault import load_session_key, signer_from_env

    signer = signer_from_env(allow_sign=True)
    session_key = load_session_key()
    location = os.environ.get("PRM_CONFIG_STORE", "/data/store")
    if location.startswith("https://"):
        from presidio_admin.documents import imds_token

        client_id = os.environ.get("PRM_ADMIN_MI_CLIENT_ID", "")

        def token_provider() -> str:
            return imds_token(resource="https://storage.azure.com/", client_id=client_id)

        store = ConfigStore.open(location, signer=signer, token_provider=token_provider)
    else:
        store = ConfigStore(Path(location), signer=signer)
    try:
        active = store.read_active()
    except ConfigRejected as exc:
        if exc.reason_code != "published_config_missing":
            raise SystemExit(1) from exc
        active = store.bootstrap(default_config())
    logging.getLogger("presidio_admin").info(
        "published_config version_id=%s sha256=%s",
        active.version_id,
        active.sha256,
    )
    audience = os.environ.get("PRM_ADMIN_CLIENT_ID", "")
    if not audience:
        raise SystemExit(1)
    jwks_path = os.environ.get("PRM_ADMIN_JWKS_FILE")
    if jwks_path:
        import json

        jwks = json.loads(Path(jwks_path).read_text(encoding="utf-8"))
    else:
        jwks = httpx.get(f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys", timeout=10).json()
    tenant_id = os.environ.get("PRM_ADMIN_TENANT_ID", TENANT_ID)
    verifier = EntraVerifier(
        jwks=jwks,
        audience=audience,
        tenant_id=tenant_id,
        required_acrs=os.environ.get("PRM_ADMIN_ACRS", "c1"),
    )
    proxy_audit = _optional_key("PRM_PROXY_AUDIT_HMAC_KEY")
    portal = Portal(
        store=store,
        changes=ChangeService(store),
        verifier=verifier,
        session_key=session_key,
        cookie_secure=os.environ.get("PRM_ENV", "production") == "production",
        redirect_uri=os.environ.get("PRM_ADMIN_REDIRECT_URI", ""),
        assertion=assertion_from_env(client_id=audience, tenant_id=tenant_id),
        proxy_audit_key=proxy_audit,
    )
    return create_app(portal)


class _AuthMiddleware:
    def __init__(self, app: Starlette, portal: Portal) -> None:
        self.app = app
        self.portal = portal

    async def __call__(self, scope, receive, send) -> None:  # type: ignore[no-untyped-def]
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive)
        token_principal = _principal.set(None)
        token_csrf = _csrf.set("")
        try:
            if request.url.path not in PUBLIC:
                try:
                    principal, csrf = _resolve(self.portal, request)
                except AuthzError as exc:
                    status = _AUTHZ_STATUS.get(exc.reason_code, 403)
                    body = {"error": exc.reason_code}
                    if request.url.path.startswith("/api") or request.url.path == "/metrics":
                        response: Response = JSONResponse(body, status_code=status)
                    else:
                        response = HTMLResponse(login_page(), status_code=status)
                    await response(scope, receive, send)
                    return
                _principal.set(principal)
                _csrf.set(csrf)
            bearer = request.headers.get("authorization", "").lower().startswith("bearer ")
            refreshed = None
            if not bearer and request.url.path not in PUBLIC:
                refreshed = touch_session(request.cookies.get("prm_admin_session"), self.portal.session_key)

            async def send_refreshed(message):  # type: ignore[no-untyped-def]
                if refreshed and message["type"] == "http.response.start":
                    cookie = (
                        f"prm_admin_session={refreshed}; HttpOnly; Path=/; SameSite=strict; "
                        f"Max-Age={max(60, principal.expires_at - _unix_now())}"
                    )
                    if self.portal.cookie_secure:
                        cookie += "; Secure"
                    headers = list(message.get("headers") or [])
                    headers.append((b"set-cookie", cookie.encode("latin-1")))
                    message = {**message, "headers": headers}
                await send(message)

            await self.app(scope, receive, send_refreshed)
        finally:
            _principal.reset(token_principal)
            _csrf.reset(token_csrf)


def _resolve(portal: Portal, request: Request) -> tuple[Principal, str]:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        principal = portal.verifier.verify(header[7:].strip())
        return principal, ""
    opened = open_session(
        request.cookies.get("prm_admin_session"),
        portal.session_key,
        audience=portal.verifier.audience,
        tenant_id=portal.verifier.tenant_id,
        required_acrs=portal.verifier.required_acrs,
    )
    if opened is None:
        raise AuthzError("token_missing")
    return opened


def _require(request: Request) -> Principal:
    del request
    principal = _principal.get()
    if principal is None:
        raise AuthzError("token_missing")
    return principal


def _csrf_ok(request: Request, presented: str) -> bool:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return True
    expected = _csrf.get()
    if not expected or not presented:
        return False
    import hmac

    return hmac.compare_digest(expected, presented)


def _html(title: str, principal: Principal, body: str, request: Request, status: int = 200) -> HTMLResponse:
    notice = NOTICES.get(request.query_params.get("notice", ""), "")
    response = HTMLResponse(page(title=title, principal=principal, body=body, notice=notice), status_code=status)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'"
    return response


def _session_response(portal: Portal, principal: Principal, response: Response) -> Response:
    csrf = secrets.token_urlsafe(24)
    response.set_cookie(
        "prm_admin_session",
        seal_session(principal, csrf, portal.session_key, audience=portal.verifier.audience),
        httponly=True,
        secure=portal.cookie_secure,
        samesite="strict",
        max_age=max(60, principal.expires_at - _unix_now()),
        path="/",
    )
    response.headers["Cache-Control"] = "no-store"
    return response


def _patch_from_form(form) -> dict[str, object]:  # type: ignore[no-untyped-def]
    op = str(form.get("op") or "")
    if op in {"approve", "reject"}:
        return {"op": op}
    if op == "set_score_threshold":
        return {"op": op, "value": float(str(form.get("value")))}
    if op == "set_pattern_score":
        return {
            "op": op,
            "recognizer": str(form.get("recognizer") or ""),
            "pattern": str(form.get("pattern") or ""),
            "value": float(str(form.get("value"))),
        }
    if op == "add_client":
        return {
            "op": op,
            "client_id": str(form.get("client_id") or ""),
            "display_name": str(form.get("display_name") or ""),
            "app_role": str(form.get("app_role") or ""),
        }
    if op == "set_client_role":
        return {
            "op": op,
            "client_id": str(form.get("client_id") or ""),
            "app_role": str(form.get("app_role") or ""),
        }
    enabled = str(form.get("enabled") or "")
    if enabled not in {"true", "false"}:
        raise ApprovalError("change_rejected")
    patch: dict[str, object] = {"op": op, "enabled": enabled == "true"}
    for key in ("upstream", "tool", "recognizer", "pattern", "client_id"):
        if form.get(key):
            patch[key] = str(form.get(key))
    return patch


def _return_to(op: str) -> str:
    if op in {"approve", "reject"}:
        return "/proposals"
    if op in {"set_tool_enabled", "set_upstream_enabled"}:
        return "/upstreams"
    if op in {"add_client", "set_client_enabled", "set_client_role"}:
        return "/clients"
    if op in {"set_score_threshold", "set_pattern_score", "set_pattern_enabled"}:
        return "/recognizers"
    if op == "set_verifier":
        return "/verifier"
    return "/"


def _snap(item) -> dict[str, object]:  # type: ignore[no-untyped-def]
    return {
        "config_valid": item.config_valid,
        "chain_valid": item.chain_valid,
        "version_id": item.version_id,
        "tools_enabled": item.tools_enabled,
        "clients": item.clients,
        "verifier_enabled": item.verifier_enabled,
        "proposals_pending": item.proposals_pending,
        "score_threshold": item.score_threshold,
    }


def _named_key(name: str) -> bytes:
    file_path = os.environ.get(f"{name}_FILE")
    if file_path:
        raw = Path(file_path).read_text(encoding="utf-8").strip()
    else:
        raw = os.environ.get(name, "")
    if len(raw.encode("utf-8")) < 32 or raw.startswith("replace-with"):
        raise SystemExit(1)
    return raw.encode("utf-8")


def _optional_key(name: str) -> bytes:
    raw = os.environ.get(name, "")
    if not raw:
        return b""
    if len(raw.encode("utf-8")) < 32 or raw.startswith("replace-with"):
        raise SystemExit(1)
    return raw.encode("utf-8")


def _code_challenge(verifier: str) -> str:
    import base64
    import hashlib

    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def seal_pkce(key: bytes, state: str, verifier: str) -> str:
    from presidio_admin.authz import _sign

    return _sign({"state": state, "verifier": verifier, "exp": _unix_now() + 600, "iat": _unix_now()}, key)


def open_pkce(value: str | None, key: bytes) -> tuple[str, str] | None:
    from presidio_admin.authz import _open

    payload = _open(value, key)
    if not payload:
        return None
    if int(payload.get("exp") or 0) <= _unix_now():
        return None
    state = payload.get("state")
    verifier = payload.get("verifier")
    if not isinstance(state, str) or not isinstance(verifier, str):
        return None
    return state, verifier


async def _exchange(portal: Portal, code: str, verifier: str) -> str:
    if portal.assertion is None or not callable(portal.assertion):
        raise AuthzError("auth_not_configured")
    data = token_request_form(
        client_id=portal.verifier.audience,
        code=code,
        redirect_uri=portal.redirect_uri,
        code_verifier=verifier,
        assertion=portal.assertion(),
    )
    url = f"https://login.microsoftonline.com/{portal.verifier.tenant_id}/oauth2/v2.0/token"
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.post(url, data=data)
    if response.status_code != 200:
        raise AuthzError("token_invalid")
    token = response.json().get("access_token")
    if not isinstance(token, str):
        raise AuthzError("token_invalid")
    return token


def _unix_now() -> int:
    import time

    return int(time.time())

