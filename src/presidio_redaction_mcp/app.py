"""Streamable HTTP MCP application with ingress-bound bearer auth."""

from __future__ import annotations

import contextlib
import json
from collections.abc import AsyncIterator
from contextvars import ContextVar
from typing import Any

import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route
from starlette.types import ASGIApp, Receive, Scope, Send

from presidio_redaction_mcp.audit import AuditLog
from presidio_redaction_mcp.auth import CallerIdentity, authenticate
from presidio_redaction_mcp.config import Settings, ToolSpec
from presidio_redaction_mcp.errors import AuthError
from presidio_redaction_mcp.service import RedactionService

caller_var: ContextVar[CallerIdentity | None] = ContextVar("prm_caller", default=None)


def create_app(
    *,
    settings: Settings,
    ingress: str,
    audit: AuditLog,
    service: RedactionService,
    allowed_hosts: list[str],
) -> Starlette:
    mcp_server = Server("presidio-redaction-mcp")
    tools = _tool_models(settings)

    @mcp_server.list_tools()
    async def list_tools() -> list[types.Tool]:
        if caller_var.get() is None:
            return []
        return tools

    @mcp_server.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        caller = caller_var.get()
        if caller is None:
            text = json.dumps({"error": "blocked", "reason_code": "auth_context_missing"}, sort_keys=True)
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=text)],
                isError=True,
            )
        text = await service.call_tool(caller, name, arguments)
        is_error = json.loads(text).get("error") == "blocked"
        return types.CallToolResult(
            content=[types.TextContent(type="text", text=text)],
            isError=is_error,
        )

    session_manager = StreamableHTTPSessionManager(
        app=mcp_server,
        json_response=True,
        stateless=True,
        security_settings=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts,
            allowed_origins=[],
        ),
        max_request_body_size=settings.allowlist.max_payload_bytes,
    )

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        audit.note_config(settings.config_sha256)
        async with session_manager.run():
            yield

    mcp_app = _SessionApp(session_manager)
    protected = _IngressAuth(
        mcp_app,
        settings=settings,
        ingress=ingress,
        audit=audit,
    )

    async def health(_: Any) -> JSONResponse:
        return JSONResponse({"status": "ok"})

    return Starlette(
        routes=[
            Route("/healthz", health, methods=["GET"]),
            Mount("/mcp", app=protected),
        ],
        lifespan=lifespan,
    )


class _SessionApp:
    def __init__(self, session_manager: StreamableHTTPSessionManager) -> None:
        self.session_manager = session_manager

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self.session_manager.handle_request(scope, receive, send)


class _IngressAuth:
    def __init__(self, app: ASGIApp, *, settings: Settings, ingress: str, audit: AuditLog) -> None:
        self.app = app
        self.settings = settings
        self.ingress = ingress
        self.audit = audit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in scope.get("headers", [])}
        try:
            caller = authenticate(
                self.settings.callers,
                ingress=self.ingress,
                authorization=headers.get("authorization"),
                cf_client_id=headers.get("cf-access-client-id"),
                cf_client_secret=headers.get("cf-access-client-secret"),
            )
        except AuthError as exc:
            self.audit.record(
                caller="unknown",
                ingress=self.ingress,
                phi_capable=None,
                upstream=None,
                tool=None,
                args_hmac=None,
                entity_counts={},
                decision="deny",
                reason_code=exc.reason_code,
                latency_ms=0,
                config_sha256=self.settings.config_sha256,
            )
            response = JSONResponse(
                {"error": "unauthorized", "reason_code": exc.reason_code},
                status_code=401,
            )
            await response(scope, receive, send)
            return
        token = caller_var.set(caller)
        try:
            await self.app(scope, receive, send)
        finally:
            caller_var.reset(token)


def _tool_models(settings: Settings) -> list[types.Tool]:
    models: list[types.Tool] = []
    for _name, upstream in settings.allowlist.upstreams.items():
        for spec in upstream.tools:
            models.append(
                types.Tool(
                    name=spec.name,
                    description=spec.description,
                    inputSchema=_schema(spec),
                )
            )
    return models


def _schema(spec: ToolSpec) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    for arg in spec.arguments:
        if arg.type == "integer":
            schema: dict[str, Any] = {"type": "integer"}
            if arg.name == "limit":
                schema["minimum"] = 1
                schema["maximum"] = spec.max_items
        else:
            schema = {"type": "string"}
            if arg.max_length is not None:
                schema["maxLength"] = arg.max_length
            if arg.pattern is not None:
                schema["pattern"] = arg.pattern
        properties[arg.name] = schema
    return {"type": "object", "additionalProperties": False, "properties": properties}
