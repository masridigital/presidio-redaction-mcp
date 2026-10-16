"""Serve the Azure private listener. Lab mode is the VPN bearer listener only."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import uvicorn

from presidio_redaction_mcp.audit import AuditLog
from presidio_redaction_mcp.config import load_settings
from presidio_redaction_mcp.factory import build_runtime
from presidio_redaction_mcp.key_vault import resolve_verifier_key
from presidio_redaction_mcp.logging_setup import configure_logging


def main() -> None:
    config_path = Path(os.environ.get("PRM_CONFIG", "/etc/presidio-redaction-mcp/allowlist.yaml"))
    settings = load_settings(config_path)
    configure_logging(settings.recognizers, os.environ.get("LOG_LEVEL", "INFO"), settings.secret_values)
    audit = AuditLog(
        Path(os.environ.get("PRM_AUDIT_PATH", "/var/lib/presidio-redaction-mcp/audit/audit.jsonl")),
        Path(os.environ.get("PRM_AUDIT_STATE", "/var/lib/presidio-redaction-mcp/audit/config-sha")),
        settings.audit_hmac_key,
        forward=settings.audit_forward,
    )
    api_key = resolve_verifier_key(settings) if settings.allowlist.verifier.enabled else None
    runtime = build_runtime(settings, audit, anthropic_api_key=api_key)
    if settings.env == "production" and settings.auth_mode != "entra":
        raise SystemExit(1)
    if settings.auth_mode == "entra":
        _serve_azure(runtime.private_app)
        return
    _serve_lab(runtime, settings)


def _serve_azure(app: object) -> None:
    if app is None or os.environ.get("PRM_AZURE_INTERNAL") != "1":
        raise SystemExit(1)
    bind_host = os.environ.get("PRM_BIND_HOST", "0.0.0.0")  # nosec B104
    port = int(os.environ.get("PRM_PORT", "8080"))
    if bind_host in {"", "::"}:
        raise SystemExit(1)
    uvicorn.run(app, host=bind_host, port=port, access_log=False, log_level="info")  # type: ignore[arg-type]


def _serve_lab(runtime: object, settings: object) -> None:
    if getattr(settings, "env", "") == "production" or getattr(settings, "auth_mode", "") == "entra":
        raise SystemExit(1)
    vpn_host = os.environ.get("PRM_VPN_BIND_HOST", "10.8.0.1")
    vpn_port = int(os.environ.get("PRM_VPN_PORT", "8444"))
    if vpn_host in {"0.0.0.0", "::", ""}:  # nosec B104
        raise SystemExit(1)
    tls_cert = getattr(settings, "tls_cert_file", None)
    tls_key = getattr(settings, "tls_key_file", None)
    ssl_kwargs = {"ssl_certfile": tls_cert, "ssl_keyfile": tls_key}

    async def serve() -> None:
        vpn_server = uvicorn.Server(
            uvicorn.Config(
                runtime.vpn_app,  # type: ignore[attr-defined]
                host=vpn_host,
                port=vpn_port,
                log_level="info",
                access_log=False,
                **ssl_kwargs,
            )
        )
        await vpn_server.serve()

    asyncio.run(serve())


if __name__ == "__main__":
    main()
