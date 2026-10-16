"""Serve the Cloudflare listener and the VPN listener over TLS."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import uvicorn

from presidio_redaction_mcp.audit import AuditLog
from presidio_redaction_mcp.config import load_settings
from presidio_redaction_mcp.factory import build_runtime
from presidio_redaction_mcp.logging_setup import configure_logging


def main() -> None:
    config_path = Path(os.environ.get("PRM_CONFIG", "/app/config/allowlist.yaml"))
    settings = load_settings(config_path)
    configure_logging(settings.recognizers, os.environ.get("LOG_LEVEL", "INFO"))
    audit = AuditLog(
        Path(os.environ.get("PRM_AUDIT_PATH", "/var/lib/presidio-redaction-mcp/audit/audit.jsonl")),
        Path(os.environ.get("PRM_AUDIT_STATE", "/var/lib/presidio-redaction-mcp/audit/config-sha")),
    )
    runtime = build_runtime(settings, audit)
    bind_host = os.environ.get("PRM_BIND_HOST", "127.0.0.1")
    vpn_host = os.environ.get("PRM_VPN_BIND_HOST", bind_host)
    cf_port = int(os.environ.get("PRM_CF_PORT", "8443"))
    vpn_port = int(os.environ.get("PRM_VPN_PORT", "8444"))
    ssl_kwargs = {
        "ssl_certfile": settings.tls_cert_file,
        "ssl_keyfile": settings.tls_key_file,
    }
    if settings.env == "production" and (not settings.tls_cert_file or not settings.tls_key_file):
        raise SystemExit(1)

    async def serve() -> None:
        cf_server = uvicorn.Server(
            uvicorn.Config(
                runtime.cloudflare_app,
                host=bind_host,
                port=cf_port,
                log_level="info",
                access_log=False,
                **ssl_kwargs,
            )
        )
        vpn_server = uvicorn.Server(
            uvicorn.Config(
                runtime.vpn_app,
                host=vpn_host,
                port=vpn_port,
                log_level="info",
                access_log=False,
                **ssl_kwargs,
            )
        )
        await asyncio.gather(cf_server.serve(), vpn_server.serve())

    asyncio.run(serve())


if __name__ == "__main__":
    main()
