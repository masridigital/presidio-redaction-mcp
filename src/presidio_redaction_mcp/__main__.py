"""Serve the Azure private listener. Lab mode is the VPN bearer listener only."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import uvicorn

from presidio_redaction_mcp.audit import AuditLog
from presidio_redaction_mcp.config import assert_published_store, load_settings
from presidio_redaction_mcp.factory import build_runtime
from presidio_redaction_mcp.key_vault import resolve_verifier_key
from presidio_redaction_mcp.logging_setup import configure_logging
from presidio_redaction_mcp.published_config import log_published


def main() -> None:
    config_path = Path(os.environ.get("PRM_CONFIG", "/etc/presidio-redaction-mcp/allowlist.yaml"))
    settings = load_settings(config_path)
    published_tools: frozenset[str] | None = None
    published = None
    store_dir = os.environ.get("PRM_CONFIG_STORE")
    from presidio_redaction_mcp.errors import ConfigError

    try:
        assert_published_store(settings, store_dir)
    except ConfigError:
        raise SystemExit(1) from None
    if store_dir:
        from presidio_redaction_mcp.published_config import apply_published, load_published_or_fail

        store_key = _hmac_env("PRM_STORE_HMAC_KEY")
        audit_key = _hmac_env("PRM_ADMIN_AUDIT_HMAC_KEY")
        _distinct_store_keys(store_key, audit_key, settings.audit_hmac_key)
        try:
            published = load_published_or_fail(
                store_dir,
                store_key=store_key,
                audit_key=audit_key,
            )
            settings = apply_published(settings, published)
        except ConfigError:
            raise SystemExit(1) from None
        published_tools = frozenset(published.config.enabled_tools())
    configure_logging(settings.recognizers, os.environ.get("LOG_LEVEL", "INFO"), settings.secret_values)
    if published is not None:
        log_published(published.version_id, published.sha256)
    audit = AuditLog(
        Path(os.environ.get("PRM_AUDIT_PATH", "/var/lib/presidio-redaction-mcp/audit/audit.jsonl")),
        Path(os.environ.get("PRM_AUDIT_STATE", "/var/lib/presidio-redaction-mcp/audit/config-sha")),
        settings.audit_hmac_key,
        forward=settings.audit_forward,
    )
    api_key = resolve_verifier_key(settings) if settings.allowlist.verifier.enabled else None
    runtime = build_runtime(
        settings,
        audit,
        anthropic_api_key=api_key,
        published_tools=published_tools,
    )
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


def _distinct_store_keys(store_key: bytes, audit_key: bytes, proxy_audit_key: bytes) -> None:
    """The store, the admin audit chain, and the proxy tool-call audit use different keys."""
    if len({store_key, audit_key, proxy_audit_key}) != 3:
        raise SystemExit(1)


def _hmac_env(name: str) -> bytes:
    file_path = os.environ.get(f"{name}_FILE")
    if file_path:
        raw = Path(file_path).read_bytes().strip()
    else:
        raw = os.environ.get(name, "").encode("utf-8")
    if len(raw) < 32 or raw.startswith(b"replace-with"):
        raise SystemExit(1)
    return raw


if __name__ == "__main__":
    main()
