"""Wire Presidio, mocks, and the two ingress apps."""

from __future__ import annotations

from dataclasses import dataclass

import httpx
from starlette.applications import Starlette

from presidio_redaction_mcp.app import create_app
from presidio_redaction_mcp.audit import AuditLog
from presidio_redaction_mcp.config import Settings, assert_verifier_permitted
from presidio_redaction_mcp.errors import ConfigError
from presidio_redaction_mcp.presidio_client import PresidioClient
from presidio_redaction_mcp.redact import Redactor
from presidio_redaction_mcp.service import RateLimiter, RedactionService
from presidio_redaction_mcp.upstream import MockUpstream
from presidio_redaction_mcp.verifier import ClaudeVerifier


@dataclass
class Runtime:
    settings: Settings
    audit: AuditLog
    presidio: PresidioClient
    upstreams: dict[str, MockUpstream]
    service: RedactionService
    verifier: ClaudeVerifier | None
    cloudflare_app: Starlette
    vpn_app: Starlette


def build_runtime(
    settings: Settings,
    audit: AuditLog,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    upstreams: dict[str, MockUpstream] | None = None,
    allowed_hosts: list[str] | None = None,
    rate_limiter: RateLimiter | None = None,
    anthropic_api_key: str | None = None,
    verifier_transport: httpx.AsyncBaseTransport | None = None,
) -> Runtime:
    presidio = PresidioClient(
        analyzer_url=settings.allowlist.presidio.analyzer_url,
        anonymizer_url=settings.allowlist.presidio.anonymizer_url,
        recognizers=settings.recognizers,
        timeout_seconds=settings.allowlist.presidio.timeout_seconds,
        score_threshold=settings.allowlist.presidio.score_threshold,
        egress_check=settings.egress.check,
        transport=transport,
        ca_file=settings.presidio_ca_file,
        require_https=settings.env == "production",
    )
    if upstreams is None:
        upstreams = {
            name: MockUpstream(name=name, base_url=spec.base_url)
            for name, spec in settings.allowlist.upstreams.items()
        }
    assert_verifier_permitted(settings)
    verifier: ClaudeVerifier | None = None
    if settings.allowlist.verifier.enabled:
        if not anthropic_api_key:
            raise ConfigError("anthropic_key_missing")
        verifier = ClaudeVerifier(
            api_key=anthropic_api_key,
            model=settings.allowlist.verifier.model,
            timeout_seconds=settings.allowlist.verifier.timeout_seconds,
            max_tokens=settings.allowlist.verifier.max_tokens,
            egress_check=settings.egress.check,
            transport=verifier_transport,
        )
    service = RedactionService(
        settings=settings,
        audit=audit,
        redactor=Redactor(presidio, settings.recognizers, settings.allowlist.max_payload_bytes),
        upstreams=upstreams,
        rate_limiter=rate_limiter,
        verifier=verifier,
    )
    hosts = allowed_hosts or [
        "127.0.0.1",
        "127.0.0.1:*",
        "localhost",
        "localhost:*",
        "testserver",
        "testserver:*",
    ]
    shared = {
        "settings": settings,
        "audit": audit,
        "service": service,
        "allowed_hosts": hosts,
    }
    return Runtime(
        settings=settings,
        audit=audit,
        presidio=presidio,
        upstreams=upstreams,
        service=service,
        verifier=verifier,
        cloudflare_app=create_app(ingress="cloudflare", **shared),
        vpn_app=create_app(ingress="vpn", **shared),
    )
