"""Wire Presidio, mocks, and the ingress apps."""

from __future__ import annotations

from dataclasses import dataclass

import httpx
from starlette.applications import Starlette

from presidio_redaction_mcp.app import create_app
from presidio_redaction_mcp.audit import AuditLog
from presidio_redaction_mcp.config import Settings, assert_verifier_permitted
from presidio_redaction_mcp.entra import EntraTokenVerifier
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
    vpn_app: Starlette
    private_app: Starlette | None = None


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
    entra: EntraTokenVerifier | None = None,
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
    limits = settings.allowlist.limits
    service = RedactionService(
        settings=settings,
        audit=audit,
        redactor=Redactor(
            presidio,
            settings.recognizers,
            settings.allowlist.max_payload_bytes,
            max_depth=limits.max_depth,
            max_nodes=limits.max_nodes,
            max_strings=limits.max_strings,
            max_list_items=limits.max_list_items,
            max_presidio_calls=limits.max_presidio_calls,
        ),
        upstreams=upstreams,
        rate_limiter=rate_limiter,
        verifier=verifier,
    )
    listeners = settings.allowlist.listeners
    _reject_testserver(listeners.vpn_allowed_hosts)
    if entra is None and settings.auth_mode == "entra":
        entra = EntraTokenVerifier(
            audience=settings.entra_audience,
            clients=settings.entra_clients,
            jwks_fetcher=_live_jwks,
        )
    shared = {
        "settings": settings,
        "audit": audit,
        "service": service,
        "entra": entra,
    }
    private_app = None
    if entra is not None:
        private_app = create_app(
            ingress="private",
            allowed_hosts=_hosts(
                ["127.0.0.1", "127.0.0.1:*"],
                test_mode=settings.env == "test",
                override=allowed_hosts,
            ),
            **shared,
        )
    return Runtime(
        settings=settings,
        audit=audit,
        presidio=presidio,
        upstreams=upstreams,
        service=service,
        verifier=verifier,
        vpn_app=create_app(
            ingress="vpn",
            allowed_hosts=_hosts(
                list(listeners.vpn_allowed_hosts),
                test_mode=settings.env == "test",
                override=allowed_hosts,
            ),
            **shared,
        ),
        private_app=private_app,
    )


def _hosts(configured: list[str], *, test_mode: bool, override: list[str] | None) -> list[str]:
    hosts = list(override or configured)
    if test_mode:
        for item in ("testserver", "testserver:*"):
            if item not in hosts:
                hosts.append(item)
    return hosts


def _live_jwks() -> dict:
    import httpx

    from presidio_redaction_mcp.entra import PINNED_TENANT_ID

    url = f"https://login.microsoftonline.com/{PINNED_TENANT_ID}/discovery/v2.0/keys"
    try:
        response = httpx.get(url, timeout=5.0)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        from presidio_redaction_mcp.errors import AuthError

        raise AuthError("jwks_fetch_failed") from exc
    if not isinstance(payload, dict):
        from presidio_redaction_mcp.errors import AuthError

        raise AuthError("jwks_fetch_failed")
    return payload


def _reject_testserver(hosts: list[str]) -> None:
    if any("testserver" in host.lower() for host in hosts):
        raise ConfigError("testserver_not_allowed")
