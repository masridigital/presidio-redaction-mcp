"""Load and reject anything outside the day-1 StackJack and Composio allowlist."""

from __future__ import annotations

import hashlib
import math
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from presidio_redaction_mcp.auth import CallerSecret, digest
from presidio_redaction_mcp.egress import EgressPolicy
from presidio_redaction_mcp.errors import ConfigError
from presidio_redaction_mcp.recognizers import RecognizerSet, load_recognizers
from presidio_redaction_mcp.verifier_policy import model_allowed

ALLOWED_UPSTREAMS = frozenset({"stackjack", "composio"})
MAX_PAGE_ITEMS = 20
_NAME = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")
# Static descriptions only. Instruction-override text is a poisoned tool definition.
_POISONED_DESCRIPTION = re.compile(
    r"(?i)(?:"
    r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions"
    r"|disregard\s+(?:all\s+)?(?:previous|prior|above)"
    r"|you\s+are\s+now"
    r"|system\s+prompt"
    r"|jailbreak"
    r"|exfiltrate"
    r"|override\s+(?:the\s+|your\s+)?instructions"
    r"|<\s*\|im_start\|\s*>"
    r"|</?\s*system\s*>"
    r")"
)
_WILDCARD = re.compile(r"[\*\?\[\]]|(?:^|[_\-])all(?:[_\-]|$)")
_LIST_ALL = re.compile(r"list[_-]?all", re.IGNORECASE)
_READ_VERB = re.compile(
    r"(?:^|[_\-])(get|list|search|health|status|fetch)(?:[_\-]|$)",
    re.IGNORECASE,
)
_WRITE_TOKEN = re.compile(
    r"(?:^|[_\-])(post|put|patch|delete|bulk|send|create|update|remove|execute|reply|forward|share|add|edit|new|write)(?:[_\-]|$)",
    re.IGNORECASE,
)
_PLACEHOLDER = re.compile(
    r"replace-with|changeme|placeholder|not-a-secret|configure-before-deploy",
    re.IGNORECASE,
)
_GUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_ACCOUNT = re.compile(r"^ca_[a-z0-9_]{8,64}$")


class ArgSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    type: Literal["string", "integer"]
    pattern: str | None = None
    max_length: int | None = Field(default=None, ge=1, le=500)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        _reject_identifier(value, field="argument")
        return value

    @field_validator("pattern")
    @classmethod
    def _pattern(cls, value: str | None) -> str | None:
        if value is None:
            return value
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError("argument_pattern_invalid") from exc
        return value


class ToolSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str
    description_sha256: str
    rationale: str
    read_only: Literal[True]
    phi_scope: Literal["none"]
    max_items: int = Field(ge=1, le=MAX_PAGE_ITEMS)
    allowed_result_fields: list[str]
    arguments: list[ArgSpec]
    toolkit: str | None = None
    action_id: str | None = None
    connected_account_id: str | None = None

    @field_validator("name", "action_id")
    @classmethod
    def _tool_names(cls, value: str | None) -> str | None:
        if value is None:
            return value
        _reject_identifier(value, field="tool")
        return value

    @field_validator("toolkit")
    @classmethod
    def _toolkit(cls, value: str | None) -> str | None:
        if value is None:
            return value
        _reject_identifier(value, field="toolkit")
        return value

    @model_validator(mode="after")
    def _pin_description(self) -> ToolSpec:
        if _POISONED_DESCRIPTION.search(self.description):
            raise ValueError("tool_description_poisoned")
        digest = hashlib.sha256(self.description.encode("utf-8")).hexdigest()
        if _SHA256.fullmatch(self.description_sha256) is None or digest != self.description_sha256:
            raise ValueError("tool_description_hash_mismatch")
        return self

    @field_validator("allowed_result_fields")
    @classmethod
    def _fields(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("field_allowlist_empty")
        for item in value:
            _reject_identifier(item, field="field")
        return value


class UpstreamSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["stackjack", "composio"]
    mode: Literal["mock"]
    base_url: str
    tools: list[ToolSpec]

    @field_validator("base_url")
    @classmethod
    def _url(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("upstream_url_must_be_https")
        if "cloudflare" in value.lower() or "trycloudflare" in value.lower():
            raise ValueError("upstream_must_not_use_cloudflare")
        return value


# grok-bot stays usable on structured fields. Free text, dates, and IPs are
# dropped before redaction. A hit that remains in an allowed field is still blocked.
_GROK_TOOLS = frozenset(
    {
        "stackjack_health_check",
        "stackjack_get_service_status",
        "UPTIMEROBOT_GET_MONITORS",
    }
)
_GROK_DENIED_FIELDS = frozenset(
    {
        "summary",
        "description",
        "text",
        "body",
        "url",
        "friendly_name",
        "date",
        "datetime",
        "created_at",
        "updated_at",
        "timestamp",
        "dob",
        "ip",
        "ip_address",
        "client_ip",
    }
)


class CallerSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    phi_capable: bool
    # Entra app ids of callers with baa true are the result-mask allowlist.
    baa: bool = False
    allowed_ingress: list[Literal["external-nonphi", "vpn"]]
    token_secret: str
    allowed_tools: list[str] = Field(default_factory=list)
    denied_result_fields: list[str] = Field(default_factory=list)


class DeploymentSpec(BaseModel):
    """Where this process is allowed to run. Only Azure may be marked BAA."""

    model_config = ConfigDict(extra="forbid")

    target: Literal["azure", "cloudflare", "non-baa"]
    baa: bool

    @model_validator(mode="after")
    def _mark(self) -> DeploymentSpec:
        if self.baa and self.target != "azure":
            raise ValueError("baa_mark_requires_azure_target")
        return self


class VerifierSpec(BaseModel):
    """Optional Claude second pass. Off unless a BAA deployment enables it."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    model: str = "claude-sonnet-4-5"
    timeout_seconds: float = Field(default=8.0, gt=0, le=30)
    max_tokens: int = Field(default=256, ge=64, le=1024)
    key_vault_url: str | None = None
    key_vault_secret: str | None = None

    @field_validator("model")
    @classmethod
    def _model(cls, value: str) -> str:
        if not model_allowed(value):
            raise ValueError("verifier_model_not_allowlisted")
        return value

    @field_validator("key_vault_url")
    @classmethod
    def _vault(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not re.fullmatch(r"https://[a-z0-9-]{3,24}\.vault\.azure\.net", value):
            raise ValueError("key_vault_url_rejected")
        return value

    @field_validator("key_vault_secret")
    @classmethod
    def _secret_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not re.fullmatch(r"[A-Za-z0-9-]{1,127}", value):
            raise ValueError("key_vault_secret_rejected")
        return value


class PresidioSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analyzer_url: str
    anonymizer_url: str
    timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    score_threshold: float = Field(default=0.4, ge=0.4, le=1)


class EgressSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    upstream_hosts: list[str]
    presidio_hosts: list[str]
    test_hosts: list[str] = Field(default_factory=list)


class ListenerSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vpn_cidr: str = "10.8.0.0/24"
    vpn_allowed_hosts: list[str]

    @field_validator("vpn_allowed_hosts")
    @classmethod
    def _hosts(cls, value: list[str]) -> list[str]:
        if not value:
            raise ValueError("allowed_hosts_empty")
        for host in value:
            lowered = host.lower()
            if "testserver" in lowered or lowered in {"*", "0.0.0.0", "0.0.0.0:*"}:  # nosec B104
                raise ValueError("allowed_host_rejected")
        return value

    @field_validator("vpn_cidr")
    @classmethod
    def _cidr(cls, value: str) -> str:
        import ipaddress

        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError("vpn_cidr_invalid") from exc
        if network.version != 4:
            raise ValueError("vpn_cidr_invalid")
        return str(network)


class LimitSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requests_per_minute: int = Field(default=120, ge=1, le=600)
    max_depth: int = Field(default=6, ge=1, le=16)
    max_nodes: int = Field(default=200, ge=1, le=2000)
    max_strings: int = Field(default=80, ge=1, le=500)
    max_list_items: int = Field(default=20, ge=1, le=MAX_PAGE_ITEMS)
    max_presidio_calls: int = Field(default=400, ge=1, le=2000)


class AllowlistFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    require_published_config: bool = True
    upstreams: dict[str, UpstreamSpec]
    callers: dict[str, CallerSpec]
    presidio: PresidioSpec
    egress: EgressSpec
    deployment: DeploymentSpec
    verifier: VerifierSpec = Field(default_factory=VerifierSpec)
    listeners: ListenerSpec
    limits: LimitSpec = Field(default_factory=LimitSpec)
    recognizers_file: str
    max_payload_bytes: int = Field(default=262144, gt=0, le=1_000_000)

    @model_validator(mode="after")
    def _upstreams(self) -> AllowlistFile:
        if set(self.upstreams) != ALLOWED_UPSTREAMS:
            raise ValueError("upstreams_must_be_exactly_stackjack_and_composio")
        for name, upstream in self.upstreams.items():
            if upstream.kind != name:
                raise ValueError("upstream_kind_mismatch")
        names: set[str] = set()
        for name, upstream in self.upstreams.items():
            for tool in upstream.tools:
                if tool.name in names:
                    raise ValueError("duplicate_tool")
                names.add(tool.name)
                if name == "composio":
                    if not tool.toolkit or not tool.action_id or not tool.connected_account_id:
                        raise ValueError("composio_tool_pin_incomplete")
                    if not _ACCOUNT.match(tool.connected_account_id):
                        raise ValueError("connected_account_id_invalid")
                    if tool.action_id != tool.name:
                        raise ValueError("composio_action_must_match_tool_name")
                else:
                    if tool.toolkit or tool.action_id or tool.connected_account_id:
                        raise ValueError("stackjack_tool_must_not_pin_composio_fields")
        if "grok-bot" not in self.callers or "claude-local" not in self.callers or "open-webui" not in self.callers:
            raise ValueError("required_caller_missing")
        grok = self.callers["grok-bot"]
        if grok.phi_capable or grok.baa or grok.allowed_ingress != ["external-nonphi"]:
            raise ValueError("grok_bot_must_be_external_nonphi")
        if set(grok.allowed_tools) != _GROK_TOOLS:
            raise ValueError("grok_bot_tools_must_be_structured")
        if not _GROK_DENIED_FIELDS <= set(grok.denied_result_fields):
            raise ValueError("grok_bot_free_text_fields_required")
        for caller in self.callers.values():
            if "external-nonphi" in caller.allowed_ingress and caller.phi_capable:
                raise ValueError("external_nonphi_cannot_be_phi_capable")
        claude = self.callers["claude-local"]
        if not claude.phi_capable or not claude.baa or claude.allowed_ingress != ["vpn"]:
            raise ValueError("phi_caller_must_be_vpn_only")
        if claude.allowed_tools or claude.denied_result_fields:
            raise ValueError("phi_caller_uses_the_shared_allowlist")
        webui = self.callers["open-webui"]
        # local-ai-stack has not cleared Open WebUI for PHI. Keep it non-BAA.
        if webui.phi_capable or webui.baa or webui.allowed_ingress != ["vpn"]:
            raise ValueError("open_webui_not_cleared_for_phi")
        if set(self.egress.upstream_hosts) != {"stackjack.invalid", "composio.invalid"}:
            raise ValueError("egress_upstreams_must_be_phase1_pins")
        if self.verifier.enabled and (self.deployment.target != "azure" or not self.deployment.baa):
            raise ValueError("verifier_refused_non_baa_target")
        return self


class Settings(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    env: str
    config_path: Path
    config_sha256: str
    allowlist: AllowlistFile
    recognizers: RecognizerSet
    callers: tuple[CallerSecret, ...]
    egress: EgressPolicy
    audit_hmac_key: bytes
    secret_values: tuple[str, ...] = ()
    tls_cert_file: str | None
    tls_key_file: str | None
    presidio_ca_file: str | None
    audit_forward: str | None = None
    auth_mode: str = "bearer"
    entra_audience: str = ""
    entra_clients: tuple[Any, ...] = ()
    baa_client_ids: frozenset[str] = frozenset()
    published_version_id: int | None = None
    published_sha256: str = ""


def assert_published_store(settings: Settings, store_dir: str | None) -> None:
    """Production always requires the published store. Entra mode does when the flag is on.

    The flag defaults on. Production forces it even if the file says false.
    """
    forced = settings.env == "production"
    if not forced and not settings.allowlist.require_published_config:
        return
    if not forced and settings.auth_mode != "entra":
        return
    if not store_dir:
        raise ConfigError("published_config_required")


def assert_verifier_permitted(source: Settings | AllowlistFile) -> None:
    """Refuse to enable the verifier when the deployment target is marked non-BAA."""
    allowlist = source.allowlist if isinstance(source, Settings) else source
    if not allowlist.verifier.enabled:
        return
    if allowlist.deployment.target != "azure" or not allowlist.deployment.baa:
        raise ConfigError("verifier_refused_non_baa_target")


def _apply_presidio_url_overrides(parsed: AllowlistFile) -> AllowlistFile:
    analyzer = os.environ.get("PRM_ANALYZER_URL", "").strip()
    anonymizer = os.environ.get("PRM_ANONYMIZER_URL", "").strip()
    if not analyzer and not anonymizer:
        return parsed
    if not analyzer or not anonymizer:
        raise ConfigError("presidio_url_pair_required")
    presidio = parsed.presidio.model_copy(update={"analyzer_url": analyzer, "anonymizer_url": anonymizer})
    return parsed.model_copy(update={"presidio": presidio})


def _entra_clients(parsed: AllowlistFile) -> tuple[str, tuple[Any, ...]]:
    from presidio_redaction_mcp.entra import PINNED_TENANT_ID, EntraClient

    tenant = os.environ.get("PRM_ENTRA_TENANT_ID", PINNED_TENANT_ID).strip().lower()
    if tenant != PINNED_TENANT_ID:
        raise ConfigError("entra_tenant_unpinned")
    audience = os.environ.get("PRM_ENTRA_AUDIENCE", "").strip()
    lowered = audience.lower()
    if not audience or "common" in lowered or "organizations" in lowered:
        raise ConfigError("entra_audience_invalid")
    specs = (
        ("claude-local", "PRM_ENTRA_CLIENT_CLAUDE", True),
        ("open-webui", "PRM_ENTRA_CLIENT_OPEN_WEBUI", True),
        ("grok-bot", "PRM_ENTRA_CLIENT_GROK", False),
    )
    clients = []
    for name, key, human in specs:
        app_id = os.environ.get(key, "").strip().lower()
        if _GUID.fullmatch(app_id) is None:
            raise ConfigError("entra_client_missing")
        caller = parsed.callers[name]
        clients.append(EntraClient(name=name, app_id=app_id, phi_capable=caller.phi_capable, human=human))
    if len({client.app_id for client in clients}) != len(clients):
        raise ConfigError("entra_client_duplicate")
    return audience, tuple(clients)


def load_settings(config_path: Path, *, env: str | None = None) -> Settings:
    env_name = env or os.environ.get("PRM_ENV", "production")
    raw_bytes = config_path.read_bytes()
    try:
        parsed = AllowlistFile.model_validate(yaml.safe_load(raw_bytes))
    except Exception as exc:
        if "verifier_refused_non_baa_target" in str(exc):
            raise ConfigError("verifier_refused_non_baa_target") from exc
        if "external_nonphi_cannot_be_phi_capable" in str(exc):
            raise ConfigError("external_nonphi_cannot_be_phi_capable") from exc
        raise ConfigError("allowlist_rejected") from exc
    assert_verifier_permitted(parsed)
    recognizer_path = config_path.parent / parsed.recognizers_file
    if not recognizer_path.is_file():
        recognizer_path = config_path.parent.parent / parsed.recognizers_file
    recognizers = load_recognizers(recognizer_path)
    secrets = {name: _read_secret(name, env_name=env_name) for name in _secret_names(parsed)}
    _reject_duplicate_secrets(secrets)
    hmac_key = secrets["audit_hmac_key"].encode("utf-8")
    callers = tuple(_caller_secret(name, spec, secrets) for name, spec in parsed.callers.items())
    _reject_duplicate_caller_tokens(callers)
    auth_mode = os.environ.get("PRM_AUTH_MODE", "bearer").strip() or "bearer"
    if auth_mode not in {"bearer", "entra"}:
        raise ConfigError("auth_mode_invalid")
    if env_name == "production" and auth_mode != "entra":
        raise ConfigError("entra_required")
    azure_internal = os.environ.get("PRM_AZURE_INTERNAL") == "1"
    parsed = _apply_presidio_url_overrides(parsed)
    if auth_mode == "entra":
        entra_audience, entra_clients = _entra_clients(parsed)
    else:
        entra_audience, entra_clients = "", ()
    baa_client_ids = frozenset(
        client.app_id.lower() for client in entra_clients if parsed.callers[client.name].baa
    )
    if env_name == "production":
        for url in (parsed.presidio.analyzer_url, parsed.presidio.anonymizer_url):
            if azure_internal and url.startswith("http://127.0.0.1"):
                continue
            if not url.startswith("https://"):
                raise ConfigError("presidio_must_be_https")
        if set(parsed.egress.presidio_hosts) != {"127.0.0.1"}:
            raise ConfigError("presidio_must_be_loopback")
        tls_cert, tls_key, ca_file = _tls_paths()
        if auth_mode != "entra" or not entra_audience or not entra_clients:
            raise ConfigError("entra_required" if auth_mode != "entra" else "entra_not_configured")
        if not azure_internal:
            for path in (tls_cert, tls_key, ca_file):
                if not path or not Path(path).is_file():
                    raise ConfigError("tls_material_missing")
    else:
        tls_cert, tls_key, ca_file = _tls_paths()
    forward = os.environ.get("PRM_AUDIT_FORWARD", "").strip() or None
    if forward is not None and forward != "syslog" and not forward.startswith("file:"):
        raise ConfigError("audit_forward_invalid")
    egress = EgressPolicy(
        upstream_hosts=frozenset(parsed.egress.upstream_hosts),
        presidio_hosts=frozenset(parsed.egress.presidio_hosts),
        test_hosts=frozenset(parsed.egress.test_hosts),
        allow_test_hosts=env_name == "test",
    )
    egress.check(parsed.presidio.analyzer_url, purpose="presidio")
    egress.check(parsed.presidio.anonymizer_url, purpose="presidio")
    for upstream in parsed.upstreams.values():
        egress.check(upstream.base_url, purpose="upstream")
    return Settings(
        env=env_name,
        config_path=config_path,
        config_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        allowlist=parsed,
        recognizers=recognizers,
        callers=callers,
        egress=egress,
        audit_hmac_key=hmac_key,
        secret_values=tuple(value for value in secrets.values() if len(value) >= 8),
        tls_cert_file=tls_cert,
        tls_key_file=tls_key,
        presidio_ca_file=ca_file,
        audit_forward=forward,
        auth_mode=auth_mode,
        entra_audience=entra_audience,
        entra_clients=entra_clients,
        baa_client_ids=baa_client_ids,
    )


def with_presidio_urls(settings: Settings, analyzer_url: str, anonymizer_url: str) -> Settings:
    """Point a loaded allowlist at another Presidio pair after the egress check."""
    settings.egress.check(analyzer_url, purpose="presidio")
    settings.egress.check(anonymizer_url, purpose="presidio")
    presidio = settings.allowlist.presidio.model_copy(
        update={"analyzer_url": analyzer_url, "anonymizer_url": anonymizer_url}
    )
    allowlist = settings.allowlist.model_copy(update={"presidio": presidio})
    return settings.model_copy(update={"allowlist": allowlist})


def tool_index(settings: Settings) -> dict[str, tuple[str, ToolSpec]]:
    index: dict[str, tuple[str, ToolSpec]] = {}
    for name, upstream in settings.allowlist.upstreams.items():
        for tool in upstream.tools:
            index[tool.name] = (name, tool)
    return index


def _secret_names(parsed: AllowlistFile) -> set[str]:
    names = {"audit_hmac_key"}
    for caller in parsed.callers.values():
        names.add(caller.token_secret)
    return names


def _secret_candidates(name: str) -> list[Path]:
    paths: list[Path] = []
    override = os.environ.get(f"PRM_SECRET_FILE_{name.upper()}")
    if override:
        paths.append(Path(override))
    credentials = os.environ.get("CREDENTIALS_DIRECTORY")
    if credentials:
        paths.append(Path(credentials) / name)
    paths.append(Path("/etc/presidio-redaction-mcp/secrets") / name)
    paths.append(Path("/run/secrets") / name)
    return paths


def _read_secret(name: str, *, env_name: str) -> str:
    value = ""
    for path in _secret_candidates(name):
        if path.is_file():
            value = path.read_text(encoding="utf-8").strip()
            break
    else:
        env_value = os.environ.get(f"PRM_SECRET_{name.upper()}", "")
        if env_name == "production":
            if env_value:
                raise ConfigError("secret_env_fallback_denied")
            raise ConfigError("secret_missing")
        value = env_value
    if not value:
        raise ConfigError("secret_missing")
    if name == "audit_hmac_key" and len(value.encode("utf-8")) < 32:
        raise ConfigError("hmac_key_too_short")
    _assert_secret_quality(value)
    return value


def _assert_secret_quality(value: str) -> None:
    if _PLACEHOLDER.search(value):
        raise ConfigError("secret_placeholder")
    raw = value.encode("utf-8")
    if len(raw) < 32:
        raise ConfigError("secret_too_short")
    if len(set(value)) < 8 or _shannon_bits(value) < 3.0:
        raise ConfigError("secret_low_entropy")


def _shannon_bits(value: str) -> float:
    counts = Counter(value)
    total = len(value)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _reject_duplicate_secrets(secrets: dict[str, str]) -> None:
    seen: dict[str, str] = {}
    for name, value in secrets.items():
        if value in seen:
            raise ConfigError("duplicate_secret_value")
        seen[value] = name


def _reject_duplicate_caller_tokens(callers: tuple[CallerSecret, ...]) -> None:
    seen: dict[bytes, str] = {}
    for caller in callers:
        previous = seen.get(caller.token_sha256)
        if previous is not None:
            raise ConfigError("duplicate_caller_token")
        seen[caller.token_sha256] = caller.name


def _tls_paths() -> tuple[str | None, str | None, str | None]:
    credentials = os.environ.get("CREDENTIALS_DIRECTORY")
    cert = os.environ.get("PRM_TLS_CERT_FILE")
    key = os.environ.get("PRM_TLS_KEY_FILE")
    ca_file = os.environ.get("PRM_PRESIDIO_CA_FILE")
    if credentials:
        cred = Path(credentials)
        cert = cert or str(cred / "tls_cert")
        key = key or str(cred / "tls_key")
        ca_file = ca_file or str(cred / "internal_ca")
    return cert, key, ca_file


def _caller_secret(name: str, spec: CallerSpec, secrets: dict[str, str]) -> CallerSecret:
    return CallerSecret(
        name=name,
        phi_capable=spec.phi_capable,
        allowed_ingress=frozenset(spec.allowed_ingress),
        token_sha256=digest(secrets[spec.token_secret]),
    )


def _reject_identifier(value: str, *, field: str) -> None:
    if not _NAME.match(value) or _WILDCARD.search(value) or _LIST_ALL.search(value):
        raise ValueError(f"{field}_rejected")
    if field == "tool" and (_READ_VERB.search(value) is None or _WRITE_TOKEN.search(value)):
        raise ValueError("tool_read_verb_required")
