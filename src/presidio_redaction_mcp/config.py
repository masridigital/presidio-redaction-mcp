"""Load and reject anything outside the day-1 StackJack and Composio allowlist."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Literal

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
_VERB = re.compile(
    r"(?:^|[_\-])(write|send|create|update|delete|export|bulk|download|upload|"
    r"post|put|patch|insert|remove|execute|reply|forward|share|add|edit|new)(?:[_\-]|$)",
    re.IGNORECASE,
)
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

    @field_validator("name", "toolkit", "action_id")
    @classmethod
    def _idents(cls, value: str | None) -> str | None:
        if value is None:
            return value
        _reject_identifier(value, field="tool")
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


class CallerSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    phi_capable: bool
    allowed_ingress: list[Literal["cloudflare", "vpn"]]
    token_secret: str
    cf_access_client_id_secret: str | None = None
    cf_access_client_secret_secret: str | None = None


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


class AllowlistFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    upstreams: dict[str, UpstreamSpec]
    callers: dict[str, CallerSpec]
    presidio: PresidioSpec
    egress: EgressSpec
    deployment: DeploymentSpec
    verifier: VerifierSpec = Field(default_factory=VerifierSpec)
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
        if grok.phi_capable or grok.allowed_ingress != ["cloudflare"]:
            raise ValueError("grok_bot_must_be_cloudflare_non_phi")
        if not grok.cf_access_client_id_secret or not grok.cf_access_client_secret_secret:
            raise ValueError("grok_bot_cf_service_token_required")
        for name in ("claude-local", "open-webui"):
            caller = self.callers[name]
            if not caller.phi_capable or caller.allowed_ingress != ["vpn"]:
                raise ValueError("phi_caller_must_be_vpn_only")
            if caller.cf_access_client_id_secret or caller.cf_access_client_secret_secret:
                raise ValueError("vpn_caller_must_not_bind_cf_token")
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


def assert_verifier_permitted(source: Settings | AllowlistFile) -> None:
    """Refuse to enable the verifier when the deployment target is marked non-BAA."""
    allowlist = source.allowlist if isinstance(source, Settings) else source
    if not allowlist.verifier.enabled:
        return
    if allowlist.deployment.target != "azure" or not allowlist.deployment.baa:
        raise ConfigError("verifier_refused_non_baa_target")


def load_settings(config_path: Path, *, env: str | None = None) -> Settings:
    env_name = env or os.environ.get("PRM_ENV", "production")
    raw_bytes = config_path.read_bytes()
    try:
        parsed = AllowlistFile.model_validate(yaml.safe_load(raw_bytes))
    except Exception as exc:
        if "verifier_refused_non_baa_target" in str(exc):
            raise ConfigError("verifier_refused_non_baa_target") from exc
        raise ConfigError("allowlist_rejected") from exc
    assert_verifier_permitted(parsed)
    recognizer_path = config_path.parent / parsed.recognizers_file
    if not recognizer_path.is_file():
        recognizer_path = config_path.parent.parent / parsed.recognizers_file
    recognizers = load_recognizers(recognizer_path)
    secrets = {name: _read_secret(name) for name in _secret_names(parsed)}
    hmac_key = secrets["audit_hmac_key"].encode("utf-8")
    if len(hmac_key) < 32:
        raise ConfigError("hmac_key_too_short")
    callers = tuple(_caller_secret(name, spec, secrets) for name, spec in parsed.callers.items())
    if env_name == "production":
        for url in (parsed.presidio.analyzer_url, parsed.presidio.anonymizer_url):
            if not url.startswith("https://"):
                raise ConfigError("presidio_must_be_https")
        tls_cert = os.environ.get("PRM_TLS_CERT_FILE", "/run/secrets/tls_cert")
        tls_key = os.environ.get("PRM_TLS_KEY_FILE", "/run/secrets/tls_key")
        ca_file = os.environ.get("PRM_PRESIDIO_CA_FILE", "/run/secrets/internal_ca")
        for path in (tls_cert, tls_key, ca_file):
            if not Path(path).is_file():
                raise ConfigError("tls_material_missing")
    else:
        tls_cert = os.environ.get("PRM_TLS_CERT_FILE")
        tls_key = os.environ.get("PRM_TLS_KEY_FILE")
        ca_file = os.environ.get("PRM_PRESIDIO_CA_FILE")
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
        if caller.cf_access_client_id_secret:
            names.add(caller.cf_access_client_id_secret)
        if caller.cf_access_client_secret_secret:
            names.add(caller.cf_access_client_secret_secret)
    return names


def _read_secret(name: str) -> str:
    file_override = os.environ.get(f"PRM_SECRET_FILE_{name.upper()}")
    path = Path(file_override or f"/run/secrets/{name}")
    if path.is_file():
        value = path.read_text(encoding="utf-8").strip()
    else:
        value = os.environ.get(f"PRM_SECRET_{name.upper()}", "")
    if not value:
        raise ConfigError("secret_missing")
    return value


def _caller_secret(name: str, spec: CallerSpec, secrets: dict[str, str]) -> CallerSecret:
    cf_id = secrets[spec.cf_access_client_id_secret] if spec.cf_access_client_id_secret else None
    cf_secret = secrets[spec.cf_access_client_secret_secret] if spec.cf_access_client_secret_secret else None
    return CallerSecret(
        name=name,
        phi_capable=spec.phi_capable,
        allowed_ingress=frozenset(spec.allowed_ingress),
        token_sha256=digest(secrets[spec.token_secret]),
        cf_client_id_sha256=digest(cf_id) if cf_id is not None else None,
        cf_client_secret_sha256=digest(cf_secret) if cf_secret is not None else None,
    )


def _reject_identifier(value: str, *, field: str) -> None:
    if not _NAME.match(value) or _WILDCARD.search(value) or _LIST_ALL.search(value) or _VERB.search(value):
        raise ValueError(f"{field}_rejected")
