"""Portal config. Invalid documents fail closed and are never published."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from presidio_admin.catalog import COMPOSIO_TOOLS, RECOGNIZERS, STACKJACK_TOOLS, UPSTREAMS
from presidio_admin.errors import ConfigRejected

SCHEMA_VERSION = 1
ALLOWED_UPSTREAMS = frozenset({"stackjack", "composio"})
SCORE_FLOOR = 0.4
PATTERN_FLOOR = 0.75
MAX_CLIENTS = 32
_GUID = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_NAME = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
_DISPLAY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,79}$")
_WILDCARD = re.compile(r"[\*\?\[\]]|(?:^|[_\-])all(?:[_\-]|$)")
_LIST_ALL = re.compile(r"list[_-]?all", re.IGNORECASE)
_VERB = re.compile(
    r"(?:^|[_\-])(write|send|create|update|delete|export|bulk|download|upload|"
    r"post|put|patch|insert|remove|execute|reply|forward|share|add|edit|new)(?:[_\-]|$)",
    re.IGNORECASE,
)
_ACCOUNT = re.compile(r"^ca_[a-z0-9_]{8,64}$")
def _reject_identifier(value: str) -> None:
    if not _NAME.match(value) or _WILDCARD.search(value) or _LIST_ALL.search(value) or _VERB.search(value):
        raise ValueError("identifier_rejected")


class ArgConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    type: Literal["string", "integer"]
    pattern: str | None = None
    max_length: int | None = Field(default=None, ge=1, le=500)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        _reject_identifier(value)
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


class ToolConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    enabled: bool = False
    description: str = Field(min_length=1, max_length=240)
    rationale: str = Field(min_length=1, max_length=400)
    read_only: Literal[True]
    max_items: int = Field(ge=1, le=20)
    allowed_result_fields: list[str] = Field(min_length=1)
    arguments: list[ArgConfig]
    toolkit: str | None = None
    action_id: str | None = None
    connected_account_id: str | None = None

    @field_validator("name", "toolkit", "action_id")
    @classmethod
    def _idents(cls, value: str | None) -> str | None:
        if value is None:
            return value
        _reject_identifier(value)
        return value

    @field_validator("allowed_result_fields")
    @classmethod
    def _fields(cls, value: list[str]) -> list[str]:
        for item in value:
            _reject_identifier(item)
        return value

    @field_validator("connected_account_id")
    @classmethod
    def _account(cls, value: str | None) -> str | None:
        if value is not None and _ACCOUNT.match(value) is None:
            raise ValueError("connected_account_id_invalid")
        return value


class UpstreamConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["stackjack", "composio"]
    enabled: bool = True
    base_url: str
    tools: list[ToolConfig]

    @field_validator("base_url")
    @classmethod
    def _url(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("upstream_url_must_be_https")
        lowered = value.lower()
        if "cloudflare" in lowered or "trycloudflare" in lowered:
            raise ValueError("upstream_must_not_use_cloudflare")
        return value


class ClientConfig(BaseModel):
    """A pre-registered Entra application. No client secret is stored."""

    model_config = ConfigDict(extra="forbid")

    client_id: str
    display_name: str
    app_role: Literal["PHI", "NonPHI"]
    enabled: bool = True

    @field_validator("client_id")
    @classmethod
    def _client_id(cls, value: str) -> str:
        if _GUID.match(value) is None:
            raise ValueError("client_id_invalid")
        return value.lower()

    @field_validator("display_name")
    @classmethod
    def _display(cls, value: str) -> str:
        if _DISPLAY.match(value) is None or "@" in value:
            raise ValueError("display_name_rejected")
        return value


class PatternConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    regex: str = Field(min_length=1, max_length=400)
    score: float = Field(ge=PATTERN_FLOOR, le=1)
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        _reject_identifier(value)
        return value

    @field_validator("regex")
    @classmethod
    def _regex(cls, value: str) -> str:
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError("recognizer_regex_invalid") from exc
        return value


class RecognizerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    entity: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")
    patterns: list[PatternConfig] = Field(min_length=1)

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        _reject_identifier(value)
        return value


class PortalConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = SCHEMA_VERSION
    score_threshold: float = Field(default=SCORE_FLOOR, ge=SCORE_FLOOR, le=1)
    claude_verifier_enabled: bool = False
    upstreams: dict[str, UpstreamConfig]
    clients: list[ClientConfig] = Field(default_factory=list, max_length=MAX_CLIENTS)
    recognizers: list[RecognizerConfig]
    presidio_timeout_seconds: float = Field(default=5.0, gt=0, le=30)

    @model_validator(mode="after")
    def _closed_world(self) -> PortalConfig:
        if set(self.upstreams) != ALLOWED_UPSTREAMS:
            raise ValueError("upstreams_must_be_exactly_stackjack_and_composio")
        for name, upstream in self.upstreams.items():
            if upstream.kind != name:
                raise ValueError("upstream_kind_mismatch")
            catalog = UPSTREAMS[name]
            if upstream.base_url != catalog["base_url"]:
                raise ValueError("upstream_url_locked")
            _tools_match_catalog(name, upstream.tools)
        _recognizers_match_catalog(self.recognizers)
        seen: set[str] = set()
        for client in self.clients:
            if client.client_id in seen:
                raise ValueError("duplicate_client")
            seen.add(client.client_id)
        return self

    def enabled_tools(self) -> list[str]:
        """Tools the proxy may call. Default deny: disabled tools are omitted."""
        names: list[str] = []
        for upstream in self.upstreams.values():
            if not upstream.enabled:
                continue
            for tool in upstream.tools:
                if tool.enabled:
                    names.append(tool.name)
        return names

    def pattern_state(self) -> dict[str, tuple[float, bool]]:
        state: dict[str, tuple[float, bool]] = {}
        for recognizer in self.recognizers:
            for pattern in recognizer.patterns:
                state[pattern.name] = (pattern.score, pattern.enabled)
        return state


def default_config() -> PortalConfig:
    """Default-deny tools, verifier off, threshold at the floor, no clients."""
    upstreams = {}
    for name, spec in UPSTREAMS.items():
        tools = [ToolConfig.model_validate(dict(item)) for item in spec["tools"]]
        upstreams[name] = UpstreamConfig(
            kind=name,  # type: ignore[arg-type]
            enabled=True,
            base_url=str(spec["base_url"]),
            tools=tools,
        )
    recognizers = []
    for entry in RECOGNIZERS:
        patterns = [
            PatternConfig(name=str(item["name"]), regex=str(item["regex"]), score=float(item["score"]))
            for item in entry["patterns"]  # type: ignore[index]
        ]
        recognizers.append(
            RecognizerConfig(name=str(entry["name"]), entity=str(entry["entity"]), patterns=patterns)
        )
    return PortalConfig(upstreams=upstreams, recognizers=recognizers, clients=[])


def parse_config(payload: object) -> PortalConfig:
    try:
        return PortalConfig.model_validate(payload)
    except Exception as exc:
        raise ConfigRejected("config_rejected") from exc


def _tools_match_catalog(upstream: str, tools: list[ToolConfig]) -> None:
    catalog = STACKJACK_TOOLS if upstream == "stackjack" else COMPOSIO_TOOLS
    expected = {str(item["name"]): item for item in catalog}
    if {tool.name for tool in tools} != set(expected):
        raise ValueError("tool_catalog_mismatch")
    seen: set[str] = set()
    for tool in tools:
        if tool.name in seen:
            raise ValueError("duplicate_tool")
        seen.add(tool.name)
        expected_tool = ToolConfig.model_validate(expected[tool.name]).model_dump()
        actual = tool.model_dump()
        actual["enabled"] = False
        expected_tool["enabled"] = False
        if actual != expected_tool:
            raise ValueError("tool_definition_locked")
        if upstream == "composio":
            if tool.action_id != tool.name or not tool.toolkit or not tool.connected_account_id:
                raise ValueError("composio_tool_pin_incomplete")
        elif tool.toolkit or tool.action_id or tool.connected_account_id:
            raise ValueError("stackjack_tool_must_not_pin_composio_fields")


def _recognizers_match_catalog(recognizers: list[RecognizerConfig]) -> None:
    expected = {str(item["name"]): item for item in RECOGNIZERS}
    if {item.name for item in recognizers} != set(expected):
        raise ValueError("recognizer_catalog_mismatch")
    for recognizer in recognizers:
        catalog = expected[recognizer.name]
        if recognizer.entity != catalog["entity"]:
            raise ValueError("recognizer_entity_locked")
        catalog_patterns = {str(item["name"]): item for item in catalog["patterns"]}  # type: ignore[index]
        if {pattern.name for pattern in recognizer.patterns} != set(catalog_patterns):
            raise ValueError("recognizer_pattern_locked")
        for pattern in recognizer.patterns:
            if pattern.regex != catalog_patterns[pattern.name]["regex"]:
                raise ValueError("recognizer_regex_locked")
