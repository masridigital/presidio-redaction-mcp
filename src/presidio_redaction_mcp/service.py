"""Tool-call pipeline: authz, Presidio, upstream, Presidio again, audit."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from typing import Any

from presidio_redaction_mcp.audit import AuditLog
from presidio_redaction_mcp.auth import CallerIdentity
from presidio_redaction_mcp.config import Settings, ToolSpec, tool_index
from presidio_redaction_mcp.egress import EgressPolicy
from presidio_redaction_mcp.errors import FailClosed, PolicyError
from presidio_redaction_mcp.redact import Redactor, count_items, filter_fields
from presidio_redaction_mcp.upstream import MockUpstream

_ARG_NAME = re.compile(r"^[A-Za-z0-9_-]{1,80}$")


class RedactionService:
    def __init__(
        self,
        *,
        settings: Settings,
        audit: AuditLog,
        redactor: Redactor,
        upstreams: dict[str, MockUpstream],
    ) -> None:
        self.settings = settings
        self.audit = audit
        self.redactor = redactor
        self.upstreams = upstreams
        self._tools = tool_index(settings)

    async def call_tool(self, caller: CallerIdentity, name: str, arguments: dict[str, Any] | None) -> str:
        started = time.perf_counter()
        arguments = arguments or {}
        args_hmac = _args_hmac(self.settings.audit_hmac_key, arguments)
        located = self._tools.get(name)
        if located is None:
            # Do not write the caller-supplied name. It is untrusted and may itself be an identifier.
            self._audit(
                caller,
                upstream=None,
                tool=None,
                args_hmac=args_hmac,
                counts={},
                decision="deny",
                reason="tool_not_allowlisted",
                started=started,
            )
            return _error("tool_not_allowlisted")
        upstream_name, tool = located
        try:
            self._validate_arguments(tool, arguments)
        except PolicyError as exc:
            reason = exc.reason_code
        except (TypeError, ValueError):
            reason = "invalid_arguments"
        else:
            reason = ""
        if reason:
            self._audit(
                caller,
                upstream=upstream_name,
                tool=name,
                args_hmac=args_hmac,
                counts={},
                decision="deny",
                reason=reason,
                started=started,
            )
            return _error(reason)

        try:
            redacted_args, arg_counts = await self.redactor.redact(arguments)
        except FailClosed as exc:
            self._audit(
                caller,
                upstream=upstream_name,
                tool=name,
                args_hmac=args_hmac,
                counts={},
                decision="block",
                reason=exc.reason_code,
                started=started,
            )
            return _error(exc.reason_code)

        if caller.ingress == "cloudflare" and _sensitive(arg_counts):
            self._audit(
                caller,
                upstream=upstream_name,
                tool=name,
                args_hmac=args_hmac,
                counts=arg_counts,
                decision="block",
                reason="phi_in_cloudflare_tool_args",
                started=started,
            )
            return _error("phi_in_cloudflare_tool_args")

        upstream = self.upstreams[upstream_name]
        try:
            self.settings.egress.check(upstream.base_url, purpose="upstream")
            raw_result = await upstream.call(tool, redacted_args)
        except FailClosed as exc:
            self._audit(
                caller,
                upstream=upstream_name,
                tool=name,
                args_hmac=args_hmac,
                counts=arg_counts,
                decision="block",
                reason=exc.reason_code,
                started=started,
            )
            return _error(exc.reason_code)
        except PolicyError as exc:
            self._audit(
                caller,
                upstream=upstream_name,
                tool=name,
                args_hmac=args_hmac,
                counts=arg_counts,
                decision="deny",
                reason=exc.reason_code,
                started=started,
            )
            return _error(exc.reason_code)

        if count_items(raw_result) > tool.max_items:
            self._audit(
                caller,
                upstream=upstream_name,
                tool=name,
                args_hmac=args_hmac,
                counts=arg_counts,
                decision="block",
                reason="pagination_cap_exceeded",
                started=started,
            )
            return _error("pagination_cap_exceeded")

        try:
            filtered = filter_fields(raw_result, set(tool.allowed_result_fields))
            redacted_result, result_counts = await self.redactor.redact(filtered)
        except FailClosed as exc:
            self._audit(
                caller,
                upstream=upstream_name,
                tool=name,
                args_hmac=args_hmac,
                counts=arg_counts,
                decision="block",
                reason=exc.reason_code,
                started=started,
            )
            return _error(exc.reason_code)

        counts = _merge(arg_counts, result_counts)
        self._audit(
            caller,
            upstream=upstream_name,
            tool=name,
            args_hmac=args_hmac,
            counts=counts,
            decision="allow",
            reason="ok",
            started=started,
        )
        return json.dumps(redacted_result, sort_keys=True, separators=(",", ":"))

    def _validate_arguments(self, tool: ToolSpec, arguments: dict[str, Any]) -> None:
        if not isinstance(arguments, dict):
            raise PolicyError("invalid_arguments")
        allowed = {spec.name: spec for spec in tool.arguments}
        for key in arguments:
            if not isinstance(key, str) or _ARG_NAME.match(key) is None or key not in allowed:
                raise PolicyError("invalid_arguments")
        for name, spec in allowed.items():
            if name not in arguments:
                continue
            value = arguments[name]
            if spec.type == "integer":
                if not isinstance(value, int) or isinstance(value, bool):
                    raise PolicyError("invalid_arguments")
                if name == "limit" and (value < 1 or value > tool.max_items):
                    raise PolicyError("pagination_cap_exceeded")
            else:
                if not isinstance(value, str):
                    raise PolicyError("invalid_arguments")
                if spec.max_length is not None and len(value) > spec.max_length:
                    raise PolicyError("invalid_arguments")
                if spec.pattern is not None and re.fullmatch(spec.pattern, value) is None:
                    raise PolicyError("invalid_arguments")

    def _audit(
        self,
        caller: CallerIdentity,
        *,
        upstream: str | None,
        tool: str | None,
        args_hmac: str,
        counts: dict[str, int],
        decision: str,
        reason: str,
        started: float,
    ) -> None:
        self.audit.record(
            caller=caller.name,
            ingress=caller.ingress,
            phi_capable=caller.phi_capable,
            upstream=upstream,
            tool=tool,
            args_hmac=args_hmac,
            entity_counts=counts,
            decision=decision,
            reason_code=reason,
            latency_ms=(time.perf_counter() - started) * 1000,
            config_sha256=self.settings.config_sha256,
        )


def _args_hmac(key: bytes, arguments: dict[str, Any]) -> str:
    canonical = json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


def _error(reason_code: str) -> str:
    return json.dumps({"error": "blocked", "reason_code": reason_code}, sort_keys=True)


def _sensitive(counts: dict[str, int]) -> bool:
    return any(count > 0 for count in counts.values())


def _merge(left: dict[str, int], right: dict[str, int]) -> dict[str, int]:
    merged = dict(left)
    for key, count in right.items():
        merged[key] = merged.get(key, 0) + count
    return merged


def assert_egress_closed(policy: EgressPolicy, url: str) -> None:
    policy.check(url, purpose="upstream")
