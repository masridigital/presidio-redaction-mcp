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
from presidio_redaction_mcp.redact import Redactor, count_items, drop_denied_fields, filter_fields
from presidio_redaction_mcp.upstream import MockUpstream
from presidio_redaction_mcp.verifier import ClaudeVerifier

_ARG_NAME = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
_INJECTION = re.compile(
    r"(?i)(?:"
    r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions"
    r"|disregard\s+(?:all\s+)?(?:previous|prior|above)(?:\s+instructions)?"
    r"|you\s+are\s+now"
    r"|system\s+prompt"
    r"|do\s+not\s+tell\s+the\s+user"
    r"|<\s*\|im_start\|\s*>"
    r"|</?\s*system\s*>"
    r")"
)


class RateLimiter:
    """Fixed window per caller. The clock is injectable so tests do not sleep."""

    def __init__(self, *, limit: int = 600, window_seconds: float = 60.0, clock=None) -> None:
        if limit < 1:
            raise ValueError("rate_limit")
        self.limit = limit
        self.window_seconds = window_seconds
        self._clock = clock or time.monotonic
        self._hits: dict[str, list[float]] = {}

    def check(self, key: str) -> None:
        now = self._clock()
        window = [stamp for stamp in self._hits.get(key, []) if now - stamp < self.window_seconds]
        if len(window) >= self.limit:
            self._hits[key] = window
            raise PolicyError("rate_limited")
        window.append(now)
        self._hits[key] = window


class RedactionService:
    def __init__(
        self,
        *,
        settings: Settings,
        audit: AuditLog,
        redactor: Redactor,
        upstreams: dict[str, MockUpstream],
        rate_limiter: RateLimiter | None = None,
        verifier: ClaudeVerifier | None = None,
    ) -> None:
        self.settings = settings
        self.audit = audit
        self.redactor = redactor
        self.upstreams = upstreams
        self.rate_limiter = rate_limiter or RateLimiter()
        self.verifier = verifier
        self._tools = tool_index(settings)
        self._hits: dict[str, list[float]] = {}

    async def call_tool(self, caller: CallerIdentity, name: str, arguments: dict[str, Any] | None) -> str:
        started = time.perf_counter()
        try:
            return await self._call_tool(caller, name, arguments, started)
        except Exception:
            try:
                self._audit(
                    caller,
                    upstream=None,
                    tool=None,
                    args_hmac=_args_hmac(self.settings.audit_hmac_key, arguments or {}),
                    counts={},
                    decision="block",
                    reason="internal_error",
                    started=started,
                )
            except Exception:
                return _error("internal_error")
            return _error("internal_error")

    async def _call_tool(
        self,
        caller: CallerIdentity,
        name: str,
        arguments: dict[str, Any] | None,
        started: float,
    ) -> str:
        arguments = arguments or {}
        args_hmac = _args_hmac(self.settings.audit_hmac_key, arguments)
        if not self._allow_rate(caller.name):
            self._audit(
                caller,
                upstream=None,
                tool=None,
                args_hmac=args_hmac,
                counts={},
                decision="deny",
                reason="rate_limited",
                started=started,
            )
            return _error("rate_limited")
        located = self._tools.get(name)
        try:
            self.rate_limiter.check(caller.name)
        except PolicyError as exc:
            self._audit(
                caller,
                upstream=located[0] if located else None,
                tool=name if located else None,
                args_hmac=args_hmac,
                counts={},
                decision="deny",
                reason=exc.reason_code,
                started=started,
            )
            return _error(exc.reason_code)
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

        try:
            await self._second_pass(
                caller,
                upstream=upstream_name,
                tool=name,
                value=redacted_args,
                counts=arg_counts,
                direction="input",
                started=started,
            )
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

        if caller.ingress == "external-nonphi" and _sensitive(arg_counts):
            self._audit(
                caller,
                upstream=upstream_name,
                tool=name,
                args_hmac=args_hmac,
                counts=arg_counts,
                decision="block",
                reason="phi_in_external_nonphi_tool_args",
                started=started,
            )
            return _error("phi_in_external_nonphi_tool_args")

        spec = self.settings.allowlist.callers.get(caller.name)
        if spec is None or (spec.allowed_tools and name not in spec.allowed_tools):
            self._audit(
                caller,
                upstream=upstream_name,
                tool=name,
                args_hmac=args_hmac,
                counts=arg_counts,
                decision="deny",
                reason="caller_tool_not_allowed",
                started=started,
            )
            return _error("caller_tool_not_allowed")

        upstream = self.upstreams[upstream_name]
        redacted_args = scrub_secrets(redacted_args, self.settings.secret_values)
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
            if spec.denied_result_fields and _result_is_non_baa(caller, self.settings.baa_client_ids):
                filtered = drop_denied_fields(filtered, set(spec.denied_result_fields))
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

        # Entity hits are blocked for non-BAA callers. phi_capable alone is not enough:
        # Cloudflare ingress always blocks, and an Entra client id off the BAA
        # allowlist blocks even when the caller profile says it is PHI-capable.
        # This runs on the default path and does not depend on the optional verifier.
        if _sensitive(result_counts) and _result_is_non_baa(caller, self.settings.baa_client_ids):
            self._audit(
                caller,
                upstream=upstream_name,
                tool=name,
                args_hmac=args_hmac,
                counts=_merge(arg_counts, result_counts),
                decision="block",
                reason="phi_in_non_baa_tool_result",
                started=started,
            )
            return _error("phi_in_non_baa_tool_result")

        try:
            await self._second_pass(
                caller,
                upstream=upstream_name,
                tool=name,
                value=redacted_result,
                counts=result_counts,
                direction="result",
                started=started,
            )
        except FailClosed as exc:
            self._audit(
                caller,
                upstream=upstream_name,
                tool=name,
                args_hmac=args_hmac,
                counts=_merge(arg_counts, result_counts),
                decision="block",
                reason=exc.reason_code,
                started=started,
            )
            return _error(exc.reason_code)

        counts = _merge(arg_counts, result_counts)
        redacted_result = scrub_secrets(
            strip_instructions(redacted_result),
            self.settings.secret_values,
        )
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
        rendered = json.dumps(redacted_result, sort_keys=True, separators=(",", ":"))
        return scrub_secrets(rendered, self.settings.secret_values)

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

    def _allow_rate(self, caller: str) -> bool:
        limit = self.settings.allowlist.limits.requests_per_minute
        now = time.monotonic()
        window = [stamp for stamp in self._hits.get(caller, []) if now - stamp < 60]
        if len(window) >= limit:
            self._hits[caller] = window
            return False
        window.append(now)
        self._hits[caller] = window
        return True

    async def _second_pass(
        self,
        caller: CallerIdentity,
        *,
        upstream: str,
        tool: str,
        value: Any,
        counts: dict[str, int],
        direction: str,
        started: float,
    ) -> None:
        if self.verifier is None:
            return
        rendered = _canonical(value)
        input_hmac = _text_hmac(self.settings.audit_hmac_key, rendered)
        model = self.verifier.model

        def row(decision: str, reason: str, verdict: str | None, entity_counts: dict[str, int]) -> None:
            self.audit.record_verifier(
                caller=caller.name,
                ingress=caller.ingress,
                upstream=upstream,
                tool=tool,
                direction=direction,
                decision=decision,
                reason_code=reason,
                verdict=verdict,
                entity_counts=entity_counts,
                input_hmac=input_hmac,
                model=model,
                latency_ms=(time.perf_counter() - started) * 1000,
                config_sha256=self.settings.config_sha256,
            )

        if _sensitive(counts):
            row("block", "presidio_flagged", None, counts)
            raise FailClosed("presidio_flagged")
        try:
            outcome = await self.verifier.verify(rendered)
        except FailClosed as exc:
            row("block", exc.reason_code, None, {})
            raise
        if outcome.verdict != "clear":
            reason = "verifier_flagged" if outcome.verdict == "phi" else "verifier_uncertain"
            row("block", reason, outcome.verdict, outcome.entity_counts())
            raise FailClosed(reason)
        row("allow", "ok", "clear", {})


def _canonical(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _args_hmac(key: bytes, arguments: dict[str, Any]) -> str:
    canonical = _canonical(arguments).encode("utf-8")
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


def _text_hmac(key: bytes, text: str) -> str:
    return hmac.new(key, text.encode("utf-8"), hashlib.sha256).hexdigest()


def _error(reason_code: str) -> str:
    return json.dumps({"error": "blocked", "reason_code": reason_code}, sort_keys=True)


def _sensitive(counts: dict[str, int]) -> bool:
    return any(count > 0 for count in counts.values())


def _result_is_non_baa(caller: CallerIdentity, baa_client_ids: frozenset[str]) -> bool:
    """True when a masked PHI result must not be returned.

    The external-nonphi mark is never a BAA path. Under APIM the Entra client id
    (azp/appid) must be on the BAA allowlist. phi_capable is not sufficient.
    """
    if caller.ingress == "external-nonphi":
        return True
    if caller.authn == "entra":
        client_id = (caller.client_id or "").lower()
        if client_id not in baa_client_ids:
            return True
    return not caller.phi_capable


def strip_instructions(value: Any) -> Any:
    """Remove instruction-override text from a result. Tool definitions stay pinned."""
    if isinstance(value, str):
        return _INJECTION.sub("<STRIPPED>", value)
    if isinstance(value, dict):
        return {key: strip_instructions(item) for key, item in value.items()}
    if isinstance(value, list):
        return [strip_instructions(item) for item in value]
    return value


def scrub_secrets(value: Any, secrets: tuple[str, ...]) -> Any:
    if isinstance(value, str):
        for secret in secrets:
            if secret and secret in value:
                value = value.replace(secret, "<REDACTED>")
        return value
    if isinstance(value, dict):
        return {key: scrub_secrets(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [scrub_secrets(item, secrets) for item in value]
    return value


def _merge(left: dict[str, int], right: dict[str, int]) -> dict[str, int]:
    merged = dict(left)
    for key, count in right.items():
        merged[key] = merged.get(key, 0) + count
    return merged


def assert_egress_closed(policy: EgressPolicy, url: str) -> None:
    policy.check(url, purpose="upstream")
