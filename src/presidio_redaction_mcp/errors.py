"""Errors that carry a reason code and never include payload text."""


class ProxyError(Exception):
    """Base error. ``reason_code`` is safe to return to callers and to log."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class ConfigError(ProxyError):
    """Allowlist or secret configuration failed closed."""


class AuthError(ProxyError):
    """Missing, invalid, or wrong-ingress credential."""


class PolicyError(ProxyError):
    """Allowlist, pagination, egress, or caller-profile rejection."""


class FailClosed(ProxyError):
    """Presidio or stream failure. Results must be discarded."""
