"""Reason codes only. Messages must stay free of payloads and tokens."""

from __future__ import annotations

import logging
import sys

_ALERT_LOGGER = "presidio_admin.alert"
_SIGNATURE_ALERT = "alert reason_code=store_signature_invalid"
_STDERR_HANDLER = "_prm_alert_stderr"


def alert_logger() -> logging.Logger:
    """Logger with its own stderr handler. Root logging cannot drop this line."""
    logger = logging.getLogger(_ALERT_LOGGER)
    logger.setLevel(logging.ERROR)
    logger.propagate = False
    if not any(getattr(handler, _STDERR_HANDLER, False) for handler in logger.handlers):
        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(logging.ERROR)
        handler.setFormatter(logging.Formatter("%(message)s"))
        setattr(handler, _STDERR_HANDLER, True)
        logger.addHandler(handler)
    return logger


def emit_store_signature_alert(reason_code: str) -> None:
    """One stderr line. The proxy workspace alerts on this text."""
    if reason_code != "store_signature_invalid":
        return
    alert_logger().error(_SIGNATURE_ALERT)


alert_logger()


class PortalError(Exception):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class ConfigRejected(PortalError):
    """The document is invalid. Callers must keep the last good version."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        emit_store_signature_alert(reason_code)


class AuthzError(PortalError):
    """The caller is not an MFA-authenticated Admin in this tenant."""


class ApprovalError(PortalError):
    """A change could not be proposed, approved, or rejected."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        emit_store_signature_alert(reason_code)
