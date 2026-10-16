"""Reason codes only. Messages must stay free of payloads and tokens."""

from __future__ import annotations

import logging

_SIGNATURE_ALERT = "alert reason_code=store_signature_invalid"


def emit_store_signature_alert(reason_code: str) -> None:
    """One stderr line. The proxy workspace alerts on this text."""
    if reason_code != "store_signature_invalid":
        return
    logging.getLogger("presidio_admin.alert").error(_SIGNATURE_ALERT)


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
