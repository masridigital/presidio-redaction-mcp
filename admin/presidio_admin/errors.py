"""Reason codes only. Messages must stay free of payloads and tokens."""


class PortalError(Exception):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class ConfigRejected(PortalError):
    """The document is invalid. Callers must keep the last good version."""


class AuthzError(PortalError):
    """The caller is not an MFA-authenticated Admin in this tenant."""


class ApprovalError(PortalError):
    """A change could not be proposed, approved, or rejected."""
