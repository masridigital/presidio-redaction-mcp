"""Logging that cannot retain raw identifier spans."""

from __future__ import annotations

import logging

from presidio_redaction_mcp.recognizers import RecognizerSet

_configured = False


class RecognizerLogFilter(logging.Filter):
    def __init__(self, recognizers: RecognizerSet, secrets: tuple[str, ...] = ()) -> None:
        super().__init__()
        self.recognizers = recognizers
        self.secrets = tuple(secret for secret in secrets if secret)

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)
        redacted = message
        for secret in self.secrets:
            if secret in redacted:
                redacted = redacted.replace(secret, "<REDACTED>")
        spans = self.recognizers.find_spans(redacted)
        if spans or "bearer " in redacted.lower() or "authorization" in redacted.lower() or redacted != message:
            for span in sorted(spans, key=lambda item: item["start"], reverse=True):
                redacted = redacted[: span["start"]] + "<REDACTED>" + redacted[span["end"] :]
            lowered = redacted.lower()
            if "bearer " in lowered or "authorization" in lowered:
                redacted = "redacted-credential-log"
            record.msg = redacted
            record.args = ()
        return True


def configure_logging(recognizers: RecognizerSet, level: str = "INFO", secrets: tuple[str, ...] = ()) -> None:
    global _configured
    root = logging.getLogger()
    root.setLevel(level)
    scrub = RecognizerLogFilter(recognizers, secrets)

    def _install(logger: logging.Logger) -> None:
        logger.filters = [item for item in logger.filters if not isinstance(item, RecognizerLogFilter)]
        logger.addFilter(scrub)

    _install(root)
    for name in ("mcp", "httpx", "httpcore", "uvicorn", "uvicorn.access", "uvicorn.error"):
        logger = logging.getLogger(name)
        logger.setLevel(logging.WARNING)
        _install(logger)
    # Handler filters cover loggers that do not carry their own copy, including
    # handlers attached before this process finishes configuring logging.
    for handler in root.handlers:
        handler.filters = [item for item in handler.filters if not isinstance(item, RecognizerLogFilter)]
        handler.addFilter(scrub)
    _configured = True
