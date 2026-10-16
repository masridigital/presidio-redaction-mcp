"""Logging that cannot retain raw identifier spans."""

from __future__ import annotations

import logging

from presidio_redaction_mcp.recognizers import RecognizerSet

_configured = False


class RecognizerLogFilter(logging.Filter):
    def __init__(self, recognizers: RecognizerSet) -> None:
        super().__init__()
        self.recognizers = recognizers

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)
        spans = self.recognizers.find_spans(message)
        if spans or "bearer " in message.lower() or "authorization" in message.lower():
            redacted = message
            for span in sorted(spans, key=lambda item: item["start"], reverse=True):
                redacted = redacted[: span["start"]] + "<REDACTED>" + redacted[span["end"] :]
            lowered = redacted.lower()
            if "bearer " in lowered or "authorization" in lowered:
                redacted = "redacted-credential-log"
            record.msg = redacted
            record.args = ()
        return True


def configure_logging(recognizers: RecognizerSet, level: str = "INFO") -> None:
    global _configured
    root = logging.getLogger()
    root.setLevel(level)
    scrub = RecognizerLogFilter(recognizers)

    def _install(logger: logging.Logger) -> None:
        logger.filters = [item for item in logger.filters if not isinstance(item, RecognizerLogFilter)]
        logger.addFilter(scrub)

    _install(root)
    for name in ("mcp", "httpx", "httpcore", "uvicorn", "uvicorn.access", "uvicorn.error"):
        logger = logging.getLogger(name)
        logger.setLevel(logging.WARNING)
        _install(logger)
    _configured = True
