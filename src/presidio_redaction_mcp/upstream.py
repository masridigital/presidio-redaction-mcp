"""Phase 1 mock upstreams. They record only what the proxy forwards and never dial Cloudflare."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from presidio_redaction_mcp.config import ToolSpec
from presidio_redaction_mcp.errors import FailClosed


class StreamInterrupted(FailClosed):
    def __init__(self) -> None:
        super().__init__("upstream_stream_interrupted")


# Canonical synthetic values the mock result always contains. Kept aligned with
# tests/fixtures/synthetic_corpus.yaml. Not real persons or account numbers.
CANONICAL_RESULT_SECRETS = (
    "Testy McFakerson",
    "fake.user@example.com",
    "MRN-SYN-0001234",
    "ACCT-SYN-99990000",
    "REC-SYN-000042",
    "NPI-SYN-1234567890",
    "555-0100",
    "1900-01-01",
    "4111 1111 1111 1111",
    "123 Fake Street, Testville, ZZ 00000",
    "Jane Synthetic-Doe",
    "Pat Placeholder",
)


@dataclass
class RecordedCall:
    upstream: str
    tool: str
    base_url: str
    via: str
    arguments: dict[str, Any]


@dataclass
class MockUpstream:
    name: str
    base_url: str
    calls: list[RecordedCall] = field(default_factory=list)
    force_overflow: bool = False
    break_stream: bool = False
    stream_token: str = "MRN-SYN-0001234"
    result_body: Any = None

    async def call(self, tool: ToolSpec, arguments: dict[str, Any]) -> Any:
        if "cloudflare" in self.base_url.lower() or "trycloudflare" in self.base_url.lower():
            raise FailClosed("upstream_via_cloudflare")
        if self.break_stream:
            self.calls.append(
                RecordedCall(
                    upstream=self.name,
                    tool=tool.name,
                    base_url=self.base_url,
                    via="direct",
                    arguments=arguments,
                )
            )
            _ = self.stream_token
            raise StreamInterrupted()
        self.calls.append(
            RecordedCall(
                upstream=self.name,
                tool=tool.name,
                base_url=self.base_url,
                via="direct",
                arguments=arguments,
            )
        )
        if self.result_body is not None:
            return self.result_body
        item_count = 21 if self.force_overflow else int(arguments.get("limit") or 1)
        items = [
            {
                "id": f"mon-{index}",
                "status": 2,
                "type": 1,
                "interval": 60,
                "patient_name": "Jane Synthetic-Doe",
                "url": "https://example.com/not-allowlisted",
            }
            for index in range(item_count)
        ]
        return {
            "status": "operational",
            "summary": "SYNTHETIC check by " + " ".join(CANONICAL_RESULT_SECRETS),
            "items": items,
            "patient_name": "Pat Placeholder",
            "blob": "not-text",
        }
