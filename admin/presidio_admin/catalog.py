"""Closed catalogs. Upstream types and tool shapes cannot be extended here.

The day-1 tool definitions match ``config/allowlist.yaml``. The portal may
toggle ``enabled`` and may adjust scores. It may not add a third upstream,
a write tool, or a new result field.
"""

from __future__ import annotations

STACKJACK_URL = "https://stackjack.invalid/mcp"
COMPOSIO_URL = "https://composio.invalid/mcp"
CONNECTED_ACCOUNT = "ca_day1_uptimerobot_nonphi_ro"

_CURSOR = {
    "name": "cursor",
    "type": "string",
    "max_length": 128,
    "pattern": r"^[A-Za-z0-9._:-]{0,128}$",
}
_DOC = {
    "name": "doc_id",
    "type": "string",
    "max_length": 64,
    "pattern": r"^[A-Za-z0-9._:-]{1,64}$",
}


def _limit() -> dict[str, str]:
    return {"name": "limit", "type": "integer"}


def _tool(
    name: str,
    description: str,
    rationale: str,
    max_items: int,
    fields: list[str],
    arguments: list[dict[str, object]],
    *,
    toolkit: str | None = None,
    action_id: str | None = None,
    connected_account_id: str | None = None,
) -> dict[str, object]:
    return {
        "name": name,
        "enabled": False,
        "description": description,
        "rationale": rationale,
        "read_only": True,
        "max_items": max_items,
        "allowed_result_fields": fields,
        "arguments": arguments,
        "toolkit": toolkit,
        "action_id": action_id,
        "connected_account_id": connected_account_id,
    }


STACKJACK_TOOLS: tuple[dict[str, object], ...] = (
    _tool(
        "stackjack_health_check",
        "StackJack process liveness. No customer records.",
        "Liveness only. No tickets, transcripts, or client records.",
        5,
        ["status", "summary"],
        [_limit()],
    ),
    _tool(
        "stackjack_get_service_status",
        "StackJack service status fields only.",
        "Status metadata. No support-ticket or tenant content.",
        5,
        ["status", "summary"],
        [_limit()],
    ),
    _tool(
        "stackjack_list_advisories",
        "Published StackJack security advisories, one page.",
        "Product security advisories. Paginated. Not a client export.",
        20,
        ["status", "summary", "items", "id", "type", "interval"],
        [_limit(), dict(_CURSOR)],
    ),
    _tool(
        "stackjack_get_release_notes",
        "Product changelog for one version id.",
        "Public product notes addressed by an opaque version id.",
        5,
        ["status", "summary"],
        [dict(_DOC)],
    ),
    _tool(
        "stackjack_search_docs",
        "Search public StackJack documentation.",
        "Public docs search. Query text is still redacted before the upstream.",
        10,
        ["status", "summary", "items", "id"],
        [{"name": "query", "type": "string", "max_length": 200}, _limit()],
    ),
    _tool(
        "stackjack_get_doc_page",
        "Fetch one public documentation page by id.",
        "One public page. The id is an opaque slug, not a name or record id.",
        5,
        ["status", "summary"],
        [dict(_DOC)],
    ),
)

COMPOSIO_TOOLS: tuple[dict[str, object], ...] = (
    _tool(
        "UPTIMEROBOT_GET_MONITORS",
        "UptimeRobot monitor id, status, type, and interval.",
        "Availability metadata for one pinned connected account.",
        20,
        ["status", "summary", "items", "id", "type", "interval"],
        [_limit(), dict(_CURSOR)],
        toolkit="UPTIMEROBOT",
        action_id="UPTIMEROBOT_GET_MONITORS",
        connected_account_id=CONNECTED_ACCOUNT,
    ),
    _tool(
        "UPTIMEROBOT_GET_ACCOUNT_DETAILS",
        "UptimeRobot plan and capacity fields only.",
        "Account metrics for the same pinned connected account.",
        5,
        ["status", "summary"],
        [_limit()],
        toolkit="UPTIMEROBOT",
        action_id="UPTIMEROBOT_GET_ACCOUNT_DETAILS",
        connected_account_id=CONNECTED_ACCOUNT,
    ),
)

UPSTREAMS: dict[str, dict[str, object]] = {
    "stackjack": {"kind": "stackjack", "base_url": STACKJACK_URL, "tools": STACKJACK_TOOLS},
    "composio": {"kind": "composio", "base_url": COMPOSIO_URL, "tools": COMPOSIO_TOOLS},
}

# Synthetic recognizers. Regexes match the fixture corpus only.
RECOGNIZERS: tuple[dict[str, object], ...] = (
    {
        "name": "synthetic_mrn",
        "entity": "MRN",
        "patterns": (
            {"name": "mrn_canonical", "regex": r"\bMRN-SYN-\d{7}\b", "score": 0.95},
            {
                "name": "mrn_spaced",
                "regex": r"(?i)\bm\s*r\s*n\s*-\s*s\s*y\s*n\s*-\s*(?:\d\s*){7}",
                "score": 0.85,
            },
            {
                "name": "mrn_labeled",
                "regex": r"(?i)\b(?:medical\s+record\s+number|m\.r\.n\.|mrn|mr\s*#)[\s:#-]*\d{6,10}\b",
                "score": 0.9,
            },
            {
                "name": "mrn_context",
                "regex": r"(?i)\b(?:medical\s+record(?:\s+number)?|m\.r\.n\.|mrn|chart\s+number|patient\s+id)(?!\w)[^0-9]{1,24}\d{6,10}\b",
                "score": 0.9,
            },
            {
                "name": "mrn_context_trailing",
                "regex": r"(?i)\b\d{6,10}\b[^A-Za-z0-9]{0,8}(?:is\s+the\s+)?mrn\b",
                "score": 0.9,
            },
        ),
    },
    {
        "name": "synthetic_record",
        "entity": "RECORD_ID",
        "patterns": (
            {"name": "record_canonical", "regex": r"\bREC-SYN-\d{6}\b", "score": 0.95},
            {
                "name": "record_labeled",
                "regex": r"(?i)\b(?:record(?:\s+(?:id|number))?|rec)[\s:#-]*\d{5,12}\b",
                "score": 0.9,
            },
            {
                "name": "record_context",
                "regex": r"(?i)\b(?:record\s+(?:id|number)|rec\s*#)(?!\w)[^0-9]{0,16}\d{5,12}\b",
                "score": 0.9,
            },
        ),
    },
    {
        "name": "synthetic_account",
        "entity": "ACCOUNT_ID",
        "patterns": (
            {"name": "account_canonical", "regex": r"\bACCT-SYN-\d{8}\b", "score": 0.95},
            {
                "name": "account_labeled",
                "regex": r"(?i)\b(?:account(?:\s+(?:number|id|no))?|acct\.?)[\s:#-]*\d{6,17}\b",
                "score": 0.9,
            },
            {
                "name": "account_context",
                "regex": r"(?i)\b(?:account\s+(?:number|id|no)|acct\.?|member\s+id)(?!\w)[^0-9]{0,16}\d{6,17}\b",
                "score": 0.9,
            },
            {
                "name": "account_context_trailing",
                "regex": r"(?i)\b\d{6,17}\b[^A-Za-z0-9]{0,8}(?:is\s+the\s+)?account\s+(?:number|id)\b",
                "score": 0.9,
            },
        ),
    },
    {
        "name": "synthetic_npi",
        "entity": "NPI",
        "patterns": (
            {"name": "npi_canonical", "regex": r"\bNPI-SYN-\d{10}\b", "score": 0.95},
            {"name": "npi_labeled", "regex": r"(?i)\bNPI[\s:#-]*\d{10}\b", "score": 0.95},
        ),
    },
    {
        "name": "synthetic_ssn",
        "entity": "US_SSN",
        "patterns": (
            {"name": "ssn_dashed", "regex": r"\b(?:000-00-0000|666-12-3456|900-00-0001)\b", "score": 0.95},
            {"name": "ssn_dotted", "regex": r"\b(?:000\.00\.0000|666\.12\.3456|900\.00\.0001)\b", "score": 0.9},
        ),
    },
    {
        "name": "synthetic_email",
        "entity": "EMAIL_ADDRESS",
        "patterns": (
            {
                "name": "example_email",
                "regex": r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@example\.(?:com|org)\b",
                "score": 0.9,
            },
        ),
    },
    {
        "name": "synthetic_phone",
        "entity": "PHONE_NUMBER",
        "patterns": ({"name": "fictional_555", "regex": r"\b555-01[0-9]{2}\b", "score": 0.9},),
    },
    {
        "name": "synthetic_dob",
        "entity": "DATE_OF_BIRTH",
        "patterns": ({"name": "implausible_dob", "regex": r"\b(?:1900-01-01|1901-02-02)\b", "score": 0.9},),
    },
    {
        "name": "synthetic_card",
        "entity": "CREDIT_CARD",
        "patterns": ({"name": "test_pan", "regex": r"\b4111[ -]1111[ -]1111[ -]1111\b", "score": 0.95},),
    },
    {
        "name": "synthetic_location",
        "entity": "LOCATION",
        "patterns": (
            {"name": "fake_street", "regex": "123 Fake Street, Testville, ZZ 00000", "score": 0.95},
        ),
    },
)
