# Upstream scope policy — StackJack and Composio

Status: Draft. Pending Marko review. Cap's decision of 2026-10-16 is the scope this proxy enforces. This file is operational policy for the Yellow lane. It is not legal advice. Cap's counsel confirms BAA scope. Traceability is in `docs/control-map-traceability.md`.

## Decision

The proxy forwards to two upstreams: StackJack and Composio. Cap decided both are outside BAA coverage. The control is this written no-PHI scope, enforced by `config/allowlist.yaml`. This policy records that decision. It does not ask either vendor for a BAA.

PHI is outside the source data those tools may return, and outside the arguments callers may send them.

## In scope

Day-1 tools are read-only (`read_only: true`, `phi_scope: none`). The pins and the rationale on each tool live in `config/allowlist.yaml`.

StackJack:

- `stackjack_health_check`
- `stackjack_get_service_status`
- `stackjack_list_advisories`
- `stackjack_get_release_notes`
- `stackjack_search_docs`
- `stackjack_get_doc_page`

Composio, toolkit `UPTIMEROBOT`, connected account `ca_day1_uptimerobot_nonphi_ro`:

- `UPTIMEROBOT_GET_MONITORS`
- `UPTIMEROBOT_GET_ACCOUNT_DETAILS`

Source data is in scope when it is product health, public documentation, published advisories, release notes, or UptimeRobot monitor and account metadata for that one connected account. Contact, URL, and friendly-name fields are not allowlisted on the UptimeRobot tools.

## Out of scope

- Any upstream other than `stackjack` and `composio`. That includes direct M365 and Halo.
- Write, send, export, bulk, or wildcard tools. Config load fails closed if any of those appear, or if a Composio tool is missing its toolkit, action, and connected-account pins.
- PHI in source data. A result that contains PHI is still redacted, and the event is an incident candidate under `docs/incident-response.md`. Redaction is not permission to aim a PHI tool at these vendors.
- Routable vendor hosts. Phase 1 egress pins are `stackjack.invalid` and `composio.invalid`. Whether those vendors' real endpoints sit behind Cloudflare has not been verified, so real hosts stay off the egress list. Production egress denies `backend.composio.dev` and Cloudflare hostnames.

Test fixtures are a separate rule: synthetic only, Faker seed 4242, header `SYNTHETIC`. Production calls are real vendor responses inside the list above, not synthetic payloads.

## Callers

| Caller | PHI-capable | Path to the proxy | What the upstream sees |
|---|---|---|---|
| `grok-bot` | No. Standing no-PHI rule. | Cloudflare Tunnel + Access | Nothing, when inbound Presidio finds an entity. The call is blocked and audited as `phi_in_cloudflare_tool_args`. |
| `claude-local` | Yes | VPN only | Masked arguments, and only for a day-1 tool |
| `open-webui` | Yes | VPN only | Masked arguments, and only for a day-1 tool |

Tool arguments from Grok Bot cross Cloudflare before Presidio. Callers do not put PHI in tool arguments. Blocking the call does not undo that hop. PHI-capable callers stay on the VPN listener. A valid token on the wrong listener is 401 and makes no upstream call.

Upstream requests do not leave through cloudflared. The tunnel is ingress for the Grok Bot profile. Egress allows only the pins in the allowlist. Phase 1 upstreams are mocks (`mode: mock`) and do not dial a routable host.

## Enforcement

- Startup rejects a config outside this scope (`allowlist_rejected`).
- Presidio runs on arguments and on results and fails closed, including a truncated stream. Analyzer and anonymizer are pip installs in their own venvs, `presidio-analyzer[server]==2.2.362` and `presidio-anonymizer[server]==2.2.362`, with spaCy `3.8.16` and `en_core_web_lg` `3.8.0`, installed with `pip --require-hashes`. They listen on `127.0.0.1` only. The unit and the pins are in `docs/native-install.md`.
- Host egress is default-deny, per service user where the firewall can express it. See `docs/host-hardening.md`.

## Changes

A new tool, toolkit, action, connected account, upstream, or routable host goes through `docs/allowlist-change-process.md`. Marko reviews before merge. A routable host, a toolkit, an action, or a connected account also needs a new Cap decision. Widening this scope to PHI would be a new Cap decision. It is not a BAA request.
