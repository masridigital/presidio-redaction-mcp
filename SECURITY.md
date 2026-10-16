# SECURITY — presidio-redaction-mcp

Status: Draft. Marko security review is **NO-GO** for merge, deploy, and exposure until a later review clears the code. This file is the Yellow-lane policy for Phase 1.

## Purpose

Risk reduction for Yellow-lane tool data. Redaction is not HIPAA de-identification and is not Safe Harbor. The no-PHI rule for Grok Bot remains. Presidio is a seatbelt: pattern and deny-list coverage misses free text, unusual formats, and quasi-identifiers.

## Cap decisions (2026-10-16)

**StackJack and Composio have no BAAs.** Written scope, enforced by `config/allowlist.yaml`:

- Day-1 tools are read-only and non-PHI. They are product health, public docs, published advisories, release notes, and UptimeRobot monitor/account metadata for one pinned connected account (`ca_day1_uptimerobot_nonphi_ro`, toolkit `UPTIMEROBOT`).
- No write, send, export, bulk, or wildcard tools. Config load fails closed if any appear, or if any upstream other than `stackjack` and `composio` is present.
- Source data for those tools is in scope only when it is not PHI. If PHI shows up in a result, the proxy still redacts and the event is an incident candidate. That is not permission to point PHI tools at these vendors.
- Vendor endpoints may sit behind Cloudflare. That has **not** been verified. Real hosts are not on the egress list. Phase 1 pins are `stackjack.invalid` and `composio.invalid`. Adding a routable host, a toolkit, an action, or a connected account requires Marko review and a new Cap decision.

**Residual risk of redaction misses is accepted** for this lane, with three conditions: recall floors in `config/recall-floors.yaml` are a CI gate on the synthetic corpus; the residual-risk statement in this file stays visible; a suspected miss triggers the breach-assessment step in `docs/incident-response.md`.

## Callers and ingress

| Caller | PHI-capable | Ingress | Token binding |
|---|---|---|---|
| `grok-bot` | No. Standing no-PHI rule. | Cloudflare Tunnel + Access only | Bearer plus Cloudflare Access service-token id and secret, compared in constant time |
| `claude-local` | Yes | VPN only | Bearer |
| `open-webui` | Yes | VPN only | Bearer |

Tool arguments cross Cloudflare **before** Presidio when the caller is Grok Bot. Callers must not put PHI in tool arguments. The proxy still scans them and, on the Cloudflare ingress, **blocks** the call when any entity is detected (it does not forward a masked copy). That does not undo the hop that already happened; `phi_in_cloudflare_tool_args` is an incident candidate. PHI-capable callers stay on the VPN listener. Their arguments are masked before the no-PHI upstreams see them. A valid token on the wrong listener is 401 and makes no upstream call.

A tool result that Presidio flags is **blocked**, not masked, for a non-BAA caller (`phi_capable: false`). The caller receives `phi_in_non_baa_tool_result` and not the redacted body. That check is in the service on the default path and does not depend on the optional verifier. PHI-capable callers still receive the masked result when the verifier is off.

VPN-only is the inbound path for local Claude and Open WebUI. This repo does not host Open WebUI and does not store chat history.

## Fail closed

Any Presidio error, timeout, non-JSON body, HTTP error, truncated stream, or anonymizer no-op blocks the call. Inbound failure: the mock upstream is not called. Outbound failure: the result is discarded and is not returned. Binary, image, embedded file, unknown encoding, base64 that decodes to a detected identifier, an oversized payload, or a non-string scalar that matches a recognizer is blocked. Field allowlists run first and drop every other result field. Known-sensitive field names that remain are replaced regardless of score. Detections at or above the 0.4 threshold are masked; there is no pass band. Custom pattern scores are authored at 0.75 or higher so they are not ambiguous.

Low-recall misses can still pass. That is the accepted residual risk, not a fail-open switch.

The optional Claude verifier is a second pass on text Presidio has already returned. It is off by default. It runs only when `deployment.target` is `azure` and `deployment.baa` is true. A deployment target marked non-BAA, including Cloudflare, cannot enable it: config load and process start both refuse. When it is on, a Presidio hit, a Claude `phi` or `uncertain` verdict, a timeout, an error, a malformed body, an echo of the submitted text, or an instruction-like override blocks the call. Claude's body is untrusted and must match the verdict schema (offsets and entity types only). The call is `POST https://api.anthropic.com/v1/messages` with an allowlisted model, structured outputs, and no beta header, tools, files, batches, or web search. The API key comes from Azure Key Vault or a `0600` file. Audit rows for verifier decisions store an HMAC of the redacted text, never the text.

## Least privilege

Default deny. Read-only. No bulk export. Pagination caps (`max_items` ≤ 20). Field allowlists. Exactly two upstreams. Application egress allows only those two pins, the internal Presidio host, and (when `PRM_ENV=test`) the test hosts. Production denies loopback and any other destination, including `backend.composio.dev` and Cloudflare hostnames. Upstream credentials, when they exist in a later phase, stay read-only and tenant-scoped. Upstream permissions are the ceiling.

## Auth and TLS

Separate bearer tokens for Grok Bot, local Claude, and Open WebUI. Rotation target remains 90 days and is a Phase 4 exposure gate, not a Phase 1 gap that may be ignored at exposure time. Constant-time compare. Cloudflare Access service token is bound to the Grok Bot profile. TLS from Phase 1 on both listeners, and TLS from the proxy to Presidio via the internal nginx sidecar. Certificates are Docker secrets. Presidio images are official `mcr.microsoft.com/presidio-analyzer` and `presidio-anonymizer` at 2.2.362, pinned by digest, with no published ports.

## Audit

One row per call: timestamp, caller identity, ingress, whether that caller is PHI-capable, upstream, tool, keyed HMAC of the arguments (not an unsalted hash), entity counts, decision, reason code, latency, config hash. When the verifier runs, a separate `verifier_decision` row stores the direction, verdict, entity-type counts, and an HMAC of the redacted text. Config load writes a `config_change` row when the allowlist hash changes. No raw PHI, tokens, argument text, or API key. Review cadence: Joseph weekly (fail-closed, Cloudflare PHI blocks, denied tools, entity-count spikes); monthly allowlist review; quarterly caller-token review. Retention: 6 years HIPAA documentation / 5 years NYDFS 500.6, at least 1 year searchable. See `docs/host-hardening.md`.

## Incident response

`docs/incident-response.md`: HIPAA four-factor assessment (164.402) when a miss may have reached a no-BAA party; NYDFS 72-hour notice decision (500.17) when a Covered Entity is in scope; FTC 30-day notice decision (314.4(j)) at 500 consumers. Report vulnerabilities in this proxy privately to Joseph Masri.

## Test data and change control

Synthetic fixtures only, seeded Faker (seed 4242), header `SYNTHETIC`. No real PHI, client data, or Lumina data. No live secrets in git. Marko reviews before any merge, deploy, exposure, or allowlist expansion. CI: pytest (acceptance tests 1–10, recall floors, streaming fail-closed), gitleaks, bandit, pip-audit, CycloneDX SBOM, shellcheck.

## Host

The primary deployment is Azure Container Apps under the Microsoft BAA. That path is the P2 lane. `deploy/install.sh` is an optional on-prem installer only (venv and systemd, no Docker). Host controls for that optional path are in `docs/host-hardening.md` and `docs/native-install.md`: LUKS, UFW default-deny inbound and outbound, unattended-upgrades, a CIS L1-style baseline, and encrypted 3-2-1 backups.
