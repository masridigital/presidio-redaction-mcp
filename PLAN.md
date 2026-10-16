# presidio-redaction-mcp — PLAN

Task: `local-ai-dlp` · Aligned with the local-ai-dlp plan (Yellow lane) · Status: Draft. Marko review of the design was NO-GO; this Phase 1 implementation is still pending a fresh Marko review before any merge or deploy.

## 1. Goal
A remote MCP proxy that hosted assistants (Grok Bot — no BAA; Claude) call. It forwards to **exactly two** upstream MCPs: **StackJack** and **Composio** (no others; no M365/Halo-direct), runs Presidio on **inbound args** and **outbound results**, **fails closed**, enforces a **per-upstream tool allowlist** (read-first, no bulk export), writes an audit log, authenticates every caller, and is exposed only via Cloudflare Tunnel + Access or VPN.

## 2. Build-vs-reuse evaluation (do first)
| Option | Fit | Gaps |
|---|---|---|
| **LiteLLM MCP gateway** (docs.litellm.ai/docs/mcp) + `pii_masking_v2` / Presidio guardrail with `pre_mcp_call` | Already in local-ai-stack; aggregates upstream MCPs, virtual-key auth, per-key MCP server/tool access controls, logging | Guardrail coverage of **tool results** (post-call on MCP output) must be verified per version; fail-closed semantics on Presidio error must be verified (some guardrail paths log-and-continue); custom recognizers/deny-lists less flexible; couples Yellow lane to Red-lane stack |
| **cmalpass/mcp-presidio** | MCP server exposing Presidio analyze/anonymize as *tools* | It is a tool the model calls, not a transparent proxy; cannot guarantee enforcement on other tools' data |
| **ManoharMarri/local-presidio-mcp-server** | Local Presidio MCP server, same pattern | Same as above; single-maintainer, needs code audit; not a forwarder |
| **Custom thin proxy** (Python, official MCP SDK, Streamable HTTP) | Full control: mandatory filtering on both directions, hard fail-closed, field allowlists, pagination caps, audit schema | We own maintenance + security of the code |

**Recommendation:** Build a **custom thin proxy** for the hosted-assistant (Yellow) path, because enforcement must be mandatory and fail-closed on both args and results — the Presidio-as-tool servers do not provide that, and LiteLLM's result-side + fail-closed behavior is not guaranteed. Reuse: official Presidio analyzer/anonymizer images and the recognizer YAML in this repo. Phase 1 spiked LiteLLM **v1.96.0** against acceptance tests 1–4. It does not pass. Do not switch to LiteLLM unless a later pin passes tests 1–10 plus non-text and streaming. See `docs/litellm-gateway-spike.md`. Recognizer ideas borrowed from OSS servers still need a license check before any code is copied; Phase 1 uses original patterns for the synthetic corpus only.

## 3. Architecture
```
grok-bot (no PHI) ──HTTPS──► Cloudflare Access + cloudflared ─► 127.0.0.1:8443
claude-local / open-webui (PHI-capable) ──VPN only──► VPN address:8444
   ─► proxy /mcp (bearer per caller; Grok Bot also presents its CF service token)
        1. authN binds token → caller profile → allowed ingress (wrong door = 401, no upstream)
        2. allowlist (upstream, tool, pinned Composio toolkit/action/account, arg schema, pagination cap)
        3. Presidio on args (any error/timeout/truncated stream ⇒ BLOCK, zero upstream calls)
           Cloudflare ingress: any detected entity ⇒ BLOCK (do not forward), audit phi_in_cloudflare_tool_args
           VPN ingress: forward only the masked args (upstreams are no-PHI)
        4. forward only to stackjack.invalid or composio.invalid (Phase 1 mocks; never via cloudflared)
        5. field allowlist, then Presidio on the result (failure ⇒ discard, caller gets a reason code only)
        6. audit: ts, caller, ingress, upstream, tool, keyed args HMAC, entity counts, decision, latency, config hash
```
`config/allowlist.yaml` has exactly two upstream keys (`stackjack`, `composio`). Any other upstream, wildcard, write/send/export/bulk tool, or missing Composio pin fails config load.

**Cap (no BAAs):** StackJack and Composio are out of BAA scope. Day-1 tools are read-only and non-PHI only. Vendor Cloudflare in front of those SaaS endpoints is unverified, so routable vendor hosts are not egress-allowed.

**Chief:** local Claude and Open WebUI are PHI-capable and VPN-only. Grok Bot may use the tunnel under the standing no-PHI rule, with inbound filtering and fail-closed. Profiles are per-token to one ingress.

**Residual risk:** misses can still reach Grok Bot. Accepted only with the recall CI gate, the statement in SECURITY.md, and the breach-assessment step in `docs/incident-response.md` (HIPAA four-factor, NYDFS 72-hour decision, FTC 30-day decision).

## 4. Phases (full build — HIPAA / NYDFS 500 / FTC Safeguards, not an MVP)
| Phase | Scope |
|---|---|
| 1 | LiteLLM-gateway spike vs tests 1–4 (result: do not switch; see `docs/litellm-gateway-spike.md`). Custom proxy: Streamable HTTP MCP, mock StackJack + Composio, Presidio both directions, hard fail-closed including streaming, default-deny allowlist with exact day-1 tools, field allowlists, pagination caps, caller profiles (CF vs VPN), keyed HMAC audit log with caller identity and config-change rows, recall floors, TLS, official MCR Presidio images by digest, no published Presidio ports, Docker secrets, deny-all egress except the two pins and test. CI (pytest, gitleaks, SAST, dependency scan, SBOM, shellcheck). Draft PR only. |
| 2 | Real StackJack + Composio connectors with read-only, tenant-scoped creds (via vault); rate limiting; token rotation; Entra OIDC option; audit export to SIEM w/ retention (6y HIPAA / 5y NYDFS); tamper-evident logs |
| 3 | Hardening: threat model, Marko red-team w/ synthetic PHI corpus, recall/precision report per recognizer, container hardening (non-root, read-only FS, seccomp), backup/restore of config + logs, IR runbook (DLP-failure scenario) |
| 4 | Exposure via Cloudflare Tunnel + Access (service token per assistant, `/mcp` only, WAF) — after Marko CLEAR; register with Grok Bot/Claude |
| 5 | Compliance evidence pack (Reggie control mapping), quarterly review + recognizer tuning cadence |

## 5. Acceptance tests (synthetic data ONLY — no real PHI/client/Lumina data)
1. Inbound args with synthetic PII/MRN are masked before mock upstream sees them.
2. Outbound results with synthetic PII/MRN/account IDs are masked before caller sees them.
3. **Fail-closed (analyzer down / anonymizer down / timeout / malformed response):** call returns error; mock upstream receives zero calls (inbound case) or result is discarded (outbound case).
4. Non-allowlisted tool, unknown upstream, or bulk/export tool ⇒ denied, logged.
5. Pagination/item cap enforced.
6. Missing/invalid/wrong-assistant token ⇒ 401, no upstream call.
7. Audit log row per call; contains no raw fixture PII.
8. **Cloudflare egress = redacted only (no BAA):** capture all bytes leaving the proxy toward the tunnel side for the full fixture suite; assert zero raw synthetic PII/MRN/account values appear, and that upstream traffic never routes via cloudflared.
9. Config with any upstream other than `stackjack`/`composio` fails to load.
10. Fixtures generated with seeded Faker, header `SYNTHETIC`; CI fails if any fixture lacks it.

## Decisions recorded for Phase 1

- LiteLLM v1.96.0 does not pass tests 1–4 as a fail-closed both-direction gateway. The custom proxy is the Yellow-lane control. Do not revisit LiteLLM unless a later pin passes tests 1–10 plus non-text and streaming.
- Written no-PHI scope for StackJack and Composio. No BAAs. Allowlist is the enforcement.
- Tool args on the Cloudflare path are unredacted at the tunnel. Policy: callers never put PHI in tool args. PHI-capable callers are VPN-only. Grok Bot stays on the tunnel and is blocked when inbound entities are detected.
- Upstream results may cross vendor-side Cloudflare. Unverified. Day-1 allowlist is non-PHI tools only; egress hosts are `.invalid` until that is verified.
- Audit HMAC is keyed. Review cadence is weekly / monthly / quarterly as in SECURITY.md.
- TLS is in Phase 1, not deferred. Official Presidio images only (`mcr.microsoft.com`), digest-pinned, unpublished, behind internal TLS.
- This VM is separate from local-ai-stack.
- IR notes: `docs/incident-response.md`.

## Day-1 tools

See `config/allowlist.yaml` for the pins. StackJack: `stackjack_health_check`, `stackjack_get_service_status`, `stackjack_list_advisories`, `stackjack_get_release_notes`, `stackjack_search_docs`, `stackjack_get_doc_page`. Composio toolkit `UPTIMEROBOT`, connected account `ca_day1_uptimerobot_nonphi_ro`: `UPTIMEROBOT_GET_MONITORS`, `UPTIMEROBOT_GET_ACCOUNT_DETAILS`. Rationale is on each tool. Expansions only via Marko review.

## Target host: Ubuntu Server LTS VM (Cap on-prem hypervisor), separate from local-ai-stack
Deliverables in-repo: `docker compose` stack; `deploy/systemd/*.service` (compose up/down, Restart=on-failure, ordered after docker + cloudflared); `deploy/install.sh` (idempotent: packages, docker, user/group, dirs w/ 0700, secrets from env/vault, enable units); `docs/host-hardening.md` covering:
- **LUKS** full-disk encryption at install (or LUKS data volume for /var/lib/docker + backups), key/passphrase escrow held separately.
- **UFW** default deny incoming and outgoing; no inbound except SSH from the VPN/mgmt subnet; no outbound except loopback, DNS, and NTP until a reviewed allow names a real upstream host. Services are reached via cloudflared (outbound) or VPN. Docker published ports are limited to localhost and the VPN address, and `DOCKER-USER` drops other forwards. Presidio publishes no ports.
- **unattended-upgrades** for security updates + reboot window; monthly image updates.
- **CIS-style hardening** (Ubuntu CIS L1 baseline): SSH keys only/no root, auditd, AppArmor, minimal packages, time sync, sysctl hardening, docker daemon (no TCP socket, userns-remap/rootless where feasible, live-restore, log limits).
- **Log retention**: journald + docker logs rotated locally; audit logs shipped to SIEM, retained 6y (HIPAA) / 5y (NYDFS).
- **Encrypted backups**: restic/borg encrypted, 3-2-1 with immutable offsite copy, quarterly restore test.
Acceptance: install.sh shellcheck clean and idempotent in CI (Ubuntu LTS container/VM); UFW rules test asserts no listening inbound ports beyond allowed.

