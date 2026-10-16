# presidio-redaction-mcp — PLAN

Task: `local-ai-dlp` · Aligned with `/workspace/local-ai-dlp-plan.md` (Yellow lane) · Status: Draft, pending Marko security review.

## 1. Goal
A remote MCP proxy that hosted assistants (Grok Bot — no BAA; Claude) call. It forwards to **exactly two** upstream MCPs: **StackJack** and **Composio** (no others; no M365/Halo-direct), runs Presidio on **inbound args** and **outbound results**, **fails closed**, enforces a **per-upstream tool allowlist** (read-first, no bulk export), writes an audit log, authenticates every caller, and is exposed only via Cloudflare Tunnel + Access or VPN.

## 2. Build-vs-reuse evaluation (do first)
| Option | Fit | Gaps |
|---|---|---|
| **LiteLLM MCP gateway** (docs.litellm.ai/docs/mcp) + `pii_masking_v2` / Presidio guardrail with `pre_mcp_call` | Already in local-ai-stack; aggregates upstream MCPs, virtual-key auth, per-key MCP server/tool access controls, logging | Guardrail coverage of **tool results** (post-call on MCP output) must be verified per version; fail-closed semantics on Presidio error must be verified (some guardrail paths log-and-continue); custom recognizers/deny-lists less flexible; couples Yellow lane to Red-lane stack |
| **cmalpass/mcp-presidio** | MCP server exposing Presidio analyze/anonymize as *tools* | It is a tool the model calls, not a transparent proxy; cannot guarantee enforcement on other tools' data |
| **ManoharMarri/local-presidio-mcp-server** | Local Presidio MCP server, same pattern | Same as above; single-maintainer, needs code audit; not a forwarder |
| **Custom thin proxy** (Python, official MCP SDK, Streamable HTTP) | Full control: mandatory filtering on both directions, hard fail-closed, field allowlists, pagination caps, audit schema | We own maintenance + security of the code |

**Recommendation:** Build a **custom thin proxy** for the hosted-assistant (Yellow) path, because enforcement must be mandatory and fail-closed on both args and results — the Presidio-as-tool servers do not provide that, and LiteLLM's result-side + fail-closed behavior is not guaranteed. Reuse: Presidio analyzer/anonymizer containers and the same recognizer YAML as local-ai-stack; borrow recognizer ideas from the two OSS servers (after license check). Phase 1 includes a **spike** testing LiteLLM MCP gateway against acceptance tests 1–4; if it passes all of them on the pinned version, revisit and prefer LiteLLM to reduce code.

## 3. Architecture
```
Grok Bot / Claude ──HTTPS──► Cloudflare Access (service token per assistant) ─► cloudflared tunnel
   ─► proxy /mcp (bearer token per assistant, verified in-app)
        1. authN/authZ → caller identity
        2. allowlist check (upstream, tool, arg schema, pagination cap)
        3. Presidio analyze+anonymize args (error/timeout ⇒ BLOCK)
        4. forward to upstream MCP (StackJack or Composio only; upstream leg never traverses the Cloudflare tunnel)
        5. field allowlist on result → Presidio on result (error/timeout ⇒ BLOCK, discard result)
        6. audit log: ts, caller, upstream, tool, args hash, entity counts, decision, latency
```
Config: `allowlist.yaml` with exactly two upstream keys (`stackjack`, `composio`), default deny; any other upstream fails config validation; read tools only in Phase 1; no export/bulk/list-all tools; max items per call.

## 4. Phases (full build — HIPAA / NYDFS 500 / FTC Safeguards, not an MVP)
| Phase | Scope |
|---|---|
| 1 | LiteLLM-gateway spike vs tests 1–4; custom proxy core: Streamable HTTP MCP, mock StackJack + Composio upstreams, Presidio both directions w/ shared custom recognizers + client-name deny-list, hard fail-closed, default-deny allowlist, field allowlists, pagination caps, per-assistant bearer auth, structured audit log, CI (tests, gitleaks, SAST, dependency/image scan, SBOM). Draft PR. |
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
