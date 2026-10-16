# Control-map traceability — Yellow lane

Source: Reggie, "local-ai-dlp — Control Map" (HIPAA Security Rule, NYDFS 23 NYCRR 500, FTC Safeguards 16 CFR 314.4), 2026-10-15. Propose-only. Synthetic data only. Not legal advice. Cap's counsel confirms BAA scope.

This file traces the Yellow-lane rows (presidio-redaction-mcp) that Lane P3 documents. It does not close Red-lane items in local-ai-stack (Cloudflare in front of Open WebUI, the Anthropic BAA, Open WebUI chat history).

Cap's decision, recorded in `docs/upstream-scope-policy.md`: StackJack and Composio stay outside BAA coverage. The control map offered a BAA or a documented no-PHI source. The decision in force is the documented no-PHI source. These docs do not ask either vendor for a BAA.

| Control-map row | What it asked for | Where this lane records it |
|---|---|---|
| HIPAA 164.308(b)(1) and 164.314(a); top gap P0 #2 | BAA, or a written "no PHI in source" scope, for StackJack and Composio | `docs/upstream-scope-policy.md`. Scope is no-PHI, read-only, day-1 tools only, `.invalid` egress pins until a host is reviewed. |
| HIPAA 164.308(a)(6); top gap P1 #8 | Incident procedures, extended to a breach assessment when a miss reaches a no-BAA party, tied to SOP-SEC-010 | `docs/incident-response.md` |
| HIPAA 164.402 (via the 164.308(a)(6) recommendation) | Four-factor assessment | `docs/incident-response.md`, factors (i)–(iv): nature and extent, who received it, whether it was acquired or viewed, mitigation |
| NYDFS 500.16 and 500.17 | IR plan and a 72-hour notice decision for a Covered Entity | `docs/incident-response.md`. Clock starts at the determination that a cybersecurity incident occurred. Counsel confirms Covered Entity status and any 500.19 exemption. The proxy does not send the notice. |
| FTC 314.4(h) and 314.4(j) | Written incident response, and a 30-day FTC notice decision at 500 consumers | `docs/incident-response.md`. The consumer count is not taken from an audit-row entity count. |
| FTC 314.4(c)(7); HIPAA 164.312(c); POL-CHG-001 | Change control for the allowlist and proxy config | `docs/allowlist-change-process.md`. Marko reviews before merge. A routable host, toolkit, action, or connected account also needs a new Cap decision. Runtime evidence is the `config_change` audit row. |
| NYDFS 500.11 and FTC 314.4(f) | Oversight of the upstream service providers | `docs/upstream-scope-policy.md` records the scope those providers are allowed to see. A separate diligence file (security posture, retention, breach-notice terms) is still open. That file is not a BAA request. |
| DLP efficacy row; top gap P0 #3 | Numeric recall floor per entity, residual-risk acceptance, and a breach path when a miss can reach Grok Bot | Floors: `config/recall-floors.yaml` (1.0 canonical and adversarial on the listed entities). Acceptance: `docs/residual-risk.md`. Breach path: `docs/incident-response.md`. |
| HIPAA 164.310(d) and 164.312(a)(2)(iv) | Media controls and encryption at rest for the audit store | `docs/host-hardening.md` and `docs/native-install.md`. Data directories are on LUKS. Secrets are root-only files under `/etc/presidio-redaction-mcp/` or systemd `LoadCredential=`, not a container secret store. |
| HIPAA 164.316 | Policies and procedures, retained 6 years | This `docs/` set, kept in git. Six years applies to the documentation. Log retention is stated separately in `docs/host-hardening.md`. |
| HIPAA 164.308(a)(1)(ii)(A)–(B); NYDFS 500.9; FTC 314.4(b) | Written risk analysis | `docs/residual-risk.md` is the accepted-residual statement for this proxy. It is an input to Cap's enterprise risk analysis. It is not that analysis. |

## Still outside this lane

The control map's remaining gaps stay open here: workforce training, a named Qualified Individual, break-glass access, session timeouts, the full third-party diligence file, disposal schedules beyond the retention note in `docs/host-hardening.md`, and the Red-lane Cloudflare and Anthropic items. Phase 1 code already covers fail-closed behavior, the allowlist, and audit contents. The primary deployment is Azure Container Apps (P2). `docs/native-install.md` and `deploy/install.sh` are the optional on-prem path (venv per app, hardened systemd, no Docker).
