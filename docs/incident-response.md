# Incident response — redaction proxy

This is the Phase 1 runbook note for a DLP failure on the Yellow lane. It is not a full IRP. Cap's counsel and SOP-SEC-010 still govern. Do not put raw PHI in tickets, chat, or this repo.

## When this runs

Open a review when any of the following is true:

- Audit reason `phi_in_cloudflare_tool_args` (a Cloudflare caller put identifier-bearing tool arguments on the tunnel **before** Presidio could block them).
- A sampling review, user report, or upstream log shows a synthetic-or-real identifier that the proxy returned or forwarded unmasked.
- Presidio failed open in any other component (this proxy is built to fail closed; a fail-open report is itself the incident).
- The allowlist was changed without a `config_change` audit row, or a tool outside the day-1 list was observed.

Successful masking (entity counts on an `allow` row, placeholders in the result) is the control working. It is not, by itself, a breach. A **miss** is.

## Breach assessment (HIPAA)

Treat a suspected miss that reached Grok Bot, or any other no-BAA party, as a potential impermissible disclosure. Walk the four factors in 45 CFR 164.402 and document the answers:

1. What identifier was involved, and how much.
2. Who received it (Grok Bot has no BAA; Cloudflare may have seen inbound tool args; StackJack/Composio are outside the written no-PHI scope if source data was PHI).
3. Whether the data was actually acquired or viewed.
4. How far mitigation got (block, token revoke, vendor notice).

Cap decides whether it is a breach under the HIPAA Breach Notification Rule. Joseph Masri is the private reporting contact for a vulnerability in this proxy. Reggie maps the control evidence. Marko handles the security review. Do not email raw samples to a vendor with no BAA.

## NYDFS

If the affected party is a DFS Covered Entity (confirm; exemptions in 23 NYCRR 500.19 may apply), the IR lead makes an explicit **72-hour** notification decision under 500.17 from the determination that a cybersecurity event occurred. Record the clock start, the decision, and who was told. This proxy does not send that notice by itself.

## FTC Safeguards

If the event involves customer information of **500 or more consumers**, the Qualified Individual's report includes a decision on the **30-day** FTC notice under 16 CFR 314.4(j). Record the count basis. Do not guess the count from an audit row; entity counts are not a consumer census.

## Containment

1. Revoke the caller bearer and, for Grok Bot, the Cloudflare Access service token.
2. Leave the proxy fail-closed (do not point tools at the vendors directly).
3. Preserve the audit log and config hash. Do not copy payloads into the ticket.
4. If the miss came from a recognizer gap, disable the tool in `config/allowlist.yaml` (a config-change audit row is required) rather than loosening Presidio.
5. Fallback for users is the Green lane only until the stack is trusted again.

## Afterward

Write the post-incident note: timeline, factors, notice decisions, and whether the recall floors or the allowlist need a Marko-reviewed change. Residual risk of misses remains accepted only while those gates stay in CI and the no-PHI rules above stay in force.
