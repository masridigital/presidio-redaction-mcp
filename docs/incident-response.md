# Incident response — redaction proxy

Operational runbook for a DLP failure on the Yellow lane. Cap's counsel and SOP-SEC-010 govern the legal determination and any notice that is actually sent. This file is the assessment and containment record for the proxy. It is not a full enterprise IRP and it is not legal advice. Do not put raw PHI in tickets, chat, or this repo.

Trace: Reggie control map, HIPAA 164.308(a)(6) and 164.402, NYDFS 500.16 and 500.17, FTC 314.4(h) and 314.4(j). See `docs/control-map-traceability.md`.

## When this runs

Open a review when any of the following is true:

- Audit reason `phi_in_external_nonphi_tool_args` (an external-nonphi caller put identifier-bearing tool arguments on a path where Presidio blocked them).
- A sampling review, user report, or upstream log shows an identifier that the proxy returned or forwarded unmasked.
- Presidio failed open in any other component (this proxy is built to fail closed; a fail-open report is itself the incident).
- The allowlist changed without a `config_change` audit row, or a tool outside the day-1 list was observed.
- A day-1 tool returned data that is PHI in the source, which is outside `docs/upstream-scope-policy.md` even if the proxy masked the result.
- Reason code `store_signature_invalid`. The proxy workspace alerts on that line. Recovery for a junk or unsigned version file under a locked policy is a new container and a re-publish, in `docs/signing-key-rotation.md`.

Successful masking (entity counts on an allow row, placeholders in the result) is the control working. It is not, by itself, a breach. A miss is.

## Roles

- Cap decides whether the event is a breach and whether a notice goes out.
- Joseph Masri is the private reporting contact for a vulnerability in this proxy, and reviews the audit log weekly (fail-closed events, Cloudflare PHI blocks, denied tools, entity-count spikes).
- Marko handles the security review, including any allowlist change that comes out of the incident.
- Reggie maps the control evidence.
- This proxy does not send a regulatory notice.

## Breach assessment (HIPAA 164.402)

Treat a suspected miss that reached Grok Bot, or any other party outside a BAA, as a potential impermissible disclosure. An impermissible use or disclosure is presumed to be a breach unless a documented risk assessment shows a low probability that the PHI was compromised. Walk at least these four factors from 45 CFR 164.402 and write the answers in the ticket. Use reason codes, entity types, and counts. Do not paste the payload.

1. The nature and extent of the PHI: which identifier types, how much, and the likelihood of re-identification.
2. The unauthorized person who used the PHI or received the disclosure. Grok Bot has no BAA. Cloudflare may already have seen inbound tool arguments on the tunnel. StackJack and Composio are outside the written no-PHI scope if the source data was PHI.
3. Whether the PHI was actually acquired or viewed.
4. The extent of mitigation (block, token revoke, tool disabled, vendor notified without a raw sample).

Cap decides whether the presumption is overcome and whether the Breach Notification Rule applies. Do not email raw samples to a party that has no BAA.

## NYDFS — 72 hours

Counsel confirms whether the affected organization is a DFS Covered Entity and whether an exemption in 23 NYCRR 500.19 applies. When 500.17 applies, notice to the superintendent is due as promptly as possible and no later than 72 hours after the determination that a cybersecurity incident occurred. The incident lead records three things: the clock start (that determination, not the first alert), the notify-or-not decision, and who was told. This proxy does not send the notice.

## FTC Safeguards — 30 days

When the event is a notification event involving customer information of at least 500 consumers, 16 CFR 314.4(j) requires notice to the FTC as soon as possible and no later than 30 days after discovery. The Qualified Individual's report includes that decision and the basis for the consumer count. An audit-row entity count is not a consumer census. Do not derive the count from it. This proxy does not file the notice.

## Containment

1. Revoke the caller bearer and, for Grok Bot, the Cloudflare Access service token.
2. Leave the proxy fail-closed. Do not point tools at StackJack or Composio directly.
3. Preserve the audit log and the config hash. The ticket gets timestamps, caller profile, ingress, upstream, tool name, and reason code. It does not get argument text or result bodies.
4. If the miss came from a recognizer gap, disable the tool in `config/allowlist.yaml` through `docs/allowlist-change-process.md` rather than loosening Presidio. The next start must write a `config_change` row.
5. Fallback for users is the Green lane only until the stack is trusted again.
6. Stop the proxy only when fail-closed is not holding: `systemctl stop presidio-redaction-mcp`. That stops the venv process. Stop `presidio-analyzer`, `presidio-anonymizer`, and `presidio-tls` as well when the miss is on the Presidio hop. Restart, after the cause is fixed and the synthetic suite has been re-run, is `systemctl restart presidio-analyzer presidio-anonymizer presidio-tls presidio-redaction-mcp`. There is no compose project to bring down. Unit layout is in `docs/native-install.md`.

## Afterward

Write the post-incident note: timeline, the four factors, the NYDFS decision, the FTC decision, and whether the recall floors or the allowlist need a Marko-reviewed change. Residual risk of misses stays accepted only while the gates in `docs/residual-risk.md` stay in force.

Keep the note with the ticket. The policy record is retained 6 years (HIPAA 164.316). Audit-log retention is in `docs/host-hardening.md` (6 years where the row is HIPAA documentation, 5 years for a NYDFS 500.6 audit trail).
