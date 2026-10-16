# Residual risk statement

Status: Draft. Pending Marko review. This is the Yellow-lane acceptance for presidio-redaction-mcp. It is not the enterprise risk analysis and it is not legal advice. Reggie's control map (2026-10-15) asked for a numeric recall floor per entity, a residual-risk statement, and a rule that the no-BAA assistant is not fed raw PHI. The floors are in `config/recall-floors.yaml`. The statement is this file. The caller rules are below and in `SECURITY.md`.

## Accepted risk

A completed Presidio pass can still miss an identifier, and that miss can reach Grok Bot. Presidio is a pattern and deny-list control. Coverage misses free text, unusual formats, and quasi-identifiers. Redaction is not HIPAA de-identification and is not Safe Harbor.

That risk is accepted only while all three of these stay true:

1. `config/recall-floors.yaml` is a CI gate. On the synthetic corpus the floor is 1.0 for every listed entity, for canonical rows and for adversarial rows. Masked or blocked both count as caught. Negatives must pass through. The entities are `PERSON`, `US_SSN`, `MRN`, `RECORD_ID`, `ACCOUNT_ID`, `NPI`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, `CREDIT_CARD`, `LOCATION`, and `DATE_OF_BIRTH`. A miss fails CI.
2. This statement stays in the repo.
3. A suspected miss starts the assessment in `docs/incident-response.md`: the HIPAA 164.402 four-factor record, the NYDFS 72-hour decision, and the FTC 30-day decision.

The 1.0 floor measures seeded fixtures (Faker seed 4242, header `SYNTHETIC`). It does not measure recall on clinical text.

Fail-closed behavior is a separate control, not this acceptance. Analyzer or anonymizer errors, timeouts, bad bodies, and truncated streams block the call. The accepted risk is a finished analysis that did not see the identifier.

## Rules that bound it

- Grok Bot is not a PHI caller. Callers do not put PHI in its tool arguments. A detection on the `external-nonphi` mark is blocked and audited as `phi_in_external_nonphi_tool_args`. There is no Cloudflare listener in this tree. A future edge that terminates TLS can see those arguments, and that row stays an incident candidate.
- PHI-capable callers (`claude-local`, `open-webui`) use the VPN listener only. Arguments are masked before a no-PHI upstream is called. A token on the wrong listener is 401 and makes no upstream call.
- StackJack and Composio have no BAAs. Cap's decision is the written no-PHI scope in `docs/upstream-scope-policy.md`. Day-1 tools are non-PHI. PHI in a result is redacted and is an incident candidate. It is not a reason to add a PHI tool, and it is not a prompt to request a BAA.
- There is no fallback to an unredacted tool. If this stack is down, users go to the Green lane only.
- Production is the venv and systemd install in `docs/native-install.md`. A container is not the runtime that this acceptance relies on.

## Risks that are not accepted

| Risk | Why it is outside this acceptance |
|---|---|
| Allowlist or egress drift | Config load rejects a third upstream, a wildcard, and a write, send, export, or bulk tool. UFW is default-deny, and the egress pins are `.invalid` until a reviewed host is added. A change without a `config_change` audit row is an incident. |
| Real PHI committed as a fixture | Fixtures carry the `SYNTHETIC` header. CI fails when they do not. gitleaks runs on the repo. |
| Pointing a PHI source at StackJack or Composio | Outside the written scope. Masking the result does not bring it back in scope. |

A vendor incident that affects non-PHI operational data those upstreams already hold is a third-party event for data this policy already excludes from PHI scope. It does not authorize sending PHI to close that gap.

## Review

Joseph reviews fail-closed events, `phi_in_external_nonphi_tool_args`, denied tools, and entity-count spikes weekly. The allowlist is reviewed monthly. Caller tokens are reviewed quarterly. A change to this acceptance, the floors, or the allowlist waits for Marko under `docs/allowlist-change-process.md`.
