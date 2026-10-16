# LiteLLM MCP gateway spike (acceptance tests 1–4)

Pinned revision: LiteLLM **v1.96.0** (tag `v1.96.0`, published 2026-08-10), file `litellm/proxy/guardrails/guardrail_hooks/presidio.py` at that tag. Docs checked 2026-10-16: [PII masking v2](https://docs.litellm.ai/docs/proxy/guardrails/pii_masking_v2) and [MCP guardrails](https://docs.litellm.ai/docs/mcp_guardrail). This spike did not boot a LiteLLM proxy. The fail-closed result is a property of the pinned source, not of a missing container.

Phase 1 does **not** switch to LiteLLM. Tests 1–4 are not all met, and Marko's review says a pass of 1–4 would still be insufficient (streaming, non-text, route coverage). A later pin may be reconsidered only if tests 1–10 plus non-text and streaming pass on that pin.

## Results

| Test | Result | Why |
|---|---|---|
| 1. Inbound args masked before the upstream | Not met as a guarantee | `pre_mcp_call` is a supported Presidio hook in v1.96.0 and can mask tool arguments when the guardrail is actually registered (`default_on`, and not skipped at startup). Registration is best-effort: an unsupported mode logs an error and the proxy keeps starting. Key, team, and policy attachment has missed inbound MCP gateway calls in later fixes. That is not a mandatory choke point. |
| 2. Outbound results masked before the caller | Not met as a guarantee | v1.96.0 adds `post_mcp_call` and lists it on the Presidio class. The same release notes say tool results previously bypassed every guardrail. Images and embedded resources are not scanned. With `output_parse_pii`, the response path can unmask instead of scanning new values in the result. The Presidio doc's supported-mode table still leads with `pre_mcp_call` and does not treat result masking as the default. |
| 3. Fail closed on analyzer/anonymizer down, timeout, malformed body | **Fail** | In v1.96.0 `_fail_on_invalid_response`, `should_fail_closed` is true only when `pii_entities_config` or `output_parse_pii` or `apply_to_output` is set. Otherwise the analyzer error returns `[]` and the original text is kept. `mask_pii_fail_closed` is **not** in this tag (later PR #31062 adds it as opt-in, default false). Empty text is skipped. Streaming gaps are called out in PR #31063, also opt-in. A Presidio outage can pass raw tool data. |
| 4. Unknown upstream, non-allowlisted tool, or bulk/export denied | **Fail** | LiteLLM will host whatever MCP servers are configured. It does not reject a config whose upstream set is anything other than `stackjack` and `composio`, and it does not reject wildcard tools or write/send actions as a schema rule. Per-key tool grants are allow-by-configuration, not this repo's default-deny file. |

## Decision

Build the custom Streamable HTTP proxy in this repo. Enforcement has to be mandatory on both directions, fail closed on every Presidio failure including a truncated stream, and refuse any upstream other than the two named mocks. LiteLLM remains the Red-lane component in local-ai-stack; it is not the Yellow-lane choke point.
