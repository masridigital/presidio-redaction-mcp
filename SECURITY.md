# SECURITY — presidio-redaction-mcp

- **Purpose:** risk reduction for Yellow-lane tool data. Redaction ≠ HIPAA de-identification; the no-PHI rule for Grok Bot remains.
- **Fail closed:** any Presidio error, timeout, or unexpected response blocks the call; results are discarded, never passed through.
- **Least privilege:** default-deny per-upstream tool allowlist; read-only first; no bulk export; pagination caps; field allowlists. Exactly two upstreams (StackJack, Composio). Upstream credentials read-only and tenant-scoped (upstream permissions are the ceiling).
- **Auth:** Cloudflare Access service token per assistant + in-app bearer token per assistant (separate for Grok Bot and Claude), 90-day rotation; optional Entra OIDC.
- **Exposure:** Cloudflare Tunnel + Access restricted to `/mcp`, WAF + rate limits; or VPN. Never a raw port forward or public IP. Cloudflare has no BAA: only redacted data may cross it; upstream legs never traverse the tunnel.
- **Audit:** caller, tool, args hash, entity counts, decision; no raw PII in logs.
- **Secrets:** env/vault only; gitleaks in CI.
- **Test data:** synthetic only; no real PHI, client, or Lumina data.
- **Change control:** Marko security review before any merge/deploy/exposure.
- **Reporting:** report vulnerabilities privately to Joseph Masri.
