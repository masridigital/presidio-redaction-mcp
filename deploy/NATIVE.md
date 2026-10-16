# Native host (Ubuntu Server LTS)

Azure Container Apps is the primary deployment (`infra/`, `docs/azure-deploy.md`). This file is the optional native Ubuntu path. `host/install.sh` (also `deploy/install.sh`) is idempotent: apt packages, three Python venvs, hardened systemd units, UFW, and the per-user egress chain. The proxy unit starts the venv entrypoint. It does not start a container engine. `docker-compose.yml` is an optional dev file and is not the deploy path.

## Processes

| Unit | User | Bind |
|---|---|---|
| `presidio-analyzer.service` | `presidio-analyzer` | `127.0.0.1:5001` TLS |
| `presidio-anonymizer.service` | `presidio-anonymizer` | `127.0.0.1:5002` TLS |
| `presidio-redaction-mcp.service` | `presidio-proxy` | `10.8.0.1:8444` TLS in lab. Production is the private Entra listener. |
| `presidio-wg0.service` | root (wg-quick) | `10.8.0.1/24`, listen UDP 51820 |

Each app unit sets `ProtectSystem=strict`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, and an empty `CapabilityBoundingSet=`. Versions are hash-pinned (`pip install --require-hashes`). The spaCy model is `en_core_web_lg` 3.8.0, sha256 `293e9547a655b25499198ab15a525b05b9407a75f10255e405e8c3854329ab63`.

Secrets are root-owned files under `/etc/presidio-redaction-mcp/secrets` (mode 0600), passed with systemd `LoadCredential`. Production refuses `PRM_SECRET_*` environment variables. The installer does not write secret values.

Data directories under `/var/lib/presidio-*` must sit on LUKS. `PRM_REQUIRE_LUKS=1` fails the install when they do not. IP forwarding stays off so this VM is not a route to any other lane.

## Firewall (Q2 and Q3)

UFW default-deny incoming and outgoing.

- SSH (tcp/22) only from `PRM_MGMT_CIDR` (default `10.8.0.0/24`).
- WireGuard handshake UDP 51820. The MCP port is not open on the public interface.
- TCP 8444 is allowed only on `wg0` to `10.8.0.1`. That is the optional lab listener.
- TCP 8443 is not in UFW.
- Outbound for everyone else: loopback, DNS, NTP, then deny.

`PRM-OUTPUT` / `PRM-OUTPUT6` (owner match), installed ahead of the UFW output rules:

- `presidio-proxy`, `presidio-analyzer`, and `presidio-anonymizer` may use loopback only on this optional VM path. StackJack and Composio stay at `stackjack.invalid` and `composio.invalid` until a reviewed host is named. There is no general tcp/443 allow. The P4 verifier may egress to Anthropic under the Anthropic BAA. That is not an open egress rule for this proxy. The Microsoft BAA deployment is Azure (`infra/`, `docs/azure-deploy.md`), not this VM script.

## Ingress

Production callers authenticate with Entra ID through Azure API Management on a private ingress. The container re-validates the JWT. Production refuses to start unless `auth_mode` is `entra`. Cloudflare Tunnel is not part of this deploy. PHI-capable callers on the optional VM use WireGuard. `deploy/wireguard/wg0.conf.template` is not installed as a live `wg0.conf`. Peers are `10.8.0.2/32` and upward. The VPN listener rejects a client IP outside `10.8.0.0/24`.

There is no Cloudflare listener and no grok-bot service token. The `cloudflare` value on grok-bot is a non-PHI policy mark. Edge choices for a future door are in `docs/grok-bot-edge-options.md`. Cloudflare Access JWTs are not accepted.

## Result hits for grok-bot

A Presidio hit in a tool result headed to grok-bot, or to any caller who is not an Entra-authenticated PHI caller on the private ingress, is **blocked** (`phi_in_non_baa_tool_result`), not masked and returned. grok-bot stays usable because its allowlist is the structured tools `stackjack_health_check`, `stackjack_get_service_status`, and `UPTIMEROBOT_GET_MONITORS`, and free-text, date, and IP fields are dropped before redaction. A hit that remains in an allowed field is still blocked. Tool arguments for a caller marked `cloudflare` are blocked when any entity is detected (`phi_in_cloudflare_tool_args`). Masked results are returned only to a PHI caller authenticated with Entra on the private ingress. The optional anonymizer unit is not enabled. The anonymizer in Azure is the digest-pinned image.

## Audit

Each audit line carries `prev_hash` and an HMAC `row_hash` over the previous line, so a changed line breaks `AuditLog.verify()`. `PRM_AUDIT_FORWARD=syslog` copies the metadata line to local syslog. `PRM_AUDIT_FORWARD=file:/path` appends it for a SIEM shipper. The line has no argument text.

## What is still not a deploy

Real StackJack and Composio hosts are not on the egress list. Recognizers in this repo are the synthetic corpus, not a HIPAA catalog. Marko’s deploy gate (real recognizers, real Presidio recall, vendor Cloudflare status) is unchanged.
