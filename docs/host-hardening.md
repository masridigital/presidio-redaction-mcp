# Host hardening — Ubuntu Server LTS

This stack runs on its **own VM and VLAN**, not on the local-ai-stack host. The Cloudflare-exposed proxy must not be able to reach Red-lane Open WebUI, LiteLLM, or Postgres. Marko review is still NO-GO for deploy. Nothing here is to be applied to a production host from this draft.

## LUKS

Encrypt the VM disk at install, or put `/var/lib/docker` and `/var/lib/presidio-redaction-mcp` on a LUKS volume. Keep the passphrase or key escrow separate from the VM backup set. Disposal of a disk or snapshot is crypto-erase plus destruction of that escrow copy.

## UFW and Docker

`deploy/install.sh` installs a default-deny incoming and default-deny outgoing policy.

- Inbound: loopback, and SSH (tcp/22) only from `PRM_MGMT_CIDR` (the VPN or management subnet). The MCP listeners are not opened on the public interface. cloudflared makes an outbound connection; it does not need an inbound port.
- Outbound: loopback, DNS (tcp/udp 53), NTP (udp 123), then an explicit deny to anywhere else. Phase 1 upstream pins are `stackjack.invalid` and `composio.invalid`, so there is **no** general tcp/443 allow. A real StackJack or Composio host is added only after Marko confirms it is not an unintended Cloudflare path, and only as a named allow.
- Docker bypasses UFW by writing iptables. `deploy/ufw/docker-user.rules` appends a `DOCKER-USER` chain that returns established flows and loopback, then drops the rest. Compose publishes the proxy only on `127.0.0.1:8443` and `${PRM_VPN_BIND_ADDR:-10.8.0.1}:8444`. Presidio and the internal TLS proxy publish **no** host ports. The analyzer and anonymizer sit on the `presidio_internal` network (`internal: true`).

Inside the proxy container the process binds the address in `PRM_BIND_HOST` so Docker's published ports can reach it. That bind is not a host exposure.

## Unattended upgrades

Enable `unattended-upgrades` for security updates and a reboot window. Container image bumps are monthly, pinned by tag and digest, and reviewed by Marko before they roll. The installer can install the package; it does not start a production rollout from CI.

## CIS-style baseline

Ubuntu CIS L1 as the checklist, not a claim of certification:

- SSH keys only, no root login, no password auth. MFA is on the VPN that reaches SSH.
- auditd and AppArmor enabled. Time sync via NTP inside the egress rules above.
- Minimal packages. No Docker TCP socket. Prefer a non-root container user (the proxy image runs as uid 65532), `no-new-privileges`, `cap_drop: ALL`, read-only root filesystem, and tmpfs for `/tmp`.
- Live-restore and log size limits on the Docker daemon (`max-size` is set on the compose services). Journald and Docker logs must not record request or response bodies. The process forces `mcp`, `httpx`, and `uvicorn` loggers to WARNING and scrubs recognizer hits and bearer tokens from any line that still gets emitted.
- Admin shells and Docker are root-equivalent. Do not share this VM with the Red lane.

## TLS

Caller listeners are TLS 1.2+ (certificates from Docker secrets). Presidio's own images speak HTTP; nginx on the internal network terminates TLS in front of them, and the proxy verifies that internal CA. Production refuses to start without the certificate, key, and CA files. Presidio has no authentication of its own, which is why it has no published port.

## Log retention

Local journald and Docker json logs rotate. The proxy audit log is metadata only (caller, ingress, tool, keyed HMAC of args, entity counts, decision, config hash). Ship it to the SIEM. Retain **6 years** where the record is HIPAA documentation and **5 years** for a NYDFS 500.6 audit trail, with at least 1 year searchable online. Logs must stay free of raw PHI; CI asserts the synthetic corpus never appears in the audit file.

Who reviews: Joseph, weekly, for fail-closed events, `phi_in_cloudflare_tool_args`, denied tools, and entity-count spikes. Allowlist review monthly. Caller-token access review quarterly. Any allowlist expansion waits for Marko.

## Backups

restic or borg, encrypted, 3-2-1, with an immutable offsite copy. Back up config, recognizers, and audit logs. Do not back up Docker secret files into the same archive as the data without a separate key. Quarterly restore test. RTO/RPO 24h/24h is enough for this single-user tool. If the stack is down, the fallback is the Green lane only: no unredacted tool calls.

## Secrets

Docker secrets (mode 0444 in `/run/secrets`, not a committed `.env`). `.env.example` is placeholders. `compose.env` created by the installer is mode 0600 and holds no tokens. cloudflared tunnel credentials get the same treatment. The audit HMAC key is at least 32 bytes.
