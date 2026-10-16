# Host hardening — Ubuntu Server LTS

This stack runs on its **own VM and VLAN**, not on the local-ai-stack host. The Cloudflare-exposed proxy must not be able to reach Red-lane Open WebUI, LiteLLM, or Postgres. Production install is native: venvs and systemd, as in `docs/native-install.md`. Cap's directive of 2026-10-15 23:26 ET is the standard. Docker is not the production runtime.

`deploy/install.sh` on the merged Phase 1 tree still installs Docker. Do not point it at a production host. Follow `docs/native-install.md` until that script and its Ansible mirror match the runbook.

## LUKS

Encrypt the VM disk at install, or put the data directories on a LUKS volume:

- `/var/lib/presidio-analyzer`
- `/var/lib/presidio-anonymizer`
- `/var/lib/presidio-redaction-mcp`

Keep the passphrase or key escrow separate from the VM backup set. Disposal of a disk or snapshot is crypto-erase plus destruction of that escrow copy.

## UFW

Default deny incoming and default deny outgoing. The written allowlist is in `docs/native-install.md`. Inbound is loopback plus SSH from `PRM_MGMT_CIDR` only. The proxy listens on `127.0.0.1:8443` (cloudflared, outbound) and on the VPN address `:8444`. Presidio listens on `127.0.0.1` only. Nginx for `presidio-tls` listens on `127.0.0.1:443` only.

Egress is per service user where the firewall can express it. Analyzer and anonymizer users stay on loopback. The proxy user does not get a general tcp/443 allow. cloudflared (apt) is the user that may open the tunnel. WireGuard (apt) may speak only to its configured peer.

## Unattended upgrades

Enable `unattended-upgrades` for Ubuntu security updates and a reboot window. Python dependencies and the spaCy model do not move that way. They move when the hashed requirements file changes and Marko has reviewed the pin (`pip install --require-hashes`). See `docs/native-install.md`.

## CIS-style baseline

Ubuntu CIS L1 as the checklist, not a claim of certification:

- SSH keys only, no root login, no password auth. MFA is on the VPN that reaches SSH.
- auditd and AppArmor enabled. Time sync via NTP inside the egress rules above.
- Minimal packages. No Docker engine.
- Each service is a non-login system user. The unit sets `ProtectSystem=strict`, `NoNewPrivileges=yes`, `PrivateTmp=yes`, and an empty `CapabilityBoundingSet=`.
- Journald must not record request or response bodies. The process forces `mcp`, `httpx`, and `uvicorn` loggers to WARNING and scrubs recognizer hits and bearer tokens from any line that still gets emitted.
- Admin shells are root-equivalent. Do not share this VM with the Red lane.

## TLS

Caller listeners are TLS 1.2+. Certificate and key are `LoadCredential=` from `/etc/presidio-redaction-mcp/` (mode `0600`, root). Presidio's HTTP servers have no TLS and no authentication, so they bind loopback and nginx on `127.0.0.1:443` presents the internal certificate for `presidio-tls`. The proxy verifies that CA (`PRM_PRESIDIO_CA_FILE`). Production refuses to start without the certificate, key, and CA files.

## Log retention

Journald rotates local logs. The proxy audit log is metadata only (caller, ingress, tool, keyed HMAC of args, entity counts, decision, config hash) under `/var/lib/presidio-redaction-mcp/audit/`. Ship it to the SIEM. Retain **6 years** where the record is HIPAA documentation and **5 years** for a NYDFS 500.6 audit trail, with at least 1 year searchable online. Logs must stay free of raw PHI; CI asserts the synthetic corpus never appears in the audit file.

Who reviews: Joseph, weekly, for fail-closed events, `phi_in_cloudflare_tool_args`, denied tools, and entity-count spikes. Allowlist review monthly. Caller-token access review quarterly. Any allowlist expansion waits for Marko.

## Backups

restic or borg, encrypted, 3-2-1, with an immutable offsite copy. Back up config, recognizers, and audit logs. Secret files under `/etc/presidio-redaction-mcp/` use a separate key from the data archive. Quarterly restore test. RTO/RPO 24h/24h is enough for this single-user tool. If the stack is down, the fallback is the Green lane only: no unredacted tool calls.

## Secrets

`/etc/presidio-redaction-mcp/*` mode `0600`, owner root, or systemd `LoadCredential=` from those files. Nothing secret is written into the repo, the unit, or the non-secret env file. The audit HMAC key is at least 32 bytes. cloudflared tunnel credentials get the same directory treatment.
