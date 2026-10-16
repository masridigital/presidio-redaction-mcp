# Native install — venv and systemd

This page is the optional on-prem path. The primary deployment is Azure Container Apps, which the P2 lane is adding. Do not treat `deploy/install.sh` as that deployment.

Cap directive, 2026-10-15 23:26 ET, for the on-prem host: a native Ubuntu Server LTS install. Docker is not the runtime on that host. Each pip-installable app has its own virtualenv under `/opt/<app>`, its own non-login system user, and a hardened systemd unit. `docker-compose.yml` may stay in the repo for optional local development.

`deploy/install.sh` is this optional procedure, and `deploy/ansible/roles/presidio_redaction_mcp` mirrors it. Neither installs Docker. Ansible does not get a second layout.

This VM is the Yellow lane only. It does not run Open WebUI or LiteLLM. Those apps follow the same venv pattern on the Red-lane host.

## Layout

| App | Venv | User (nologin) | Listen |
|---|---|---|---|
| Presidio analyzer | `/opt/presidio-analyzer/venv` | `presidio-analyzer` | `127.0.0.1:5001` HTTP, `python -m presidio.serve` |
| Presidio anonymizer | `/opt/presidio-anonymizer/venv` | `presidio-anonymizer` | `127.0.0.1:5002` HTTP, stdlib `app.py`, unit not enabled |
| Redaction proxy | `/opt/presidio-redaction-mcp/venv` | `presidio-proxy` | VPN address `:8444`, TLS |

WireGuard comes from apt, not from a venv. There is no cloudflared package and no Cloudflare listener. Nginx from apt terminates TLS for Presidio on `127.0.0.1:443` with `server_name presidio-tls`, so the allowlist URLs `https://presidio-tls/analyze` and `https://presidio-tls/anonymize` stay unchanged. `/etc/hosts` maps `presidio-tls` to `127.0.0.1`. Production start requires `PRM_AUTH_MODE=entra`. The VPN bearer listener is lab-only.

Data directories sit on LUKS (full-disk encryption, or a LUKS volume that holds them):

- `/var/lib/presidio-analyzer`
- `/var/lib/presidio-anonymizer`
- `/var/lib/presidio-redaction-mcp` (audit log and config hash)

There is no `/var/lib/docker` path in this install.

## Pins

Install with `pip install --require-hashes`. A requirements file without hashes is a failed install.

| Component | Pin |
|---|---|
| `presidio-analyzer[server]` | `2.2.362` |
| `presidio-anonymizer[server]` | `2.2.362` |
| spaCy | `3.8.16` |
| `en_core_web_lg` | `3.8.0` |

The model is the wheel `en_core_web_lg-3.8.0-py3-none-any.whl` from the `en_core_web_lg-3.8.0` GitHub release. `python -m spacy download` is not the install. That command floats.

The analyzer HTTP app is `deploy/presidio/serve.py`. The unit starts it as `python -m presidio.serve` on `127.0.0.1` with `PRESIDIO_PORT` 5001. The anonymizer HTTP app is `deploy/presidio-anonymizer/app.py`. The installer copies that file to `/opt/presidio-anonymizer/app.py`. The unit runs it with the venv interpreter. It binds `PRESIDIO_BIND` (default `127.0.0.1`) and `PRESIDIO_PORT` (default 5002) and refuses `0.0.0.0`. Azure keeps the anonymizer image on port 3001. The native unit stays disabled.

The proxy pin is the version in `pyproject.toml`, installed from this repo into its venv:

```
/opt/presidio-redaction-mcp/venv/bin/pip install --require-hashes -r requirements/presidio-redaction-mcp.txt
```

The same shape of hashed file covers the analyzer and the anonymizer (`requirements/presidio-analyzer.txt`, `requirements/presidio-anonymizer.txt`). Hashes are generated from those pins and reviewed with the change. A bump of Presidio, spaCy, the model, or the proxy dependencies is a Marko review, same as an allowlist change (`docs/allowlist-change-process.md`).

## Secrets

Secrets live in `/etc/presidio-redaction-mcp/`, mode `0600`, owner root. They are never committed. `.env.example` is placeholders only.

Non-secret settings go in `/etc/presidio-redaction-mcp/presidio-redaction-mcp.env` (also `0600`):

```
PRM_ENV=production
LOG_LEVEL=INFO
PRM_CONFIG=/opt/presidio-redaction-mcp/config/allowlist.yaml
PRM_BIND_HOST=127.0.0.1
PRM_VPN_BIND_HOST=10.8.0.1
PRM_VPN_PORT=8444
PRM_AUDIT_PATH=/var/lib/presidio-redaction-mcp/audit/audit.jsonl
PRM_AUDIT_STATE=/var/lib/presidio-redaction-mcp/audit/config-sha
```

`PRM_VPN_BIND_HOST` is the VPN address on this host, not `0.0.0.0`. Tokens, the HMAC key, and TLS material are files in that directory, passed with systemd `LoadCredential=` so the service user reads them from the credential directory (`%d` in the unit). The unit sets `PRM_SECRET_FILE_<NAME>` and `PRM_TLS_CERT_FILE`, `PRM_TLS_KEY_FILE`, and `PRM_PRESIDIO_CA_FILE` to those credential paths. Do not put secret values in the env file. Do not use `/run/secrets`.

The optional Claude verifier is off unless `verifier.enabled` is true and `deployment` is Azure marked BAA. Its API key is not a unit environment value. On Azure, set `PRM_KEY_VAULT_URL` and `PRM_KEY_VAULT_SECRET` in the non-secret env file and read the secret with the host managed identity. A 0600 file at `PRM_SECRET_FILE_ANTHROPIC_API_KEY` is the LoadCredential alternative: add that credential to the unit only when the file exists, mode `0600` or `0400`. A deployment target marked non-BAA cannot enable the verifier. The process refuses to start that configuration.

## systemd

Every Python service uses `User=` set to its system user, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`, `CapabilityBoundingSet=` (empty), and `ReadWritePaths=` limited to its data directory. `ProtectHome=yes`, `PrivateDevices=yes`, and `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` are part of the same unit. The proxy unit also has `WorkingDirectory=/opt/presidio-redaction-mcp` and:

```
ExecStart=/opt/presidio-redaction-mcp/venv/bin/presidio-redaction-mcp
```

Order: analyzer and anonymizer, then the nginx TLS front (`presidio-tls.service`), then `presidio-redaction-mcp.service`. `Restart=on-failure`.

Proxy unit (`/etc/systemd/system/presidio-redaction-mcp.service`):

```
[Unit]
Description=Presidio redaction MCP proxy
After=network-online.target presidio-analyzer.service presidio-tls.service
Wants=network-online.target
Requires=presidio-analyzer.service presidio-tls.service

[Service]
Type=simple
User=presidio-proxy
Group=presidio-proxy
WorkingDirectory=/opt/presidio-redaction-mcp
EnvironmentFile=/etc/presidio-redaction-mcp/presidio-redaction-mcp.env
LoadCredential=tls_cert:/etc/presidio-redaction-mcp/tls_cert.pem
LoadCredential=tls_key:/etc/presidio-redaction-mcp/tls_key.pem
LoadCredential=internal_ca:/etc/presidio-redaction-mcp/internal_ca.pem
LoadCredential=audit_hmac_key:/etc/presidio-redaction-mcp/audit_hmac_key
LoadCredential=grok_bot_token:/etc/presidio-redaction-mcp/grok_bot_token
LoadCredential=claude_local_token:/etc/presidio-redaction-mcp/claude_local_token
LoadCredential=open_webui_token:/etc/presidio-redaction-mcp/open_webui_token
Environment=PRM_TLS_CERT_FILE=%d/tls_cert
Environment=PRM_TLS_KEY_FILE=%d/tls_key
Environment=PRM_PRESIDIO_CA_FILE=%d/internal_ca
Environment=PRM_SECRET_FILE_AUDIT_HMAC_KEY=%d/audit_hmac_key
Environment=PRM_SECRET_FILE_GROK_BOT_TOKEN=%d/grok_bot_token
Environment=PRM_SECRET_FILE_CLAUDE_LOCAL_TOKEN=%d/claude_local_token
Environment=PRM_SECRET_FILE_OPEN_WEBUI_TOKEN=%d/open_webui_token
ExecStart=/opt/presidio-redaction-mcp/venv/bin/presidio-redaction-mcp
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/var/lib/presidio-redaction-mcp
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
```

`%d` is the systemd credentials directory. The analyzer unit uses the same hardening block. The optional anonymizer unit runs `/opt/presidio-anonymizer/venv/bin/python /opt/presidio-anonymizer/app.py` with `PRESIDIO_PORT=5002` and `ConditionPathExists=/opt/presidio-anonymizer/app.py`. The installer copies that file and does not enable the unit. The anonymizer that runs in Azure is the digest-pinned image on port 3001. A `python -c` process that exits 0 is not a server. The TLS front is nginx from apt, bound to `127.0.0.1:443`, proxying `/analyze` to `127.0.0.1:5001` and `/anonymize` to `127.0.0.1:5002`, certificates from the same `/etc/presidio-redaction-mcp/` files.

Install the units under `/etc/systemd/system/`, then `systemctl daemon-reload`. Enable the analyzer and the proxy. Leave `presidio-anonymizer.service` disabled. Running the installer twice must leave the same users, modes, pins, and units (idempotent).

## Firewall

UFW default deny incoming and default deny outgoing.

- In: loopback, and SSH (tcp/22) only from `PRM_MGMT_CIDR` (the VPN or management subnet). No public listener for the proxy, Presidio, or nginx.
- Out, all hosts: loopback, DNS (tcp/udp 53), NTP (udp 123).
- Out, root, install and unattended-upgrades only: the Ubuntu archive and security mirrors, and the reviewed PyPI index used to build the venvs.
- No cloudflared egress. This install has no tunnel.
- Out, WireGuard: udp to the configured peer only.
- `presidio-analyzer` and `presidio-anonymizer`: loopback only.
- `presidio-proxy`: loopback, plus a named allow only after Marko reviews a real upstream host. Phase 1 pins are `stackjack.invalid` and `composio.invalid`, so the proxy user has no general tcp/443 allow.

Per-user rules use the iptables owner match where UFW cannot express a uid. The proxy user does not inherit root's egress.

## What the host must not do

- No Docker engine, no `docker compose up`, no Docker secrets, no `DOCKER-USER` chain.
- No published Presidio port. Presidio has no authentication of its own.
- No secret in git, in a unit file, or in the non-secret env file.
- No `PRM_BIND_HOST=0.0.0.0`.
