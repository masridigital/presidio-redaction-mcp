# Native install — venv and systemd

Cap directive, 2026-10-15 23:26 ET: production is a native Ubuntu Server LTS install. Docker is not the production runtime. Each pip-installable app has its own virtualenv under `/opt/<app>`, its own non-login system user, and a hardened systemd unit. `docker-compose.yml` may stay in the repo for optional local development. It is not how this host is installed.

`deploy/install.sh` and `deploy/systemd/presidio-redaction-mcp.service` on the merged Phase 1 tree still start Docker. Do not run that script for a production host. This runbook is the procedure. The installer and the Ansible role that mirrors it have to match these steps before either is used. Ansible does not get a second layout.

This VM is the Yellow lane only. It does not run Open WebUI or LiteLLM. Those apps follow the same venv pattern on the Red-lane host.

## Layout

| App | Venv | User (nologin) | Listen |
|---|---|---|---|
| Presidio analyzer | `/opt/presidio-analyzer/venv` | `presidio-analyzer` | `127.0.0.1:3000` HTTP, gunicorn |
| Presidio anonymizer | `/opt/presidio-anonymizer/venv` | `presidio-anonymizer` | `127.0.0.1:3001` HTTP, gunicorn |
| Redaction proxy | `/opt/presidio-redaction-mcp/venv` | `presidio-proxy` | `127.0.0.1:8443` and the VPN address `:8444`, TLS |

cloudflared and WireGuard come from apt, not from a venv. cloudflared uses the Cloudflare apt repository. Nginx from apt terminates TLS for Presidio on `127.0.0.1:443` with `server_name presidio-tls`, so the allowlist URLs `https://presidio-tls/analyze` and `https://presidio-tls/anonymize` stay unchanged. `/etc/hosts` maps `presidio-tls` to `127.0.0.1`.

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

The analyzer and anonymizer HTTP apps are `app.py` and `logging.ini` from the `microsoft/presidio` tag `2.2.362` (`presidio-analyzer/` and `presidio-anonymizer/`). They are not inside the wheels. Copy those two files from that tag into `/opt/presidio-analyzer` and `/opt/presidio-anonymizer`. Do not start `python app.py`: that path binds `0.0.0.0`. The unit starts gunicorn on loopback:

```
/opt/presidio-analyzer/venv/bin/gunicorn -w 1 -b 127.0.0.1:3000 "app:create_app()"
/opt/presidio-anonymizer/venv/bin/gunicorn -w 1 -b 127.0.0.1:3001 "app:create_app()"
```

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
PRM_CF_PORT=8443
PRM_VPN_PORT=8444
PRM_AUDIT_PATH=/var/lib/presidio-redaction-mcp/audit/audit.jsonl
PRM_AUDIT_STATE=/var/lib/presidio-redaction-mcp/audit/config-sha
```

`PRM_VPN_BIND_HOST` is the VPN address on this host, not `0.0.0.0`. Tokens, the HMAC key, and TLS material are files in that directory, passed with systemd `LoadCredential=` so the service user reads them from the credential directory (`%d` in the unit). The unit sets `PRM_SECRET_FILE_<NAME>` and `PRM_TLS_CERT_FILE`, `PRM_TLS_KEY_FILE`, and `PRM_PRESIDIO_CA_FILE` to those credential paths. Do not put secret values in the env file. Do not use `/run/secrets`.

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
After=network-online.target presidio-analyzer.service presidio-anonymizer.service presidio-tls.service
Wants=network-online.target
Requires=presidio-analyzer.service presidio-anonymizer.service presidio-tls.service

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
LoadCredential=grok_cf_access_client_id:/etc/presidio-redaction-mcp/grok_cf_access_client_id
LoadCredential=grok_cf_access_client_secret:/etc/presidio-redaction-mcp/grok_cf_access_client_secret
LoadCredential=claude_local_token:/etc/presidio-redaction-mcp/claude_local_token
LoadCredential=open_webui_token:/etc/presidio-redaction-mcp/open_webui_token
Environment=PRM_TLS_CERT_FILE=%d/tls_cert
Environment=PRM_TLS_KEY_FILE=%d/tls_key
Environment=PRM_PRESIDIO_CA_FILE=%d/internal_ca
Environment=PRM_SECRET_FILE_AUDIT_HMAC_KEY=%d/audit_hmac_key
Environment=PRM_SECRET_FILE_GROK_BOT_TOKEN=%d/grok_bot_token
Environment=PRM_SECRET_FILE_GROK_CF_ACCESS_CLIENT_ID=%d/grok_cf_access_client_id
Environment=PRM_SECRET_FILE_GROK_CF_ACCESS_CLIENT_SECRET=%d/grok_cf_access_client_secret
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

`%d` is the systemd credentials directory. Analyzer and anonymizer units use the same hardening block, with `ExecStart` set to the gunicorn command above, `User=` set to that app's user, and `ReadWritePaths=` set to that app's `/var/lib` directory. They have no `LoadCredential=` entries. The TLS front is nginx from apt, bound to `127.0.0.1:443`, proxying `/analyze` to `127.0.0.1:3000` and `/anonymize` to `127.0.0.1:3001`, certificates from the same `/etc/presidio-redaction-mcp/` files.

Install the units under `/etc/systemd/system/`, then `systemctl daemon-reload` and `systemctl enable --now` each unit. Running the installer twice must leave the same users, modes, pins, and units (idempotent).

## Firewall

UFW default deny incoming and default deny outgoing.

- In: loopback, and SSH (tcp/22) only from `PRM_MGMT_CIDR` (the VPN or management subnet). No public listener for the proxy, Presidio, or nginx.
- Out, all hosts: loopback, DNS (tcp/udp 53), NTP (udp 123).
- Out, root, install and unattended-upgrades only: the Ubuntu archive and security mirrors, and the reviewed PyPI index used to build the venvs.
- Out, `cloudflared` user: tcp/443 for the tunnel. No inbound port.
- Out, WireGuard: udp to the configured peer only.
- `presidio-analyzer` and `presidio-anonymizer`: loopback only.
- `presidio-proxy`: loopback, plus a named allow only after Marko reviews a real upstream host. Phase 1 pins are `stackjack.invalid` and `composio.invalid`, so the proxy user has no general tcp/443 allow.

Per-user rules use the iptables owner match where UFW cannot express a uid. The proxy user does not inherit cloudflared's or root's egress.

## What the host must not do

- No Docker engine, no `docker compose up`, no Docker secrets, no `DOCKER-USER` chain.
- No published Presidio port. Presidio has no authentication of its own.
- No secret in git, in a unit file, or in the non-secret env file.
- No `PRM_BIND_HOST=0.0.0.0`.
