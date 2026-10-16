# Presidio admin portal

Management plane for the redaction proxy. It publishes a versioned config the proxy reads at startup. An invalid or tampered document fails closed: the proxy exits and the portal reports unhealthy.

There is no Mastery MCP or `masridigital/Masri-MCP` repository in the org. The pages follow the usual controls for this kind of portal: a closed connector list, a default-deny tool allowlist, registered clients, an Admin role, an append-only audit chain, and two-person approval. Citations for the Microsoft controls are in `docs/best-practices-compliance.md`.

## What an Admin can change

| Area | Rule |
| --- | --- |
| Upstreams | StackJack and Composio only. A third upstream is rejected. |
| Tools | Catalog tools only, all read-only. They start disabled. Enabling one waits for a second Admin. |
| Clients | Pre-registered Entra app ids. App role `PHI` is a human PHI caller. `NonPHI` is a workload. The proxy enforces that mapping. No client secret is stored. There is no dynamic client registration. |
| Recognizers | Synthetic patterns from the day-1 catalog. Scores can move. Regexes cannot. |
| Score threshold | Presidio minimum score. Floor is 0.4. Lowering it, or raising the floor, waits for a second Admin. |
| Claude verifier | Off by default, matching the proxy. Turning it on publishes immediately and is still refused unless the deployment is Azure and marked BAA. Turning it off waits for a second Admin. |

The Admin who proposes a risky change cannot approve it. Tightening a control (disabling a tool, disabling an upstream, turning the verifier back on, disabling a client) publishes immediately and is still audited.

## Run locally

Use synthetic values only. The process refuses an HMAC key shorter than 32 bytes and refuses a value that still says `replace-with`.

```bash
export PRM_ENV=test
export PRM_ADMIN_BIND=127.0.0.1
export PRM_STORE_HMAC_KEY="$(python -c 'print("s"*32)')"
export PRM_ADMIN_AUDIT_HMAC_KEY="$(python -c 'print("a"*32)')"
export PRM_ADMIN_SESSION_HMAC_KEY="$(python -c 'print("e"*32)')"
export PRM_ADMIN_CLIENT_ID=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa
export PRM_ADMIN_JWKS_FILE=/path/to/synthetic-jwks.json
export PRM_CONFIG_STORE=/tmp/prm-admin-store
python -m presidio_admin
```

The three keys must differ, and they must differ from `PRM_SECRET_AUDIT_HMAC_KEY`. Token exchange uses `PRM_ADMIN_ASSERTION=managed_identity` or `certificate`. There is no client secret. A session goes idle after 15 minutes and the cookie requires `nbf`.

The approvals page shows the metadata diff, the base hash, and the proposed hash. The `Admin` role is a group of named accounts reviewed every quarter. A sealed break-glass account alerts Chief and Cap on use and does not skip approval. See `docs/best-practices-compliance.md`.

`PRM_ADMIN_JWKS_FILE` skips the network call to Entra. In Azure the file is unset and the process loads the tenant JWKS at startup.

Sign-in redirects to `https://login.microsoftonline.com/f7812296-5bce-41dc-8102-b1b270e7c4c7`. The access token must include the `Admin` app role, an `amr` value of `mfa` or `ngcmfa`, and `acrs` containing `c1` (or `PRM_ADMIN_ACRS`). Conditional Access is what forces the MFA prompt. The claim checks are the in-app confirmation.

## Proxy

Set `PRM_CONFIG_STORE` to the same directory, or to `https://<account>.blob.core.windows.net/prm-config`. Production and Entra mode refuse to start when that variable is unset (`require_published_config: true`). The proxy verifies the store signature with `PRM_STORE_HMAC_KEY`, verifies the admin audit chain with `PRM_ADMIN_AUDIT_HMAC_KEY`, and exits if the active version is missing, rolled back, or not anchored on the chain. Startup and `/healthz` log the version id and hash. Published tool toggles, the verifier switch, and the PHI client mapping are enforced. They cannot add a tool the allowlist does not already name.

One replica writes the store. The writer takes a lease and an ETag. Do not scale the portal past one replica until that lease is the only writer.

## Tests

```bash
pytest admin/tests tests/test_published_config.py
```
