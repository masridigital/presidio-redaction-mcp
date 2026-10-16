# presidio-redaction-mcp

Fail-closed redaction proxy in front of StackJack and Composio. Presidio and the deterministic recognizers run on tool arguments and on tool results. The proxy returns a reason code when that pass cannot finish.

## Optional Claude verifier

A second pass is available and **off by default** (`verifier.enabled: false` in `config/allowlist.yaml`).

Order, when it is enabled: raw text, then Presidio plus the deterministic recognizers, then Claude on the **already redacted** text, then forward. It runs on both inputs and tool results. The call does not move on when either pass flags an identifier, or when Claude is uncertain, times out, errors, or returns a body that is malformed, echoed, or steered by the content.

Claude is called only as the plain Messages API (`POST https://api.anthropic.com/v1/messages`) under Cap's Anthropic BAA with zero data retention. The model must be on the explicit allowlist. Fable and Mythos are rejected because they require 30-day retention. The request sends no beta header, tools, files, batches, or web search. Structured output is a JSON schema: a verdict of `clear`, `phi`, or `uncertain`, plus span offsets and entity types. There is no free-text field. The proxy treats that body as untrusted, validates it again, and rejects anything else. Content is delimited. Instruction-like overrides fail closed before the verdict is trusted.

The verifier may be enabled only when `deployment.target` is `azure` and `deployment.baa` is true (Azure under the Microsoft BAA). A target marked non-BAA, including Cloudflare, refuses to start with the verifier on. Cloudflare has no BAA. Verifier traffic is pinned to `api.anthropic.com` and is rejected if the host is a Cloudflare name.

The API key is read from Azure Key Vault (`PRM_KEY_VAULT_URL`, `PRM_KEY_VAULT_SECRET`, managed identity) or from a `0600`/`0400` file (`PRM_SECRET_FILE_ANTHROPIC_API_KEY`, including systemd `LoadCredential`). It is not stored in the repo or in the non-secret env file. Verifier audit rows are HMAC metadata only.

Recall tests use realistic-format synthetic values and a mocked Anthropic client. A live call is opt-in: set `PRM_VERIFIER_LIVE=1` and `PRM_SECRET_FILE_ANTHROPIC_API_KEY` to a `0600` file. CI does not set that variable.

## Install

The primary deployment is Azure Container Apps, which the P2 lane is adding. `deploy/install.sh` is an optional on-prem path only. It is idempotent, uses a venv and systemd, and does not install Docker. The Ansible role `deploy/ansible/roles/presidio_redaction_mcp` mirrors that optional path. `docker-compose.yml` is optional local development. The on-prem procedure is `docs/native-install.md`.

## Tests

```bash
pip install -e ".[dev]"
pytest
```
