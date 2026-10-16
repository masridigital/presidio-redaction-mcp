# Infrastructure

Two templates. Neither is applied by CI.

## Proxy — `main.bicep`

Azure Container Apps for the redaction proxy, internal ingress, system-assigned identity, Key Vault, and API Management. `PRM_CONFIG_STORE` is required. Pass the URLs published by the portal template:

- `configStoreUrl` — `https://<account>.blob.core.windows.net/prm-config`
- `signingKeyUrl` — `https://<vault>.vault.azure.net/keys/prm-config-signing`
- `versionFloorUrl` — `https://<account>.blob.core.windows.net/prm-floor`

The proxy verifies the signing key. It does not receive a private key or an HMAC for the store. Its tool-call audit HMAC stays a separate key on the host. The proxy identity reads `prm-config` with a bearer token and is the only writer of the version floor. Do not enable shared-key access on the account.

Deploy the portal template first so those three outputs exist, and pass the proxy identity's principal id in as `proxyPrincipalId`. That assignment is verify-only on the key.

## Admin portal — `admin-portal.bicep`

Internal Container Apps environment, user-assigned managed identity, Key Vault, and a private blob account. Shared keys are off (`allowSharedKeyAccess: false`). Blob versioning is on. `prm-config` has an immutability policy that does not allow protected appends. `prm-floor` allows them so the proxy can append `floor.jsonl`. There is no file share and no `listKeys()` call. Container Apps cannot mount Azure Files with a managed identity, so the store is blob storage. See `docs/best-practices-compliance.md` and `docs/signing-key-rotation.md`.

`maxReplicas` is 1. Publish takes a blob lease and an `If-Match` ETag. Leave the replica count at 1 until that lease is the only writer.

The portal identity is Storage Blob Data Contributor on `prm-config` only. It cannot write the floor. Key Vault generates `prm-config-signing` (RSA 2048, sign and verify). The portal role can sign and can create the session secret. The proxy role can read and verify.

Build the image from the repository root, push it, and pass the digest. `containerImage` must be `repository@sha256:<digest>`. A deployment without that pin fails before the container app is created. A floating tag is not an accepted example.

```bash
docker build -f admin/Dockerfile -t example.azurecr.io/prm-admin:build .
```

`containerImage` in the parameter file is `example.azurecr.io/prm-admin@sha256:` plus the digest of that push. The example digest is synthetic.

```bash
az deployment group create \
  --resource-group <resource-group> \
  --template-file infra/admin-portal.bicep \
  --parameters infra/parameters.example.json
```

Replace the nil subnet, DNS zone, client id, deployer object id, and proxy principal id before deploying. `deployerPrincipalType` is `User` for a person and `ServicePrincipal` for a pipeline. The deployer is granted Key Vault Crypto Officer so the template can create the signing key. There is no HMAC deployment parameter. The session secret `session-hmac-key` is created by the portal on first start.

After deploy, add a federated credential on the portal app registration. Issuer `https://login.microsoftonline.com/<tenant>/v2.0`, subject the `managedIdentityPrincipalId` output, audience `api://AzureADTokenExchange`. A certificate credential is the alternative. There is no client secret.

`publishToVnet` stays true. On an internal environment that publishes the app to the internal load balancer. It does not create a public IP.

The portal listens on port 8080 inside the container. The platform ingress is HTTPS.
