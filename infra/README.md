# Infrastructure

Two templates. Neither is applied by CI.

## Proxy — `main.bicep`

Azure Container Apps for the redaction proxy, internal ingress, system-assigned identity, Key Vault, and API Management. `PRM_CONFIG_STORE` is required. Pass the blob URL published by the portal template and two HMAC keys that differ from each other and from the proxy tool-call audit key:

- `configStoreUrl` — `https://<account>.blob.core.windows.net/prm-config`
- `storeHmacKey` — signs versions, proposals, and the active pointer
- `adminAuditHmacKey` — the admin audit chain the proxy verifies

The proxy identity reads that container with a bearer token. Do not enable shared-key access on the account.

## Admin portal — `admin-portal.bicep`

Internal Container Apps environment, user-assigned managed identity, Key Vault, and a private blob container. Shared keys are off (`allowSharedKeyAccess: false`). There is no file share and no `listKeys()` call. Container Apps cannot mount Azure Files with a managed identity, so the store is blob storage. See `docs/best-practices-compliance.md`.

`maxReplicas` is 1. Publish takes a blob lease and an `If-Match` ETag. Leave the replica count at 1 until that lease is the only writer.

Build the image from the repository root:

```bash
docker build -f admin/Dockerfile -t prm-admin:latest .
```

Supply the three HMAC keys outside git. The example values are placeholders. The process refuses a placeholder and refuses two keys that are equal.

```bash
az deployment group create \
  --resource-group <resource-group> \
  --template-file infra/admin-portal.bicep \
  --parameters infra/parameters.example.json
```

Replace the nil subnet, DNS zone, client id, and deployer object id before deploying. `deployerPrincipalType` is `User` for a person and `ServicePrincipal` for a pipeline. The deployer is granted Key Vault Secrets Officer so the template can create secrets. The portal identity is granted Secrets User and Storage Blob Data Contributor.

After deploy, add a federated credential on the portal app registration. Issuer `https://login.microsoftonline.com/<tenant>/v2.0`, subject the `managedIdentityPrincipalId` output, audience `api://AzureADTokenExchange`. A certificate credential is the alternative. There is no client secret.

`publishToVnet` stays true. On an internal environment that publishes the app to the internal load balancer. It does not create a public IP.

The portal listens on port 8080 inside the container. The platform ingress is HTTPS.
