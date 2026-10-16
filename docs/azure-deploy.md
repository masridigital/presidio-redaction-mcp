# Azure deploy

Azure Container Apps is the primary deployment. This file is the contract. CI does not deploy it.

## What runs

One Container App in an internal Container Apps environment (`vnetConfiguration.internal: true`). Three containers share the replica network namespace:

- `proxy` listens on 8080. That is the only ingress, and `external` is false. API Management, on an internal subnet, is the caller.
- `analyzer` is the custom image from `deploy/presidio/Dockerfile`. `PRESIDIO_BIND=127.0.0.1` and `PRESIDIO_PORT=3000`. It has no ingress of its own and no public IP.
- `anonymizer` is the digest-pinned MCR anonymizer image on port 3001. It has no ingress of its own.

The MCR analyzer image is not used. The analyzer image parameter must be a digest of the custom image.

## Network

VNet `10.40.0.0/16` in `eastus`. The infrastructure subnet is `10.40.0.0/21`. API Management Premium is internal on `10.40.8.0/27`. Key Vault uses a private endpoint on `10.40.9.0/24` and `publicNetworkAccess: Disabled`.

The NSG allows VirtualNetwork, Entra JWKS (`AzureActiveDirectory` tcp/443), and Azure Monitor, then `deny-all-outbound`. There is no public IP resource.

## Auth

API Management runs `infra/apim-policy.xml`: `validate-azure-ad-token` for the three pre-registered client ids, then `validate-jwt` against the pinned tenant v2 issuer. The policy deletes `X-MS-CLIENT-PRINCIPAL`, `X-APIM-CLIENT-ID`, and `Cf-Access-Jwt-Assertion`. The container verifies the bearer token again. Tenant `f7812296-5bce-41dc-8102-b1b270e7c4c7`.

Key Vault holds secrets. The app identity has Secrets User (`4633458b-17de-408a-b874-0445c86b69e6`). No secret values are in the template.

## Not in this change

Do not run a deployment from this branch. Zitadel is not in the template. See `docs/auth-fallback.md`.
