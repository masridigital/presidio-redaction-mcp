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

## Image pulls

`deny-all-outbound` blocks a pull from the public Microsoft Container Registry and from the public Azure Container Registry endpoint. The template creates a Premium Azure Container Registry with `publicNetworkAccess: Disabled`, admin user off, and `networkRuleBypassOptions: None`. It also creates the private DNS zone `privatelink.azurecr.io` and a private endpoint on `10.40.9.0/24` with group id `registry`. The Container App system identity has AcrPull (`7f951dda-4ed3-4680-a7ca-43fe172d538d`) and pulls through `registries` with identity `system`. Pass `containerImage`, `analyzerImage`, and `anonymizerImage` as digest-pinned copies in that registry. The anonymizer digest stays the pinned 2.2.362 digest. This template does not add a public egress rule for `mcr.microsoft.com`.

`containerImage`, `analyzerImage`, and `anonymizerImage` must contain `@sha256:` after a repository name, and the digest suffix must be 64 characters. Bicep `assert` rejects a floating tag.

## Grok Bot edge

Grok Bot has no path through the internal API Management instance. The two options for a later non-Cloudflare edge are in `docs/grok-bot-edge-options.md`. Neither is implemented in this template. The internal gateway stays internal.

## Auth

API Management runs `infra/apim-policy.xml`: `validate-azure-ad-token` for the three pre-registered client ids, then `validate-jwt` against the pinned tenant v2 issuer. A `Phi.Caller` token must include `access_as_user` among its `scp` values, including when the claim lists more than one scope. `NonPhi.Caller` tokens are not required to carry `scp`. The policy deletes `X-MS-CLIENT-PRINCIPAL`, `X-APIM-CLIENT-ID`, and `Cf-Access-Jwt-Assertion`. The container verifies the bearer token again. Tenant `f7812296-5bce-41dc-8102-b1b270e7c4c7`.

Key Vault holds secrets. The app identity has Secrets User (`4633458b-17de-408a-b874-0445c86b69e6`). No secret values are in the template.

## Pre-PHI checklist

Before a PHI client is enabled, lock the immutability policies on `prm-config` and `prm-floor` after the soak. The commands and the recovery for a junk version file are in `docs/signing-key-rotation.md`.

## Not in this change

Do not run a deployment from this branch. Zitadel is not in the template. See `docs/auth-fallback.md`.
