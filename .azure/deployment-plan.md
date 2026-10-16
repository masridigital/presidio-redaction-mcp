# Deployment plan

Status: not approved for apply. Do not run `azd up` or `az deployment` from this branch.

## Region and boundary

`eastus`. Resource group holds the VNet, internal Container Apps environment, one Container App, internal API Management Premium, Key Vault (public network disabled, private endpoint), and Log Analytics.

## Images

- Proxy: digest parameter `containerImage`.
- Analyzer: digest parameter `analyzerImage`, built from `deploy/presidio/Dockerfile`. Not `mcr.microsoft.com/presidio-analyzer`.
- Anonymizer: digest parameter `anonymizerImage`.

The analyzer container sets `PRESIDIO_BIND=127.0.0.1`. The Container App ingress is `external: false` and targets only port 8080. There is no public IP and no analyzer ingress.

## Identity

System-assigned identity on the Container App. Role Secrets User on Key Vault. Entra tenant `f7812296-5bce-41dc-8102-b1b270e7c4c7`. Client application ids are parameters.

## Egress

NSG `deny-all-outbound` after allow rules for VirtualNetwork, `AzureActiveDirectory` tcp/443 (JWKS), and `AzureMonitor` tcp/443.

## Out of scope

No Zitadel. No Cloudflare Tunnel. No deploy in CI.
