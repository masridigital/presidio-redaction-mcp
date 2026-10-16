# Grok Bot edge options

Grok Bot has no path through the internal API Management gateway. The Premium instance in `infra/main.bicep` is internal, on `10.40.8.0/27`, with no public IP. This page is the decision for Cap. Neither option is implemented.

Grok Bot stays a non-PHI caller in both options:

- `phi_capable: false` and `baa: false`. The Entra app is `NonPhi.Caller` only. A `Phi.Caller` role on that app is `role_client_mismatch`.
- A Presidio entity hit in a tool result is **blocked** (`phi_in_non_baa_tool_result`). The caller receives the reason code, not a masked body.
- Allowed tools stay `stackjack_health_check`, `stackjack_get_service_status`, and `UPTIMEROBOT_GET_MONITORS`. Free-text, date, and IP fields are dropped before redaction.
- The `cloudflare` allowlist mark remains the non-PHI policy label. It is not a listener. A future edge replaces that door. It does not grant a PHI role or a BAA allowlist entry.
- Callers must keep PHI out of tool arguments. An edge that terminates TLS can see those bytes. `phi_in_cloudflare_tool_args` stays the block for that mark.

Prices below are **estimates** from Azure public list prices, in US dollars, pay-as-you-go, before tax, discounts, and support. Microsoft states that prices on the pricing pages are estimates and are not quotes. Hourly retail meters are converted with a 730-hour month, which is the conventional month that matches the published monthly figures. Usage beyond the base fee is extra. Region for API Management meters is `eastus`. Front Door data and request rates below are Zone 1 (North America). Retrieved 2026-10-16.

Sources:

- Front Door list prices: [Azure Front Door pricing](https://azure.microsoft.com/en-us/pricing/details/frontdoor/).
- API Management list prices: [API Management pricing](https://azure.microsoft.com/en-us/pricing/details/api-management/).
- `eastus` hourly retail meters: [Azure Retail Prices API](https://prices.azure.com/api/retail/prices) (`serviceName eq 'API Management'`, `armRegionName eq 'eastus'`).
- HIPAA BAA scope: [HIPAA - Azure Compliance](https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-hipaa-us). The BAA is included through the Microsoft Product Terms and the Products and Services Data Protection Addendum for covered entities and business associates. It applies to services listed in scope on the Trust Center and excludes previews. Confirm Front Door and the chosen API Management SKU on the current in-scope list before any PHI is placed on them. Service eligibility does not make Grok Bot a PHI caller.

The Developer tier is listed at about **$48 per month** (`$0.0658/hour` × 730 ≈ $48.04). The pricing FAQ says that tier has no SLA and is not suitable for production. It is not a HIPAA production path.

## Option A — Front Door Premium, Private Link, WAF, Entra

Azure Front Door Premium terminates TLS at the Microsoft edge, applies a WAF policy, validates the Entra token, and connects to the internal API Management gateway with Private Link. WAF and Private Link are included in the Premium base fee. The origin stays the internal gateway. The Container Apps environment stays `internal: true`.

| Estimate | Amount |
|---|---|
| Premium base fee | $330 per profile per month |
| Requests, first 250 million, Zone 1 | $0.015 per 10,000 requests |
| Data transfer out to the client, first 10 TB, Zone 1 | $0.083 per GB |
| Data transfer from edge to origin, Zone 1 | $0.02 per GB |
| CAPTCHA add-on, if enabled | $0.40 per 1,000 sessions |

A small bot, illustrated as 1 million Zone 1 requests and 10 GB out to the client in a month, is about $1.50 of requests plus $0.83 of egress. The rough total is about **$333 per month** on top of the API Management unit that already exists. Private Link to an Azure origin does not add a separate Front Door meter. These figures are estimates.

BAA / HIPAA: Front Door is an Azure service whose eligibility is the Trust Center in-scope list, not this document. Premium is the tier that includes managed WAF and Private Link. Preview features, including any origin-authentication preview, stay out of a production PHI design. This option still must not carry PHI for Grok Bot. The result BLOCK, `NonPhi.Caller`, and the tool and field scope are what keep the caller non-PHI. A Microsoft BAA on Front Door is not a reason to mark Grok Bot `phi_capable` or `baa`.

Risks:

- Front Door terminates TLS, so request and response bodies are visible at the edge and in its logs. Grok Bot traffic has to stay non-PHI. A PHI payload on this path has already left the private network.
- Private Link admits internet clients onto a private endpoint of the internal gateway. The route has to be limited to Grok Bot's non-PHI operations. Response caching stays off. `Phi.Caller` is rejected on that route. Entra checks at the edge sit in front of the API Management policy and the container check. They do not replace either one.
- Microsoft's general Front Door plus API Management guide describes a publicly reachable gateway. Private Link to an internal-mode Premium gateway has to be confirmed against the current platform article, [Connect Front Door Premium to an API Management origin with Private Link](https://learn.microsoft.com/en-us/azure/frontdoor/standard-premium/how-to-enable-private-link-apim), before anyone builds it.
- Managed WAF rules can block MCP JSON. Exclusions are a reviewed change. CAPTCHA is a poor fit for a machine client and is a separate meter.
- The profile is global. The origin stays in `eastus`.

## Option B — External API Management, IP allowlist and/or mTLS

Publish an API Management gateway that is reachable from the internet and restrict it with an IP allowlist, mutual TLS, or both. Two shapes have different prices. Both are estimates.

**Dedicated external gateway for Grok Bot only.** The existing Premium internal unit stays internal. A second instance is the public door:

| SKU (eastus retail) | Hourly meter | About per unit per month | Network |
|---|---|---|---|
| Basic | $0.2016 | $147 | External only. No virtual network. |
| Basic v2 | $0.20548 | $150 | No virtual network. 10 million requests included, then $3 per extra million. |
| Standard | $0.9407 | $687 | External only. No virtual network. |
| Standard v2 | $0.9589 | $700 | Virtual network integration, not full injection. 50 million requests included, then $2.50 per extra million. |

IP filters and client certificates are policy features on these SKUs. They are not a separate base meter. A low-volume bot on Basic is about **$147 per month**. Standard v2 is about **$700 per month**.

**Switch the existing Premium unit from internal to external.** The eastus Premium unit meter is `$3.829/hour`, about **$2,795 per unit per month**. Incremental SKU cost of the switch is $0 because that unit is already in the design. Additional units of the same instance are half the first unit. Premium v2, if chosen later, is `$3.83562/hour`, about **$2,800** for the first unit and about **$1,400** per additional unit. External mode on Premium is what makes that same gateway reachable from the internet.

BAA / HIPAA: API Management is an Azure service whose eligibility is the same Trust Center list. Premium and Premium v2 are the tiers with virtual-network isolation and a 99.99% SLA when zone or multi-region requirements are met. Basic and Standard are production SKUs with a 99.95% SLA and no virtual-network injection. The Developer tier is excluded above. Putting Grok Bot on an eligible SKU still leaves Grok Bot non-PHI: result BLOCK, `NonPhi.Caller` only, no PHI role, no BAA allowlist entry.

Risks:

- An external gateway is a public endpoint. An IP allowlist depends on source addresses Grok Bot does not publish as a stable customer prefix. Addresses change, and a proxy in front of the bot hides them. Mutual TLS holds up better and turns the client certificate into a long-lived secret on the bot.
- Switching the existing Premium instance to external publishes the gateway that also serves PHI callers. A mistake in the IP filter or the client-certificate rule exposes that plane.
- A second gateway can drift from the container's result BLOCK. The container still re-validates the JWT and still blocks flagged results. The public listener is the new exposure.
- Basic and Standard cannot inject into the virtual network, so the path from that gateway to the internal Container App is a separate private-integration design. Developer remains off the production path.
- This option has no WAF unless Front Door or Application Gateway is added, which moves the design back toward option A.

## Recommendation

Recommend **option A**. The incremental estimate is about $330 per month plus a few dollars of Zone 1 usage, WAF and Private Link included, and the PHI gateway stays on the internal subnet. Option B is either a second public gateway at about $147 to $700 per month, or a $0 SKU change that publishes the Premium gateway used by PHI callers.

Leave both unimplemented until Cap chooses. The Bicep in this repository keeps API Management internal.
