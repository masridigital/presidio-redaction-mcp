# Auth fallback

Production auth is Microsoft Entra ID through Azure API Management. The container re-validates the v2 access token. Dynamic client registration is not implemented. The client list is the three pre-registered apps: Claude, Open WebUI, and Grok Bot.

Zitadel is a documented fallback only. It is not a Bicep module, not a container, and not a default. Use it only if a later Cap decision replaces Entra. That decision would add its own review. This repository does not ship Zitadel configuration.
