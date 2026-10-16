"""Default-deny outbound host check. Only the two upstreams, Presidio, and test hosts.

The verifier may call ``api.anthropic.com`` and Azure Key Vault. A Cloudflare
hostname is denied for every purpose, including those two.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from presidio_redaction_mcp.errors import PolicyError

_VERIFIER_HOST = "api.anthropic.com"
_VERIFIER_PATH = "/v1/messages"


@dataclass(frozen=True)
class EgressPolicy:
    upstream_hosts: frozenset[str]
    presidio_hosts: frozenset[str]
    test_hosts: frozenset[str]
    allow_test_hosts: bool

    def allowed_hosts(self) -> frozenset[str]:
        allowed = set(self.upstream_hosts) | set(self.presidio_hosts)
        if self.allow_test_hosts:
            allowed |= set(self.test_hosts)
        return frozenset(allowed)

    def check(self, url: str, *, purpose: str) -> str:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme not in {"https", "http"} or not host:
            raise PolicyError("egress_denied")
        if "cloudflare" in host or "trycloudflare" in host or "cloudflare" in url.lower():
            raise PolicyError("egress_denied")
        if purpose == "verifier":
            if parsed.scheme != "https" or host != _VERIFIER_HOST or parsed.path != _VERIFIER_PATH:
                raise PolicyError("egress_denied")
            return host
        if purpose == "key_vault":
            if parsed.scheme != "https" or not host.endswith(".vault.azure.net"):
                raise PolicyError("egress_denied")
            return host
        if host not in self.allowed_hosts():
            raise PolicyError("egress_denied")
        if purpose == "presidio" and host not in self.presidio_hosts and not (
            self.allow_test_hosts and host in self.test_hosts
        ):
            raise PolicyError("egress_denied")
        if purpose == "upstream" and host not in self.upstream_hosts and not (
            self.allow_test_hosts and host in self.test_hosts
        ):
            raise PolicyError("egress_denied")
        return host
