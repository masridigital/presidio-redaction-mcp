"""Default-deny outbound host check. Only the two upstreams, Presidio, and test hosts."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from presidio_redaction_mcp.errors import PolicyError


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
        host = parsed.hostname
        if parsed.scheme not in {"https", "http"} or not host:
            raise PolicyError("egress_denied")
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
