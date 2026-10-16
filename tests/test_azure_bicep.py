from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_bicep_keeps_the_analyzer_private_and_denies_egress():
    bicep = (ROOT / "infra" / "main.bicep").read_text(encoding="utf-8")
    policy = (ROOT / "infra" / "apim-policy.xml").read_text(encoding="utf-8")
    assert "f7812296-5bce-41dc-8102-b1b270e7c4c7" in bicep
    assert "external: false" in bicep
    assert "targetPort: 8080" in bicep
    assert "targetPort: 3000" not in bicep
    assert "publicIPAddresses" not in bicep
    assert "publicNetworkAccess: 'Disabled'" in bicep
    assert "4633458b-17de-408a-b874-0445c86b69e6" in bicep
    assert "10.40.0.0/16" in bicep
    assert "internal: true" in bicep
    assert "deny-all-outbound" in bicep
    assert "PRESIDIO_BIND" in bicep
    assert "'127.0.0.1'" in bicep
    assert "zitadel" not in bicep.lower()
    assert "password" not in bicep.lower()
    assert "mcr.microsoft.com/presidio-analyzer" not in bicep
    assert "validate-azure-ad-token" in policy
    assert "validate-jwt" in policy
    assert "/v2.0" in policy
    assert "/common/" not in policy
    assert "/organizations/" not in policy
    assert 'name="X-MS-CLIENT-PRINCIPAL"' in policy
    assert "Cf-Access-Jwt-Assertion" in policy
    unit = (ROOT / "deploy" / "systemd" / "presidio-redaction-mcp.service").read_text(encoding="utf-8")
    assert "cloudflared.service" not in unit
    assert "docker.service" not in unit
    assert "compose" not in unit.lower()
