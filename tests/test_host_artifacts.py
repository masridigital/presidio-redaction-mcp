from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_ufw_policy_has_no_public_inbound_and_denies_outbound():
    printed = subprocess.check_output(
        ["bash", str(ROOT / "deploy" / "install.sh"), "--print-ufw"],
        text=True,
        env={**os.environ, "PRM_MGMT_CIDR": "10.8.0.0/24"},
    )
    assert "ufw default deny incoming" in printed
    assert "ufw default deny outgoing" in printed
    assert "from 10.8.0.0/24 to any port 22" in printed
    assert "0.0.0.0/0" not in printed
    assert "8443" not in printed
    assert "8444" not in printed
    rules = (ROOT / "deploy" / "ufw" / "docker-user.rules").read_text(encoding="utf-8")
    assert "DOCKER-USER" in rules
    assert "-j DROP" in rules
    assert "ESTABLISHED,RELATED" in rules


def test_install_sh_is_idempotent(tmp_path: Path):
    env = {
        **os.environ,
        "PRM_INSTALL_ROOT": str(tmp_path),
        "PRM_SKIP_APT": "1",
        "PRM_SKIP_UFW": "1",
        "PRM_SKIP_DOCKER": "1",
        "PRM_SKIP_SYSTEMD": "1",
    }
    script = str(ROOT / "deploy" / "install.sh")
    subprocess.check_call(["bash", script], env=env)
    subprocess.check_call(["bash", script], env=env)
    audit = tmp_path / "var" / "lib" / "presidio-redaction-mcp" / "audit"
    assert audit.is_dir()
    mode = stat.S_IMODE(audit.stat().st_mode)
    assert mode == 0o700
    env_file = tmp_path / "etc" / "presidio-redaction-mcp" / "compose.env"
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    assert "PRM_ENV=production" in env_file.read_text(encoding="utf-8")
    unit = (tmp_path / "etc" / "systemd" / "system" / "presidio-redaction-mcp.service").read_text(
        encoding="utf-8"
    )
    assert "Restart=on-failure" in unit
    assert "cloudflared.service" in unit
    assert "docker.service" in unit


def test_compose_builds_the_custom_analyzer_and_publishes_no_presidio_ports():
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    compose = yaml.safe_load(text)
    analyzer = compose["services"]["presidio-analyzer"]
    anonymizer = compose["services"]["presidio-anonymizer"]
    assert "ports" not in analyzer
    assert "ports" not in anonymizer
    assert "ports" not in compose["services"]["presidio-tls"]
    assert analyzer["build"]["dockerfile"] == "deploy/presidio/Dockerfile"
    assert analyzer["image"] == "presidio-analyzer:2.2.362"
    assert not str(analyzer.get("image", "")).startswith("mcr.microsoft.com/")
    assert anonymizer["image"].startswith("mcr.microsoft.com/presidio-anonymizer:2.2.362@sha256:")
    assert "deprecated" in text
    assert "ghcr.io" not in text
    assert compose["networks"]["presidio_internal"]["internal"] is True
    published = text.split("ports:", 1)[1]
    assert "0.0.0.0:" not in published
    assert "127.0.0.1:8443:8443" in text
    assert "secrets:" in text
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "@sha256:" in dockerfile.splitlines()[0]
    custom = (ROOT / "deploy" / "presidio" / "Dockerfile").read_text(encoding="utf-8")
    assert "\nFROM python:3.12-slim@sha256:" in "\n" + custom
    assert "--require-hashes" in custom
    assert 'presidio.serve' in custom
    assert "mcr.microsoft.com" not in custom
    serve = (ROOT / "deploy" / "presidio" / "serve.py").read_text(encoding="utf-8")
    assert "sys.path" not in serve
    assert "register_us_recognizers" in serve
    assert '"/analyze"' in serve
    assert '"/health"' in serve
    unit = (ROOT / "deploy" / "systemd" / "presidio-redaction-mcp.service").read_text(encoding="utf-8")
    assert "deploy/presidio/Dockerfile" in unit
    assert "mcr.microsoft.com/presidio-analyzer is deprecated" in unit


def test_systemd_unit_restarts_on_failure():
    unit = (ROOT / "deploy" / "systemd" / "presidio-redaction-mcp.service").read_text(encoding="utf-8")
    assert "Restart=on-failure" in unit
    assert "After=docker.service network-online.target cloudflared.service" in unit
