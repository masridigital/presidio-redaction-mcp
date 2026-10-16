from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_ufw_policy_denies_both_directions_and_binds_8444_to_wg0():
    printed = subprocess.check_output(
        ["bash", str(ROOT / "deploy" / "install.sh"), "--print-ufw"],
        text=True,
        env={**os.environ, "PRM_MGMT_CIDR": "10.8.0.0/24"},
    )
    assert "ufw default deny incoming" in printed
    assert "ufw default deny outgoing" in printed
    assert "from 10.8.0.0/24 to any port 22" in printed
    assert "ufw allow in on wg0 proto tcp to 10.8.0.1 port 8444" in printed
    assert "51820" in printed
    assert "0.0.0.0/0" not in printed
    assert "8443" not in printed
    owner = subprocess.check_output(
        ["bash", str(ROOT / "deploy" / "install.sh"), "--print-owner-egress"],
        text=True,
    )
    assert "cloudflared" not in owner
    assert "7844" not in owner
    assert "104.16.0.0/13" not in owner
    assert "--uid-owner presidio-proxy" in owner
    assert "-j DROP" in owner
    assert "anthropic" not in owner.lower()
    assert "0.0.0.0/0" not in owner


def test_install_sh_is_idempotent(tmp_path: Path):
    env = {
        **os.environ,
        "PRM_INSTALL_ROOT": str(tmp_path),
        "PRM_SKIP_APT": "1",
        "PRM_SKIP_UFW": "1",
        "PRM_SKIP_SYSTEMD": "1",
        "PRM_SKIP_VENV": "1",
        "PRM_SKIP_TLS": "1",
    }
    script = str(ROOT / "deploy" / "install.sh")
    subprocess.check_call(["bash", script], env=env)
    subprocess.check_call(["bash", script], env=env)
    audit = tmp_path / "var" / "lib" / "presidio-redaction-mcp" / "audit"
    assert audit.is_dir()
    assert stat.S_IMODE(audit.stat().st_mode) == 0o700
    env_file = tmp_path / "etc" / "presidio-redaction-mcp" / "proxy.env"
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o600
    text = env_file.read_text(encoding="utf-8")
    assert "PRM_ENV=production" in text
    assert "PRM_SECRET_" not in text
    unit = (tmp_path / "etc" / "systemd" / "system" / "presidio-redaction-mcp.service").read_text(
        encoding="utf-8"
    )
    assert "Restart=on-failure" in unit
    assert "ProtectSystem=strict" in unit
    assert "NoNewPrivileges=yes" in unit
    assert "PrivateTmp=yes" in unit
    assert "CapabilityBoundingSet=" in unit
    assert "docker" not in unit.lower()
    assert "compose" not in unit.lower()
    assert "Container Apps" in unit
    assert not (tmp_path / "etc" / "systemd" / "system" / "cloudflared.service").exists()
    assert (tmp_path / "etc" / "systemd" / "system" / "presidio-wg0.service").is_file()
    assert not (tmp_path / "etc" / "wireguard" / "wg0.conf").exists()
    template = (tmp_path / "etc" / "wireguard" / "wg0.conf.template").read_text(encoding="utf-8")
    assert "10.8.0.1/24" in template
    assert "REPLACE_AT_INSTALL" in template


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
    assert "8443" not in text
    assert "8444:8444" in text
    assert "secrets:" in text
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "@sha256:" in dockerfile.splitlines()[0]
    custom = (ROOT / "deploy" / "presidio" / "Dockerfile").read_text(encoding="utf-8")
    assert "\nFROM python:3.12-slim@sha256:" in "\n" + custom
    assert "--require-hashes" in custom
    assert "presidio.serve" in custom
    assert "mcr.microsoft.com" not in custom
    serve = (ROOT / "deploy" / "presidio" / "serve.py").read_text(encoding="utf-8")
    assert "sys.path" not in serve
    assert "register_us_recognizers" in serve
    assert '"/analyze"' in serve
    assert '"/health"' in serve


def test_systemd_units_are_hardened_and_native():
    unit = (ROOT / "deploy" / "systemd" / "presidio-redaction-mcp.service").read_text(encoding="utf-8")
    assert "Restart=on-failure" in unit
    assert "ProtectSystem=strict" in unit
    assert "NoNewPrivileges=yes" in unit
    assert "User=presidio-proxy" in unit
    assert "docker.service" not in unit
    assert "cloudflared.service" not in unit
    assert "compose" not in unit.lower()
    assert "Container Apps" in unit
    assert "ExecStart=/opt/presidio-redaction-mcp/venv/bin/presidio-redaction-mcp" in unit
    analyzer = (ROOT / "deploy" / "systemd" / "presidio-analyzer.service").read_text(encoding="utf-8")
    assert "PRESIDIO_BIND=127.0.0.1" in analyzer
    assert "python -m presidio.serve" in analyzer
    assert "CapabilityBoundingSet=" in analyzer
    anonymizer = (ROOT / "deploy" / "systemd" / "presidio-anonymizer.service").read_text(encoding="utf-8")
    assert "raise SystemExit(0)" not in anonymizer
    assert 'gunicorn -w 1 -b 127.0.0.1:3001 "app:create_app()"' in anonymizer
    assert "ConditionPathExists=/opt/presidio-anonymizer/app.py" in anonymizer
    installer = (ROOT / "host" / "install.sh").read_text(encoding="utf-8")
    assert "systemctl enable presidio-analyzer.service presidio-redaction-mcp.service" in installer
    assert "enable presidio-analyzer.service presidio-anonymizer.service" not in installer
    serve = (ROOT / "deploy" / "presidio" / "serve.py").read_text(encoding="utf-8")
    assert "register_us_recognizers(engine)" in serve
    assert "def do_POST" in serve
