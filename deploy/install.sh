#!/usr/bin/env bash
# Idempotent native installer for the Ubuntu LTS host. Safe to run more than once.
# Production is venv + systemd on Azure under the Microsoft BAA. Docker is not installed.
# Secrets are not written here. The Anthropic key stays in Key Vault or a 0600 file.
set -euo pipefail

ROOT="${PRM_INSTALL_ROOT:-/}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MGMT_CIDR="${PRM_MGMT_CIDR:-10.8.0.0/24}"
SKIP_APT="${PRM_SKIP_APT:-0}"
SKIP_UFW="${PRM_SKIP_UFW:-0}"
SKIP_SYSTEMD="${PRM_SKIP_SYSTEMD:-0}"
SKIP_VENV="${PRM_SKIP_VENV:-0}"

prefix() {
  local path="$1"
  if [[ "${ROOT}" == "/" ]]; then
    printf '%s\n' "${path}"
  else
    printf '%s%s\n' "${ROOT%/}" "${path}"
  fi
}

ensure_dir() {
  local path
  path="$(prefix "$1")"
  install -d -m 0700 "${path}"
}

ensure_user() {
  local name="$1"
  if id "${name}" >/dev/null 2>&1; then
    return 0
  fi
  groupadd --system "${name}"
  useradd --system --gid "${name}" --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin "${name}"
}

ufw_rules() {
  printf '%s\n' \
    "ufw default deny incoming" \
    "ufw default deny outgoing" \
    "ufw allow in on lo" \
    "ufw allow out on lo" \
    "ufw allow in proto tcp from ${MGMT_CIDR} to any port 22" \
    "ufw allow out proto udp to any port 53" \
    "ufw allow out proto tcp to any port 53" \
    "ufw allow out proto udp to any port 123" \
    "ufw deny out to any"
}

apply_ufw_rule() {
  local rule="$1"
  case "${rule}" in
    "ufw default deny incoming") ufw default deny incoming ;;
    "ufw default deny outgoing") ufw default deny outgoing ;;
    "ufw allow in on lo") ufw allow in on lo ;;
    "ufw allow out on lo") ufw allow out on lo ;;
    "ufw allow in proto tcp from ${MGMT_CIDR} to any port 22")
      ufw allow in proto tcp from "${MGMT_CIDR}" to any port 22
      ;;
    "ufw allow out proto udp to any port 53") ufw allow out proto udp to any port 53 ;;
    "ufw allow out proto tcp to any port 53") ufw allow out proto tcp to any port 53 ;;
    "ufw allow out proto udp to any port 123") ufw allow out proto udp to any port 123 ;;
    "ufw deny out to any") ufw deny out to any ;;
    *)
      printf 'unexpected ufw rule\n' >&2
      exit 1
      ;;
  esac
}

copy_units() {
  local unit destination
  for unit in presidio-analyzer.service presidio-anonymizer.service presidio-redaction-mcp.service; do
    destination="$(prefix "/etc/systemd/system/${unit}")"
    install -d -m 0755 "$(dirname "${destination}")"
    install -m 0644 "${REPO_DIR}/deploy/systemd/${unit}" "${destination}"
  done
}

write_env_placeholder() {
  local destination
  destination="$(prefix "/etc/presidio-redaction-mcp/presidio-redaction-mcp.env")"
  if [[ ! -f "${destination}" ]]; then
    umask 077
    cat > "${destination}" <<'EOF'
# Non-secret settings only. Tokens and the Anthropic API key are not written here.
# The verifier stays off until config sets verifier.enabled on a BAA-marked Azure deployment.
# PRM_KEY_VAULT_URL=https://example.vault.azure.net
# PRM_KEY_VAULT_SECRET=anthropic-api-key
PRM_ENV=production
LOG_LEVEL=INFO
PRM_CONFIG=/opt/presidio-redaction-mcp/config/allowlist.yaml
PRM_BIND_HOST=127.0.0.1
PRM_VPN_BIND_HOST=10.8.0.1
PRM_CF_PORT=8443
PRM_VPN_PORT=8444
PRM_AUDIT_PATH=/var/lib/presidio-redaction-mcp/audit/audit.jsonl
PRM_AUDIT_STATE=/var/lib/presidio-redaction-mcp/audit/config-sha
EOF
  fi
  chmod 0600 "${destination}"
}

ensure_opt() {
  local path
  for path in /opt/presidio-analyzer /opt/presidio-anonymizer /opt/presidio-redaction-mcp; do
    install -d -m 0755 "$(prefix "${path}")"
  done
}

if [[ "${1:-}" == "--print-ufw" ]]; then
  ufw_rules
  exit 0
fi

if [[ "${SKIP_APT}" != "1" ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y python3-venv ufw unattended-upgrades auditd apparmor
fi

ensure_dir "/etc/presidio-redaction-mcp"
ensure_dir "/var/lib/presidio-analyzer"
ensure_dir "/var/lib/presidio-anonymizer"
ensure_dir "/var/lib/presidio-redaction-mcp"
ensure_dir "/var/lib/presidio-redaction-mcp/audit"
ensure_dir "/var/log/presidio-redaction-mcp"
ensure_opt
write_env_placeholder
copy_units

if [[ "$(id -u)" -eq 0 ]]; then
  ensure_user presidio-analyzer
  ensure_user presidio-anonymizer
  ensure_user presidio-proxy
  install -d -m 0700 -o presidio-proxy -g presidio-proxy "$(prefix "/var/lib/presidio-redaction-mcp/audit")"
  install -d -m 0700 -o presidio-analyzer -g presidio-analyzer "$(prefix "/var/lib/presidio-analyzer")"
  install -d -m 0700 -o presidio-anonymizer -g presidio-anonymizer "$(prefix "/var/lib/presidio-anonymizer")"
fi

if [[ "${SKIP_VENV}" != "1" && "${SKIP_APT}" != "1" ]]; then
  printf 'venv install requires a hashed requirements file reviewed with the pin\n' >&2
  exit 1
fi

if [[ "${SKIP_UFW}" != "1" ]]; then
  while IFS= read -r rule; do
    apply_ufw_rule "${rule}"
  done < <(ufw_rules)
  ufw --force enable
fi

if [[ "${SKIP_SYSTEMD}" != "1" ]]; then
  systemctl daemon-reload
  systemctl enable presidio-analyzer.service presidio-anonymizer.service presidio-redaction-mcp.service
fi
