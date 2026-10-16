#!/usr/bin/env bash
# Idempotent native install for Ubuntu Server LTS. No Docker.
# Secrets are not written here. Put them in /etc/presidio-redaction-mcp/secrets (0600).
set -euo pipefail

ROOT="${PRM_INSTALL_ROOT:-/}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKIP_APT="${PRM_SKIP_APT:-0}"
SKIP_UFW="${PRM_SKIP_UFW:-0}"
SKIP_SYSTEMD="${PRM_SKIP_SYSTEMD:-0}"
SKIP_VENV="${PRM_SKIP_VENV:-0}"
SKIP_TLS="${PRM_SKIP_TLS:-0}"

# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/ufw.sh"

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

copy_unit() {
  local name="$1"
  local destination
  destination="$(prefix "/etc/systemd/system/${name}")"
  install -d -m 0755 "$(dirname "${destination}")"
  install -m 0644 "${REPO_DIR}/deploy/systemd/${name}" "${destination}"
}

write_proxy_env() {
  local destination
  destination="$(prefix "/etc/presidio-redaction-mcp/proxy.env")"
  if [[ -f "${destination}" ]]; then
    chmod 0600 "${destination}"
    return 0
  fi
  umask 077
  cat > "${destination}" <<'EOF'
# Non-secret settings. Tokens, the HMAC key, and TLS keys are systemd credentials.
# Production refuses secret environment variables.
# Optional native process. Azure Container Apps is the primary deployment.
# Production auth is Entra. This env file does not start a compose project.
PRM_ENV=production
LOG_LEVEL=INFO
PRM_CONFIG=/etc/presidio-redaction-mcp/allowlist.yaml
PRM_BIND_HOST=127.0.0.1
PRM_VPN_BIND_HOST=10.8.0.1
PRM_VPN_PORT=8444
PRM_AUDIT_PATH=/var/lib/presidio-redaction-mcp/audit/audit.jsonl
PRM_AUDIT_STATE=/var/lib/presidio-redaction-mcp/audit/config-sha
PYTHONDONTWRITEBYTECODE=1
EOF
  chmod 0600 "${destination}"
}

copy_config() {
  local destination
  destination="$(prefix "/etc/presidio-redaction-mcp")"
  if [[ ! -f "${destination}/allowlist.yaml" ]]; then
    install -m 0640 "${REPO_DIR}/config/allowlist.yaml" "${destination}/allowlist.yaml"
  fi
  if [[ ! -f "${destination}/recognizers.yaml" ]]; then
    install -m 0640 "${REPO_DIR}/config/recognizers.yaml" "${destination}/recognizers.yaml"
  fi
}

install_wireguard_template() {
  local destination
  destination="$(prefix "/etc/wireguard/wg0.conf.template")"
  install -m 0600 "${REPO_DIR}/deploy/wireguard/wg0.conf.template" "${destination}"
  if [[ -f "$(prefix "/etc/wireguard/wg0.conf")" ]] && grep -q REPLACE_AT_INSTALL "$(prefix "/etc/wireguard/wg0.conf")"; then
    printf 'refusing live wg0.conf that still contains REPLACE_AT_INSTALL\n' >&2
    exit 1
  fi
}

copy_presidio_server() {
  local destination
  destination="$(prefix "/opt/presidio-analyzer/presidio")"
  install -d -m 0750 "${destination}"
  install -m 0640 "${REPO_DIR}/deploy/presidio/__init__.py" "${destination}/__init__.py"
  install -m 0640 "${REPO_DIR}/deploy/presidio/serve.py" "${destination}/serve.py"
  install -m 0640 "${REPO_DIR}/deploy/presidio/us_recognizers.py" "${destination}/us_recognizers.py"
}

ensure_user() {
  local name="$1"
  local home="$2"
  if id "${name}" >/dev/null 2>&1; then
    return 0
  fi
  useradd --system --home-dir "${home}" --create-home --shell /usr/sbin/nologin "${name}"
}

write_tls() {
  local dir
  dir="$(prefix "/etc/presidio-redaction-mcp/tls")"
  if [[ -f "${dir}/ca.pem" && -f "${dir}/internal.pem" && -f "${dir}/proxy.pem" ]]; then
    return 0
  fi
  local work
  work="$(mktemp -d)"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "${work}/ca.key" -out "${work}/ca.pem" -days 825 -subj "/CN=presidio-local-ca" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -keyout "${work}/internal.key" -out "${work}/internal.csr" -subj "/CN=127.0.0.1" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -keyout "${work}/proxy.key" -out "${work}/proxy.csr" -subj "/CN=presidio-proxy" >/dev/null 2>&1
  cat > "${work}/san.cnf" <<'EOF'
subjectAltName=IP:127.0.0.1,IP:10.8.0.1,DNS:localhost
extendedKeyUsage=serverAuth
EOF
  openssl x509 -req -in "${work}/internal.csr" -CA "${work}/ca.pem" -CAkey "${work}/ca.key" -CAcreateserial -out "${work}/internal.pem" -days 825 -extfile "${work}/san.cnf" >/dev/null 2>&1
  openssl x509 -req -in "${work}/proxy.csr" -CA "${work}/ca.pem" -CAkey "${work}/ca.key" -CAcreateserial -out "${work}/proxy.pem" -days 825 -extfile "${work}/san.cnf" >/dev/null 2>&1
  install -m 0644 "${work}/ca.pem" "${dir}/ca.pem"
  install -m 0640 "${work}/internal.pem" "${dir}/internal.pem"
  install -m 0640 "${work}/internal.key" "${dir}/internal.key"
  install -m 0640 "${work}/proxy.pem" "${dir}/proxy.pem"
  install -m 0640 "${work}/proxy.key" "${dir}/proxy.key"
  rm -rf "${work}"
}

install_venv() {
  local app="$1"
  local requirements="$2"
  local venv
  venv="$(prefix "/opt/${app}/venv")"
  if [[ ! -x "${venv}/bin/pip" ]]; then
    python3 -m venv "${venv}"
  fi
  "${venv}/bin/pip" install --require-hashes -r "${requirements}"
}

if [[ "${1:-}" == "--print-ufw" ]]; then
  print_ufw
  exit 0
fi

if [[ "${1:-}" == "--print-owner-egress" ]]; then
  print_owner_egress
  exit 0
fi

if [[ "${SKIP_APT}" != "1" && "${ROOT}" == "/" ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y python3 python3-venv python3-pip wireguard ufw unattended-upgrades auditd apparmor ca-certificates curl openssl
  printf '%s\n' 'APT::Periodic::Update-Package-Lists "1";' 'APT::Periodic::Unattended-Upgrade "1";' > /etc/apt/apt.conf.d/20auto-upgrades
fi

ensure_dir "/etc/presidio-redaction-mcp"
ensure_dir "/etc/presidio-redaction-mcp/secrets"
ensure_dir "/etc/presidio-redaction-mcp/tls"
ensure_dir "/etc/wireguard"
ensure_dir "/var/lib/presidio-redaction-mcp"
ensure_dir "/var/lib/presidio-redaction-mcp/audit"
ensure_dir "/var/lib/presidio-analyzer"
ensure_dir "/var/lib/presidio-analyzer/cache"
ensure_dir "/var/lib/presidio-anonymizer"
ensure_dir "/var/log/presidio-redaction-mcp"
ensure_dir "/opt/presidio-redaction-mcp"
ensure_dir "/opt/presidio-analyzer"
ensure_dir "/opt/presidio-anonymizer"
write_proxy_env
copy_config
copy_presidio_server
install_wireguard_template
copy_unit "presidio-analyzer.service"
copy_unit "presidio-anonymizer.service"
copy_unit "presidio-redaction-mcp.service"
copy_unit "presidio-wg0.service"
install -d -m 0755 "$(prefix "/etc/audit/rules.d")"
install -m 0640 "${REPO_DIR}/deploy/audit/presidio.rules" "$(prefix "/etc/audit/rules.d/presidio.rules")"

if [[ "${SKIP_TLS}" != "1" && "${ROOT}" == "/" ]]; then
  write_tls
fi

if [[ "$(id -u)" -eq 0 && "${ROOT}" == "/" ]]; then
  ensure_user presidio-proxy /opt/presidio-redaction-mcp
  ensure_user presidio-analyzer /opt/presidio-analyzer
  ensure_user presidio-anonymizer /opt/presidio-anonymizer
  chown -R presidio-proxy:presidio-proxy "$(prefix "/var/lib/presidio-redaction-mcp")"
  chown -R presidio-analyzer:presidio-analyzer "$(prefix "/var/lib/presidio-analyzer")"
  chown -R presidio-anonymizer:presidio-anonymizer "$(prefix "/var/lib/presidio-anonymizer")"
fi

if [[ "${SKIP_VENV}" != "1" ]]; then
  install_venv presidio-redaction-mcp "${REPO_DIR}/deploy/requirements/proxy.lock"
  install_venv presidio-analyzer "${REPO_DIR}/deploy/requirements/presidio.lock"
  if [[ ! -x "$(prefix "/opt/presidio-analyzer/venv/bin/python")" ]]; then
    printf 'presidio venv missing\n' >&2
    exit 1
  fi
  model_python="$(prefix "/opt/presidio-analyzer/venv/bin/python")"
  if ! "${model_python}" -c 'import en_core_web_lg' >/dev/null 2>&1; then
    tmp_model="$(mktemp)"
    curl -fsSL -o "${tmp_model}" "https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl"
    echo "293e9547a655b25499198ab15a525b05b9407a75f10255e405e8c3854329ab63  ${tmp_model}" | sha256sum -c -
    "$(prefix "/opt/presidio-analyzer/venv/bin/pip")" install --no-deps "${tmp_model}"
    rm -f "${tmp_model}"
  fi
  # Anonymizer has no spaCy model. It shares the locked Presidio requirements.
  install_venv presidio-anonymizer "${REPO_DIR}/deploy/requirements/presidio.lock"
fi

if [[ "${SKIP_UFW}" != "1" && "${ROOT}" == "/" ]]; then
  apply_ufw
  apply_owner_egress
fi

if [[ "${ROOT}" == "/" && "${PRM_REQUIRE_LUKS:-0}" == "1" ]]; then
  if ! findmnt -no SOURCE /var/lib/presidio-redaction-mcp 2>/dev/null | grep -qiE 'crypt|mapper'; then
    printf 'LUKS is required for /var/lib/presidio-redaction-mcp\n' >&2
    exit 1
  fi
fi

if [[ "${SKIP_SYSTEMD}" != "1" && "${ROOT}" == "/" ]]; then
  systemctl daemon-reload
  # The anonymizer unit is optional and stays disabled. Azure runs the digest-pinned image.
  systemctl enable presidio-analyzer.service presidio-redaction-mcp.service
fi
