#!/usr/bin/env bash
# Idempotent installer for the Ubuntu LTS host. Safe to run more than once.
# Secrets are not written here. Docker secrets and the vault supply them.
set -euo pipefail

ROOT="${PRM_INSTALL_ROOT:-/}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MGMT_CIDR="${PRM_MGMT_CIDR:-10.8.0.0/24}"
SKIP_APT="${PRM_SKIP_APT:-0}"
SKIP_UFW="${PRM_SKIP_UFW:-0}"
SKIP_DOCKER="${PRM_SKIP_DOCKER:-0}"
SKIP_SYSTEMD="${PRM_SKIP_SYSTEMD:-0}"

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

copy_unit() {
  local destination
  destination="$(prefix "/etc/systemd/system/presidio-redaction-mcp.service")"
  install -d -m 0755 "$(dirname "${destination}")"
  install -m 0644 "${REPO_DIR}/deploy/systemd/presidio-redaction-mcp.service" "${destination}"
}

write_env_placeholder() {
  local destination
  destination="$(prefix "/etc/presidio-redaction-mcp/compose.env")"
  if [[ -f "${destination}" ]]; then
    return 0
  fi
  umask 077
  cat > "${destination}" <<'EOF'
# Placeholder only. Secrets come from Docker secrets, not this file.
PRM_ENV=production
LOG_LEVEL=INFO
EOF
  chmod 0600 "${destination}"
}

link_repo() {
  local destination
  destination="$(prefix "/opt/presidio-redaction-mcp")"
  install -d -m 0755 "$(dirname "${destination}")"
  if [[ ! -e "${destination}" ]]; then
    ln -s "${REPO_DIR}" "${destination}"
  fi
}

apply_docker_user() {
  local destination
  destination="$(prefix "/etc/ufw/after.rules")"
  install -d -m 0755 "$(dirname "${destination}")"
  if [[ ! -f "${destination}" ]]; then
    printf '%s\n' "*filter" "COMMIT" > "${destination}"
  fi
  if ! grep -q "prm-docker-user" "${destination}"; then
    cat "${REPO_DIR}/deploy/ufw/docker-user.rules" >> "${destination}"
  fi
}

if [[ "${1:-}" == "--print-ufw" ]]; then
  ufw_rules
  exit 0
fi

if [[ "${SKIP_APT}" != "1" ]]; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y docker.io docker-compose-v2 ufw unattended-upgrades auditd apparmor
fi

ensure_dir "/etc/presidio-redaction-mcp"
ensure_dir "/var/lib/presidio-redaction-mcp"
ensure_dir "/var/lib/presidio-redaction-mcp/audit"
ensure_dir "/var/log/presidio-redaction-mcp"
write_env_placeholder
copy_unit
link_repo

if [[ "${SKIP_DOCKER}" != "1" ]]; then
  if ! id presidio-proxy >/dev/null 2>&1; then
    groupadd --system presidio-proxy
    useradd --system --gid presidio-proxy --create-home --shell /usr/sbin/nologin presidio-proxy
  fi
  install -d -m 0700 -o presidio-proxy -g presidio-proxy "$(prefix "/var/lib/presidio-redaction-mcp/audit")"
fi

if [[ "${SKIP_UFW}" != "1" ]]; then
  while IFS= read -r rule; do
    apply_ufw_rule "${rule}"
  done < <(ufw_rules)
  apply_docker_user
  ufw --force enable
fi

if [[ "${SKIP_SYSTEMD}" != "1" ]]; then
  systemctl daemon-reload
  systemctl enable presidio-redaction-mcp.service
fi
