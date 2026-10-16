#!/usr/bin/env bash
# UFW default-deny plus per-user egress for the native presidio host.
# Sourced by host/install.sh. Executing this file prints the rules.
# shellcheck shell=bash

print_ufw() {
  local mgmt="${PRM_MGMT_CIDR:-10.8.0.0/24}"
  local vpn_addr="${PRM_VPN_BIND_ADDR:-10.8.0.1}"
  local wg_port="${PRM_WG_PORT:-51820}"
  printf '%s\n' \
    "ufw default deny incoming" \
    "ufw default deny outgoing" \
    "ufw allow in on lo" \
    "ufw allow out on lo" \
    "ufw allow in proto tcp from ${mgmt} to any port 22 comment prm-ssh" \
    "ufw allow in proto udp to any port ${wg_port} comment prm-wireguard" \
    "ufw allow in on wg0 proto tcp to ${vpn_addr} port 8444 comment prm-vpn-mcp" \
    "ufw allow out proto udp to any port 53 comment prm-dns-udp" \
    "ufw allow out proto tcp to any port 53 comment prm-dns-tcp" \
    "ufw allow out proto udp to any port 123 comment prm-ntp" \
    "ufw deny out to any comment prm-deny-out"
}

_owner_rule() {
  if [[ "${PRM_UFW_MODE:-print}" == "apply" ]]; then
    if [[ "${2:-}" == "-N" ]]; then
      "$@" 2>/dev/null || true
      return 0
    fi
    "$@"
    return 0
  fi
  printf '%s' "$1"
  shift
  local arg
  for arg in "$@"; do
    printf ' %s' "${arg}"
  done
  printf '\n'
}

_owner_family() {
  local bin="$1"
  local chain="$2"
  local user
  _owner_rule "${bin}" -N "${chain}"
  _owner_rule "${bin}" -F "${chain}"
  _owner_rule "${bin}" -A "${chain}" -o lo -j RETURN
  for user in presidio-proxy presidio-analyzer presidio-anonymizer; do
    _owner_rule "${bin}" -A "${chain}" -m owner --uid-owner "${user}" -j DROP
  done
}

print_owner_egress() {
  printf '%s\n' "# per-user egress. proxy and Presidio: loopback only. Azure Container Apps is primary."
  _owner_family iptables PRM-OUTPUT
  _owner_family ip6tables PRM-OUTPUT6
}

apply_ufw() {
  local mgmt="${PRM_MGMT_CIDR:-10.8.0.0/24}"
  local vpn_addr="${PRM_VPN_BIND_ADDR:-10.8.0.1}"
  local wg_port="${PRM_WG_PORT:-51820}"
  ufw default deny incoming
  ufw default deny outgoing
  ufw allow in on lo || true
  ufw allow out on lo || true
  if ! ufw status | grep -q 'prm-ssh'; then
    ufw allow in proto tcp from "${mgmt}" to any port 22 comment prm-ssh
  fi
  if ! ufw status | grep -q 'prm-wireguard'; then
    ufw allow in proto udp to any port "${wg_port}" comment prm-wireguard
  fi
  if ! ufw status | grep -q 'prm-vpn-mcp'; then
    ufw allow in on wg0 proto tcp to "${vpn_addr}" port 8444 comment prm-vpn-mcp
  fi
  if ! ufw status | grep -q 'prm-dns-udp'; then
    ufw allow out proto udp to any port 53 comment prm-dns-udp
  fi
  if ! ufw status | grep -q 'prm-dns-tcp'; then
    ufw allow out proto tcp to any port 53 comment prm-dns-tcp
  fi
  if ! ufw status | grep -q 'prm-ntp'; then
    ufw allow out proto udp to any port 123 comment prm-ntp
  fi
  if ! ufw status | grep -q 'prm-deny-out'; then
    ufw deny out to any comment prm-deny-out
  fi
  ufw --force enable
}

apply_owner_egress() {
  PRM_UFW_MODE=apply
  if ! iptables -C OUTPUT -j PRM-OUTPUT 2>/dev/null; then
    iptables -N PRM-OUTPUT 2>/dev/null || true
    iptables -I OUTPUT 1 -j PRM-OUTPUT
  fi
  if ! ip6tables -C OUTPUT -j PRM-OUTPUT6 2>/dev/null; then
    ip6tables -N PRM-OUTPUT6 2>/dev/null || true
    ip6tables -I OUTPUT 1 -j PRM-OUTPUT6
  fi
  print_owner_egress >/dev/null
  PRM_UFW_MODE=print
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  set -euo pipefail
  print_ufw
  print_owner_egress
fi
