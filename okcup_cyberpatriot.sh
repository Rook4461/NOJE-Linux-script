#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME [--audit|--harden|--help]

Options:
  --audit   Show current security posture commonly checked in OK Cup/CyberPatriot
  --harden  Apply a baseline hardening profile (requires root)
  --help    Show this help message
EOF
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Error: --harden requires root privileges."
    exit 1
  fi
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

detect_pkg_manager() {
  if command_exists apt-get; then
    echo "apt"
  elif command_exists dnf; then
    echo "dnf"
  elif command_exists yum; then
    echo "yum"
  else
    echo ""
  fi
}

ensure_sshd_option() {
  local key="$1"
  local value="$2"
  local file="/etc/ssh/sshd_config"

  if [[ ! -f "$file" ]]; then
    echo "Skipping SSH hardening: $file not found."
    return
  fi

  cp -n "$file" "${file}.bak"
  if grep -Eq "^[#[:space:]]*${key}[[:space:]]+" "$file"; then
    sed -i -E "s|^[#[:space:]]*${key}[[:space:]]+.*|${key} ${value}|g" "$file"
  else
    printf "%s %s\n" "$key" "$value" >> "$file"
  fi
}

restart_ssh() {
  if command_exists systemctl; then
    systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
  elif command_exists service; then
    service ssh restart 2>/dev/null || service sshd restart 2>/dev/null || true
  fi
}

audit() {
  echo "== OK Cup / CyberPatriot Linux Audit =="

  if command_exists ufw; then
    echo "- UFW status:"
    ufw status || true
  else
    echo "- UFW not installed."
  fi

  if [[ -f /etc/ssh/sshd_config ]]; then
    echo "- SSH settings:"
    grep -E "^(PermitRootLogin|PasswordAuthentication|X11Forwarding)" /etc/ssh/sshd_config || true
  else
    echo "- SSH config not found."
  fi

  if [[ -f /etc/login.defs ]]; then
    echo "- Password policy settings:"
    grep -E "^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE)" /etc/login.defs || true
  else
    echo "- /etc/login.defs not found."
  fi
}

harden() {
  require_root

  local pkg_manager
  pkg_manager="$(detect_pkg_manager)"

  echo "== Applying baseline hardening =="
  case "$pkg_manager" in
    apt)
      apt-get update
      apt-get -y upgrade
      apt-get -y install ufw
      ;;
    dnf)
      dnf -y upgrade
      dnf -y install ufw || true
      ;;
    yum)
      yum -y update
      yum -y install ufw || true
      ;;
    *)
      echo "No supported package manager found; skipping package update."
      ;;
  esac

  if command_exists ufw; then
    ufw --force enable
    ufw allow OpenSSH || true
  fi

  ensure_sshd_option "PermitRootLogin" "no"
  ensure_sshd_option "PasswordAuthentication" "no"
  ensure_sshd_option "X11Forwarding" "no"
  restart_ssh

  if [[ -f /etc/login.defs ]]; then
    sed -i -E 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i -E 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/login.defs
    sed -i -E 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
  fi

  echo "Hardening complete. Run '$SCRIPT_NAME --audit' to review settings."
}

main() {
  case "${1:---help}" in
    --audit) audit ;;
    --harden) harden ;;
    --help|-h) usage ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
}

main "${1:---help}"
