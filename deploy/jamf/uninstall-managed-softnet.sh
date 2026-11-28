#!/bin/bash
#
# Remove what install-managed-softnet.sh installed:
#   /usr/local/libexec/sand/softnet, softnet.sha256 (and the directory if empty),
#   /etc/sudoers.d/sand-softnet, and the optional no-forwarding LaunchDaemon.
# Run as root (Jamf policy script or sudo). Idempotent. Does not change the current
# net.inet.ip.forwarding / net.inet6.ip6.forwarding values.
#
# CLI:  uninstall-managed-softnet.sh [--install-dir DIR] [--keep-forwarding-daemon]
# Jamf: $4 install directory (default /usr/local/libexec/sand)
#       $5 keep the no-forwarding LaunchDaemon: true | false (default false)
#
# After this, sand's default backend: auto uses hostOnly (needs host IP forwarding
# off); configs that pin backend: softnet fail preflight (exit 78) until softnet
# is installed again.
set -euo pipefail

readonly LABEL_FORWARDING="local.sand.no-ip-forwarding"
readonly FORWARDING_PLIST="/Library/LaunchDaemons/${LABEL_FORWARDING}.plist"
readonly SUDOERS_FILE="/etc/sudoers.d/sand-softnet"

install_dir="/usr/local/libexec/sand"
keep_daemon="false"

log() { printf 'uninstall-managed-softnet: %s\n' "$*"; }
die() { printf 'uninstall-managed-softnet: error: %s\n' "$*" >&2; exit 1; }

if [[ $# -ge 3 && "${1:-}" != --* ]]; then
  [[ -n "${4:-}" ]] && install_dir="$4"
  case "$(printf '%s' "${5:-}" | tr '[:upper:]' '[:lower:]')" in
    true | yes | 1) keep_daemon="true" ;;
  esac
else
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --install-dir) install_dir="${2:?--install-dir needs a value}"; shift ;;
      --keep-forwarding-daemon) keep_daemon="true" ;;
      -h | --help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
      *) die "unknown argument: $1" ;;
    esac
    shift
  done
fi

[[ "$(/usr/bin/id -u)" == "0" ]] || die "must run as root (Jamf policy or sudo)"
[[ "$install_dir" == /* && "$install_dir" != "/" ]] || die "install directory must be absolute"
install_dir="${install_dir%/}"

for file in "$install_dir/softnet" "$install_dir/softnet.sha256" "$install_dir/.softnet.new" "$install_dir/.softnet.sha256.new"; do
  if [[ -e "$file" || -L "$file" ]]; then
    # Strip the mode first: a hard link to a setuid binary would outlive rm.
    if [[ -f "$file" && ! -L "$file" ]]; then /bin/chmod 0000 "$file"; fi
    /bin/rm -f "$file"
    log "removed $file"
  fi
done
if [[ -d "$install_dir" ]]; then
  if /bin/rmdir "$install_dir" 2> /dev/null; then
    log "removed $install_dir"
  else
    log "kept $install_dir (not empty)"
  fi
fi

if [[ -e "$SUDOERS_FILE" ]]; then
  /bin/rm -f "$SUDOERS_FILE"
  log "removed $SUDOERS_FILE"
fi

if [[ "$keep_daemon" != "true" && -e "$FORWARDING_PLIST" ]]; then
  /bin/launchctl bootout "system/$LABEL_FORWARDING" > /dev/null 2>&1 || true
  /bin/rm -f "$FORWARDING_PLIST"
  log "removed $FORWARDING_PLIST (forwarding stays at its current value until something changes it)"
fi
log "done"
