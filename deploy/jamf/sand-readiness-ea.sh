#!/bin/bash
#
# Jamf extension attribute: reports whether this Mac can run sand with secure
# softnet isolation and zero user steps. Output: <result>STATUS; key=value ...</result>
#   STATUS ready              managed softnet is safe, privileged and matches its manifest
#   STATUS ready-hostonly     no usable managed softnet, but host IP forwarding is off
#                             (sand's default backend auto falls back to hostOnly safely)
#   STATUS not-ready          neither: sand would refuse to boot isolated VMs (exit 78)
# privilege=suid(group=G) / sudoers(group=G) names who may run softnet; the EA
# cannot know which account runs sand, so scope the smart group (or check that
# the runner account is in G) rather than trusting "ready" alone.
# Runs as root. Read-only: it never executes softnet or tart (both may live in
# user-writable directories, and running them as root would be an escalation path).
set -euo pipefail
# Always print a <result>, even when a step fails unexpectedly: Jamf records an
# empty value otherwise.
trap 'echo "<result>not-ready; error=ea-failed-at-line-$LINENO</result>"; exit 0' ERR

readonly target="/usr/local/libexec/sand/softnet"
readonly manifest="/usr/local/libexec/sand/softnet.sha256"
readonly sudoers_file="/etc/sudoers.d/sand-softnet"

problems=""
add_problem() { problems="${problems:+$problems,}$1"; }

# The binary and every ancestor directory: root-owned, not group/world-writable.
path_safe() {
  local current="$1" perms
  while :; do
    [[ -L "$current" ]] && return 1
    [[ "$(/usr/bin/stat -f '%u' "$current")" == "0" ]] || return 1
    perms="$(/usr/bin/stat -f '%Lp' "$current")"
    (( (8#$perms & 8#022) == 0 )) || return 1
    [[ "$current" == "/" ]] && return 0
    current="$(/usr/bin/dirname "$current")"
  done
}

softnet="missing"
privilege="none"
pin="none"
if [[ -f "$target" ]]; then
  if path_safe "$target"; then
    softnet="managed"
  else
    softnet="unsafe-path"
    add_problem "softnet-path"
  fi
  if [[ -u "$target" && "$(/usr/bin/stat -f '%u' "$target")" == "0" ]]; then
    if [[ "$(/usr/bin/stat -f '%Lp' "$target")" == *[1357] ]]; then
      privilege="suid(group=everyone)"
    else
      privilege="suid(group=$(/usr/bin/stat -f '%Sg' "$target"))"
    fi
  elif [[ -f "$sudoers_file" ]] && /usr/bin/grep -q "NOPASSWD: $target\$" "$sudoers_file"; then
    sudoers_group="$(/usr/bin/awk -v t="$target" '$1 ~ /^%/ && $NF == t {print substr($1, 2); exit}' "$sudoers_file")"
    privilege="sudoers(group=${sudoers_group:-unknown})"
  else
    add_problem "softnet-unprivileged"
  fi
  if [[ -f "$manifest" ]]; then
    want="$(/usr/bin/awk 'NR == 1 {print tolower($1)}' "$manifest")"
    got="$(/usr/bin/shasum -a 256 "$target" | /usr/bin/awk '{print $1}')"
    if [[ "$want" == "$got" ]]; then pin="ok"; else pin="mismatch"; add_problem "softnet-sha256"; fi
  else
    pin="no-manifest"
  fi
fi

ipv4="$(/usr/sbin/sysctl -n net.inet.ip.forwarding 2> /dev/null || echo unreadable)"
ipv6="$(/usr/sbin/sysctl -n net.inet6.ip6.forwarding 2> /dev/null || echo unreadable)"
forwarding_daemon="no"
[[ -f /Library/LaunchDaemons/local.sand.no-ip-forwarding.plist ]] && forwarding_daemon="yes"

# tart's version from its Homebrew keg path, without running it.
tart_version="missing"
for candidate in /opt/homebrew/bin/tart /usr/local/bin/tart; do
  if [[ -e "$candidate" ]]; then
    real="$(/usr/bin/readlink "$candidate" || true)"
    case "$real" in
      */Cellar/tart/*/bin/tart) tart_version="${real%/bin/tart}"; tart_version="${tart_version##*/}" ;;
      *) tart_version="unknown" ;;
    esac
    break
  fi
done

status="not-ready"
if [[ "$softnet" == "managed" && "$privilege" != "none" && "$pin" != "mismatch" ]]; then
  status="ready"
elif [[ "$ipv4" == "0" && "$ipv6" == "0" && "$pin" != "mismatch" ]]; then
  status="ready-hostonly"
fi

echo "<result>$status; softnet=$softnet privilege=$privilege sha256=$pin forwarding=$ipv4/$ipv6 no_forwarding_daemon=$forwarding_daemon tart=$tart_version${problems:+ problems=$problems}</result>"
