#!/bin/bash
#
# Install a root-owned, privileged softnet where sand looks for it first:
#   /usr/local/libexec/sand/softnet        root:wheel 4555 (setuid root, default)
#                                          or 0555 plus a sudoers rule (--sudoers)
#   /usr/local/libexec/sand/softnet.sha256 root:wheel 0444, checked by sand before every VM
#
# Run as root: a Jamf policy script, or `sudo deploy/jamf/install-managed-softnet.sh`.
# Idempotent. Refuses to install below any path component that is not root-owned
# or that is group/world-writable, because a user who can rename a directory on the
# path can replace a setuid binary and get root.
#
# Never point sand at a setuid or sudoers-allowed Homebrew softnet: /opt/homebrew is
# writable by the user who installed Homebrew.
#
# CLI:
#   install-managed-softnet.sh [--sudoers [--sudoers-group GROUP]]
#                              [--version VER] [--sha256 HEX] [--from /path/to/softnet]
#                              [--install-dir DIR] [--enforce-no-forwarding]
#                              [--verify-only]
# Jamf (parameters 1-3 are Jamf's mount point, computer name and user name):
#   $4 privilege mode: suid (default) | sudoers
#   $5 source: release (default) | absolute path to a softnet binary
#   $6 softnet version (default 0.26.0)
#   $7 expected SHA-256: of the release tarball (source release) or of the binary (source path);
#      optional for versions this script already pins
#   $8 sudoers group (default admin)
#   $9 enforce no IP forwarding: true | false (default false)
#   $10 install directory (default /usr/local/libexec/sand; anything else needs
#       vm.run.network.softnetPath in sand's config)
set -euo pipefail

readonly LABEL_FORWARDING="local.sand.no-ip-forwarding"
readonly FORWARDING_PLIST="/Library/LaunchDaemons/${LABEL_FORWARDING}.plist"
readonly SUDOERS_FILE="/etc/sudoers.d/sand-softnet"
readonly RELEASE_URL_PREFIX="https://github.com/openai/softnet/releases/download"

mode="suid"
source_kind="release"
from_path=""
version="0.26.0"
expected_sha=""
sudoers_group="admin"
enforce_no_forwarding="false"
install_dir="/usr/local/libexec/sand"
verify_only="false"

log() { printf 'install-managed-softnet: %s\n' "$*"; }
die() { printf 'install-managed-softnet: error: %s\n' "$*" >&2; exit 1; }

# shasum -a 256 of upstream release artifacts this script trusts without --sha256
# (the tarball digest matches the Homebrew formula for the same version).
known_tarball_sha() {
  case "$1" in
    0.26.0) echo "8469759f9cdfaaba52a150b629877985129308461702bc074c3ad7727837db82" ;;
    *) echo "" ;;
  esac
}
known_binary_sha() {
  case "$1" in
    0.26.0) echo "2ea5572268f814317bc3944d1352032f1f4dafe00bfe453eefc64e9dc32627a3" ;;
    *) echo "" ;;
  esac
}

usage() {
  sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
}

is_true() {
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    true | yes | 1) return 0 ;;
    *) return 1 ;;
  esac
}

if [[ $# -ge 3 && "${1:-}" != --* ]]; then
  # Jamf: $1-$3 are Jamf's own; empty parameters keep the defaults.
  [[ -n "${4:-}" ]] && mode="$4"
  if [[ -n "${5:-}" && "$5" != "release" ]]; then
    source_kind="path"
    from_path="$5"
  fi
  [[ -n "${6:-}" ]] && version="$6"
  [[ -n "${7:-}" ]] && expected_sha="$7"
  [[ -n "${8:-}" ]] && sudoers_group="$8"
  if [[ -n "${9:-}" ]] && is_true "$9"; then enforce_no_forwarding="true"; fi
  [[ -n "${10:-}" ]] && install_dir="${10}"
else
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --sudoers) mode="sudoers" ;;
      --suid) mode="suid" ;;
      --sudoers-group) sudoers_group="${2:?--sudoers-group needs a value}"; shift ;;
      --version) version="${2:?--version needs a value}"; shift ;;
      --sha256) expected_sha="${2:?--sha256 needs a value}"; shift ;;
      --from) source_kind="path"; from_path="${2:?--from needs a path}"; shift ;;
      --install-dir) install_dir="${2:?--install-dir needs a value}"; shift ;;
      --enforce-no-forwarding) enforce_no_forwarding="true" ;;
      --verify-only) verify_only="true" ;;
      -h | --help) usage; exit 0 ;;
      *) die "unknown argument: $1 (see --help)" ;;
    esac
    shift
  done
fi

expected_sha="$(printf '%s' "$expected_sha" | tr '[:upper:]' '[:lower:]')"
[[ "$mode" == "suid" || "$mode" == "sudoers" ]] || die "privilege mode must be suid or sudoers, got '$mode'"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must look like 0.26.0, got '$version'"
[[ -z "$expected_sha" || "$expected_sha" =~ ^[0-9a-f]{64}$ ]] || die "--sha256 must be 64 hex digits"
[[ "$sudoers_group" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]*$ ]] || die "invalid sudoers group '$sudoers_group'"
[[ "$install_dir" == /* && "$install_dir" != *"/../"* && "$install_dir" != *"/./"* ]] || die "install directory must be an absolute, normalized path"
install_dir="${install_dir%/}"
readonly target="$install_dir/softnet"
readonly manifest="$install_dir/softnet.sha256"

sha256_of() { /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'; }

# $1 and every existing ancestor up to / must be a real directory (not a
# symlink), owned by root and not writable by group or other.
assert_root_only_path() {
  local current="$1" uid perms
  while :; do
    if [[ -L "$current" ]]; then
      die "$current is a symlink; refusing to install below it"
    fi
    if [[ -e "$current" ]]; then
      [[ -d "$current" ]] || die "$current is not a directory"
      uid="$(/usr/bin/stat -f '%u' "$current")"
      perms="$(/usr/bin/stat -f '%Lp' "$current")"
      [[ "$uid" == "0" ]] || die "$current is owned by uid $uid, not root; a non-root user could replace the setuid binary"
      (( (8#$perms & 8#022) == 0 )) || die "$current is group/world-writable (mode $perms); refusing"
    fi
    [[ "$current" == "/" ]] && break
    current="$(/usr/bin/dirname "$current")"
  done
}

if [[ "$verify_only" != "true" && "$(/usr/bin/id -u)" != "0" ]]; then
  die "must run as root (Jamf policy or sudo); --verify-only checks the download without root"
fi

work="$(/usr/bin/mktemp -d "${TMPDIR:-/private/var/tmp}/sand-softnet.XXXXXX")"
cleanup() { /bin/rm -rf "$work"; }
trap cleanup EXIT

fetch_release() {
  local url="$RELEASE_URL_PREFIX/$version/softnet.tar.gz" want got
  want="$expected_sha"
  [[ -n "$want" ]] || want="$(known_tarball_sha "$version")"
  [[ -n "$want" ]] || die "no pinned SHA-256 for softnet $version; pass --sha256 (Jamf \$7) with the tarball's digest"
  log "downloading $url"
  /usr/bin/curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    --max-time 300 --output "$work/softnet.tar.gz" "$url"
  got="$(sha256_of "$work/softnet.tar.gz")"
  [[ "$got" == "$want" ]] || die "release tarball SHA-256 is $got, expected $want; refusing"
  log "tarball SHA-256 verified ($got)"
  /bin/mkdir "$work/extract"
  /usr/bin/tar -xzf "$work/softnet.tar.gz" -C "$work/extract" softnet
  [[ -f "$work/extract/softnet" && ! -L "$work/extract/softnet" ]] || die "tarball has no regular softnet file"
  /bin/cp "$work/extract/softnet" "$work/softnet"
  local known
  known="$(known_binary_sha "$version")"
  if [[ -n "$known" ]]; then
    got="$(sha256_of "$work/softnet")"
    [[ "$got" == "$known" ]] || die "softnet binary SHA-256 is $got, expected $known; refusing"
  fi
}

copy_from_path() {
  local got want
  [[ -f "$from_path" ]] || die "$from_path is not a file"
  # Copy first, then hash the copy: the source may be in a user-writable location.
  /bin/cp "$from_path" "$work/softnet"
  got="$(sha256_of "$work/softnet")"
  want="$expected_sha"
  [[ -n "$want" ]] || want="$(known_binary_sha "$version")"
  [[ -n "$want" ]] || die "no pinned SHA-256 for softnet $version; pass --sha256 with the binary's digest ($got)"
  [[ "$got" == "$want" ]] || die "$from_path has SHA-256 $got, expected $want (softnet $version); pass --version/--sha256 after reviewing it"
  log "binary SHA-256 verified ($got)"
}

if [[ "$source_kind" == "release" ]]; then
  fetch_release
else
  copy_from_path
fi
/usr/bin/file -b "$work/softnet" | /usr/bin/grep -q 'Mach-O' || die "softnet is not a Mach-O executable"
binary_sha="$(sha256_of "$work/softnet")"

if [[ "$verify_only" == "true" ]]; then
  log "verify-only: softnet $version verified, SHA-256 $binary_sha; nothing installed"
  exit 0
fi

assert_root_only_path "$install_dir"
if [[ ! -d "$install_dir" ]]; then
  /bin/mkdir -p "$install_dir"
fi
/usr/sbin/chown root:wheel "$install_dir"
/bin/chmod 0755 "$install_dir"
assert_root_only_path "$install_dir"
if [[ -L "$target" || ( -e "$target" && ! -f "$target" ) ]]; then
  die "$target exists and is not a regular file"
fi

# Install next to the target, then rename: tart never sees a half-written binary.
binary_mode="0555"
[[ "$mode" == "suid" ]] && binary_mode="4555"
/usr/bin/install -o root -g wheel -m "$binary_mode" "$work/softnet" "$install_dir/.softnet.new"
/bin/mv -f "$install_dir/.softnet.new" "$target"
installed_sha="$(sha256_of "$target")"
[[ "$installed_sha" == "$binary_sha" ]] || die "installed binary hash changed during install"
printf '%s  %s\n' "$installed_sha" "$target" > "$work/softnet.sha256"
/usr/bin/install -o root -g wheel -m 0444 "$work/softnet.sha256" "$install_dir/.softnet.sha256.new"
/bin/mv -f "$install_dir/.softnet.sha256.new" "$manifest"
log "installed $target (root:wheel $binary_mode, softnet $version, SHA-256 $installed_sha)"

if [[ "$mode" == "sudoers" ]]; then
  /usr/bin/dscl . -read "/Groups/$sudoers_group" PrimaryGroupID > /dev/null 2>&1 || die "group $sudoers_group does not exist"
  cat > "$work/sudoers" <<EOF
# Managed by sand deploy/jamf/install-managed-softnet.sh; do not edit.
# Members of $sudoers_group may run the root-owned managed softnet as root without a
# password (tart runs softnet, which re-execs itself with sudo -n). No SETENV.
Defaults!$target env_keep += "SENTRY_DSN CIRRUS_SENTRY_TAGS"
%$sudoers_group ALL=(root) NOPASSWD: $target
EOF
  /usr/sbin/visudo -cf "$work/sudoers" > /dev/null || die "generated sudoers rule failed visudo -c"
  /bin/mkdir -p /etc/sudoers.d
  /usr/bin/install -o root -g wheel -m 0440 "$work/sudoers" "$SUDOERS_FILE"
  /usr/sbin/visudo -c > /dev/null || { /bin/rm -f "$SUDOERS_FILE"; die "sudoers no longer validates; removed $SUDOERS_FILE"; }
  /usr/bin/grep -Eq '^[#@]includedir[[:space:]]+(/private)?/etc/sudoers\.d' /etc/sudoers \
    || log "WARNING: /etc/sudoers has no includedir for /etc/sudoers.d; the rule will not apply"
  log "installed $SUDOERS_FILE (%$sudoers_group NOPASSWD: $target)"
elif [[ -e "$SUDOERS_FILE" ]]; then
  # Switching to setuid: drop the now-unneeded rule.
  /bin/rm -f "$SUDOERS_FILE"
  log "removed $SUDOERS_FILE (setuid mode needs no sudoers rule)"
fi

if [[ "$enforce_no_forwarding" == "true" ]]; then
  log "WARNING: enforcing net.inet.ip.forwarding=0 and net.inet6.ip6.forwarding=0 at boot and every 60s."
  log "WARNING: this breaks Internet Sharing, Tailscale subnet routing / exit node, and any VPN or VM tool that routes through this Mac."
  cat > "$work/forwarding.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL_FORWARDING</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/sbin/sysctl</string>
    <string>-w</string>
    <string>net.inet.ip.forwarding=0</string>
    <string>net.inet6.ip6.forwarding=0</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>StartInterval</key>
  <integer>60</integer>
  <key>StandardOutPath</key>
  <string>/dev/null</string>
  <key>StandardErrorPath</key>
  <string>/dev/null</string>
</dict>
</plist>
EOF
  /usr/bin/plutil -lint "$work/forwarding.plist" > /dev/null || die "generated LaunchDaemon plist is invalid"
  /bin/launchctl bootout "system/$LABEL_FORWARDING" > /dev/null 2>&1 || true
  /usr/bin/install -o root -g wheel -m 0644 "$work/forwarding.plist" "$FORWARDING_PLIST"
  /bin/launchctl bootstrap system "$FORWARDING_PLIST"
  log "installed $FORWARDING_PLIST; current state: $(/usr/sbin/sysctl -n net.inet.ip.forwarding)/$(/usr/sbin/sysctl -n net.inet6.ip6.forwarding)"
fi

log "done. Verify as the runner user: sand network preflight --config <config>  (expect P12/P3/P13 ok, backend softnet)"
