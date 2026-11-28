# Jamf deployment for sand runner Macs

These scripts make a Jamf-managed Mac ready for sand's secure softnet backend
with no steps for the user. With them in place, sand's default
`backend: auto` uses softnet (host-service and peer-VM isolation, independent
of host IP forwarding). Without them, sand falls back to the root-free
`hostOnly` backend or fails closed (exit 78). It never runs insecurely. The
background is in [docs/network-isolation.md](../../docs/network-isolation.md#jamf--managed-deployment).

| Script | Jamf object | Runs as |
| --- | --- | --- |
| `install-managed-softnet.sh` | Policy script (Install) | root |
| `uninstall-managed-softnet.sh` | Policy script (Uninstall) | root |
| `sand-readiness-ea.sh` | Computer extension attribute (String) | root |

All three use `set -euo pipefail`, call system tools by absolute path, never
pipe a download into a shell, and are shellcheck-clean.

## What gets installed

| Path | Owner / mode | Purpose |
| --- | --- | --- |
| `/usr/local/libexec/sand/` | root:wheel 0755 | managed directory (every parent directory must be root-owned and not group/world-writable) |
| `/usr/local/libexec/sand/softnet` | root:wheel 4555 (setuid) or 0555 with `--sudoers` | the only softnet sand will run with privilege |
| `/usr/local/libexec/sand/softnet.sha256` | root:wheel 0444 | `shasum -a 256` manifest; sand checks it before every VM (preflight P13) |
| `/etc/sudoers.d/sand-softnet` | root:wheel 0440 | `--sudoers` mode only: `%GROUP ALL=(root) NOPASSWD: /usr/local/libexec/sand/softnet`, checked with `visudo -c` |
| `/Library/LaunchDaemons/local.sand.no-ip-forwarding.plist` | root:wheel 0644 | `--enforce-no-forwarding` only |

The default source is the upstream release
`https://github.com/openai/softnet/releases/download/<version>/softnet.tar.gz`.
For 0.26.0 the script pins the tarball digest
`8469759f9cdfaaba52a150b629877985129308461702bc074c3ad7727837db82` (the same
value as the Homebrew formula) and the binary digest
`2ea5572268f814317bc3944d1352032f1f4dafe00bfe453eefc64e9dc32627a3`. Any other
version needs an explicit digest. The binary is installed under a temporary
name and renamed into place, so a running sand never sees a partial file.

**Never** make a Homebrew softnet setuid root or allow it in sudoers.
`/opt/homebrew` belongs to the user, so any process running as that user could
swap the binary and get root. sand refuses such a softnet (preflight P12).

## Policy: install

- Trigger: Enrollment Complete and Recurring Check-in. Execution frequency:
  Ongoing; the script is idempotent and cheap once installed. Or use Once per
  computer plus a Smart Group on the extension attribute (below) to re-run it
  where the result is not `ready`.
- Scope: the runner Macs (for example a Smart Group "sand runners").
- Script: `install-managed-softnet.sh`, priority Before. Parameter labels:

| Parameter | Label | Default |
| --- | --- | --- |
| `$4` | Privilege mode (`suid` or `sudoers`) | `suid` |
| `$5` | Source (`release` or absolute path to a softnet binary) | `release` |
| `$6` | softnet version | `0.26.0` |
| `$7` | Expected SHA-256 (tarball for `release`, binary for a path) | pinned for 0.26.0 |
| `$8` | sudoers group (sudoers mode) | `admin` |
| `$9` | Enforce no IP forwarding (`true`/`false`) | `false` |
| `$10` | Install directory (non-default needs `vm.run.network.softnetPath`) | `/usr/local/libexec/sand` |
| `$11` | (unused) | |

Empty parameters keep the defaults. `$1`-`$3` are Jamf's own (mount point,
computer name, user name) and are ignored.

`suid` or `sudoers`: both let anyone in scope run softnet as root with any
arguments. `suid` needs nothing else. `sudoers` limits that to one group
(`admin` by default, `staff` for every local user) and works with tools that
refuse setuid binaries. In sudoers mode softnet re-execs itself with
`sudo --non-interactive --preserve-env=SENTRY_DSN,CIRRUS_SENTRY_TAGS`, so the
rule keeps exactly those two variables (`env_keep`). It does not grant `SETENV`,
which would allow `DYLD_*` injection. Test the sudoers mode on one Mac before
rolling it out (verify).

`--enforce-no-forwarding` (`$9 true`) installs a LaunchDaemon that sets
`net.inet.ip.forwarding=0` and `net.inet6.ip6.forwarding=0` at boot and every
60 seconds. **It breaks Internet Sharing, Tailscale subnet routing and exit
nodes, and any VPN or VM tool that routes through the Mac.** With a working
managed softnet you do not need it. Use it only on dedicated runner Macs that
may fall back to hostOnly.

## Policy: uninstall

`uninstall-managed-softnet.sh`: `$4` install directory, `$5` keep the
no-forwarding LaunchDaemon (`true`/`false`). It removes the binary, manifest,
sudoers rule and (by default) the LaunchDaemon. It does not change the current
forwarding values.

## Extension attribute: sand readiness

Data type String, input type Script, contents `sand-readiness-ea.sh`. Example
results:

```
<result>ready; softnet=managed privilege=suid sha256=ok forwarding=1/1 no_forwarding_daemon=no tart=2.42.0</result>
<result>ready-hostonly; softnet=missing privilege=none sha256=none forwarding=0/0 no_forwarding_daemon=yes tart=2.42.0</result>
<result>not-ready; softnet=missing privilege=none sha256=none forwarding=1/1 no_forwarding_daemon=no tart=2.42.0</result>
```

- `ready`: the managed softnet is root-owned all the way up, privileged (setuid
  or sudoers) and matches its manifest. sand `auto` uses softnet.
- `ready-hostonly`: no usable managed softnet, but IP forwarding is off. sand
  `auto` uses hostOnly.
- `not-ready`: sand refuses to boot isolated VMs (exit 78) until the policy runs
  or forwarding is turned off.

The EA reads the tart version from its Homebrew keg path. It never executes
softnet or tart, because running a user-writable binary as root would itself be
an escalation path. Smart Group suggestion: "sand not ready" = EA does not
start with `ready`. Scope the install policy to it.

## Optional configuration profiles

These reduce what a `hostOnly` fallback VM can reach on the host. A working
managed softnet already blocks host services. Check every key against
Apple's current Device Management documentation for your macOS version before
deploying (verify).

- AirPlay Receiver listens on TCP 5000/7000 on all interfaces. Restrictions
  payload (`com.apple.applicationaccess`): `allowAirPlayIncomingRequests` =
  false (verify).
- Internet Sharing turns IP forwarding on. `com.apple.MCX`:
  `forceInternetSharingOff` = true (verify).
- Remote Login (sshd) on the host is reachable from a hostOnly VM. Leave it
  off unless needed, or rely on `hostListeners: deny` in the sand config.
- No PPPC/TCC or system extension approval is needed. tart uses
  Virtualization.framework and vmnet; softnet uses vmnet as root.

Also deploy tart (2.42 or newer) and `sshpass` as you do other tools. The
readiness EA reports the tart version.

## Try it on one Mac first

See "Simulate a managed Mac locally" in
[docs/network-isolation.md](../../docs/network-isolation.md#simulate-a-managed-mac-locally):

```sh
sudo deploy/jamf/install-managed-softnet.sh
sudo deploy/jamf/sand-readiness-ea.sh
swift run sand network preflight --config fixtures/network_github_default.yml
```
