# VM network isolation

Sand isolates every VM's network **by default**, with **no per-user setup**.
A runner with no `vm.run.network` key gets `profile: github` with
`backend: auto`: softnet on a Mac where IT (or an admin, once) installed a
root-owned privileged softnet at `/usr/local/libexec/sand/softnet`
([Jamf / managed deployment](#jamf--managed-deployment)), otherwise the
root-free `hostOnly` backend:

1. **No direct egress.** An enforcement backend removes every route from the
   guest to anything but the host:
   - `hostOnly` (auto's fallback): `tart run --net-host`. The VM sits on a host-only
     vmnet bridge (for example `bridge100`, 192.168.128.0/24) with no default
     gateway, no DNS and no NAT. Needs no root. A guest with root can still
     add a route via the host's bridge address, so host IP forwarding must be
     off (preflight P11) unless `ipForwarding: accept` is set.
   - `softnet` (auto's choice on a managed Mac): `--net-softnet --net-softnet-block=0.0.0.0/0
     "--net-softnet-allow=in proto tcp @host port 22"`. Also blocks host
     services and peer VMs, and does not depend on host IP forwarding, but
     needs a privileged softnet (setuid root or passwordless sudo) that only
     root can replace (preflight P12).
2. **A host-side allowlisting proxy.** Sand runs a per-VM HTTPS CONNECT proxy
   bound to `127.0.0.1` on the host. It checks the hostname against the
   policy, resolves it with the host's system resolver, refuses private or
   host-local addresses, and requires the TLS ClientHello's SNI to equal the
   CONNECT host.
3. **An SSH reverse tunnel.** The guest reaches the proxy as `127.0.0.1:3128`
   through `ssh -N -R 127.0.0.1:3128:127.0.0.1:<port>`, which runs over the
   SSH session Sand already uses. The proxy never listens on the VM bridge.
   If the tunnel dies, egress dies with it.
4. **Guest settings for usability only.** Sand writes `https_proxy`,
   `http_proxy`, `no_proxy` and `NODE_USE_ENV_PROXY=1` (Node 24+ ignores the
   proxy variables without it) into the runner's `.env` and the login shell
   profiles. On macOS it also sets the system web proxy and points DNS at
   loopback. Enforcement never depends on these settings: a tool that ignores
   them just fails to connect.
5. **Fail closed at every stage:**
   - preflight before any clone (exit 78);
   - a host-listener report and a guest egress check before any runner registers;
   - a watchdog from SSH-ready until teardown;
   - a bounded number of consecutive enforcement failures, then exit 78.

   Sand never falls back to shared NAT.

## Threat model

The guest runs untrusted workflow code as a root-capable user. The guest must
be able to reach GitHub (and approved package hosts) to run Actions jobs. It
must never reach:

- the developer's LAN, Tailscale/tailnet (100.64/10) or other networks;
- corporate networks reachable over the host's VPN (for example BlastShield
  172.16/12 routes, or 172.16.0.1 resolvers);
- cloud metadata (169.254.169.254) or anything link-local;
- arbitrary internet destinations, over UDP/QUIC, IPv6 or DNS.

The guest is not trusted to honour proxy variables. The backend removes every
direct path off the host, so the only way out is the host proxy, and the proxy
enforces the policy outside the guest.

**Host services and peer VMs depend on the backend.** Under `softnet` the guest
cannot reach the host (other than SSH replies) or other VMs. Under `hostOnly`:

- **Host services bound to any non-loopback host address are reachable.**
  Services on all interfaces answer on the bridge address, for example
  ControlCenter/AirPlay on `:5000`/`:7000`, rapportd, a dev server on
  `*:3000`, or sshd if Remote Login is on. macOS is a weak-host system, so a
  guest that adds a route via the bridge also reaches services bound only to
  the host's LAN, VPN or utun address (for example a dev server on
  `10.0.0.66:8080`). Sand reports all of them before registration
  (`hostListeners`, below) and can refuse the VM (`hostListeners: deny`).
  Services bound to `127.0.0.1`, including Sand's own proxy, are never
  reachable.
- **Host IP forwarding is an egress path.** The guest has no gateway, but a
  job with root can run `sudo route add -host 100.100.100.100 192.168.128.1`.
  With `net.inet.ip.forwarding=1` the host then forwards those packets. Where
  a return path exists (a tailnet resolver on the host, a NATing VPN, pf NAT,
  Internet Sharing, Docker/OrbStack NAT) the guest gets two-way reach that
  bypasses the proxy, the allowlist and the audit log; elsewhere it still has
  one-way UDP exfiltration. This was confirmed live: MagicDNS at
  100.100.100.100 resolved arbitrary names for a guest that routed via the
  host. Preflight P11 therefore fails closed while either forwarding switch is
  on, the watchdog stops a running VM if forwarding turns on, and the guest
  verifier repeats its probes after routing each target via the host.
- **Peer-VM isolation is not guaranteed.** With tart 2.42 each concurrently
  running `--net-host` VM got its own bridge (`bridge100`, `bridge101`), and a
  peer was unreachable both directly and when routed via the host (no return
  route). Nothing documents that behaviour, so `sand run` still warns when more
  than one runner uses `hostOnly`. Use `backend: softnet` (or one VM per host)
  when concurrent jobs must not see each other.
- Host services are not egress: a host listener cannot forward the guest to
  the internet unless it is itself a proxy or resolver. Host DNS on `:53` is
  therefore treated as egress and must be closed (probe N3b/N4a).

## Host setup

None per user. `sand doctor` or `sand network preflight --config sand.yml`
shows what the host supports and which backend `auto` picks.

- **Managed Mac (recommended):** IT deploys softnet to
  `/usr/local/libexec/sand/softnet` with
  [`deploy/jamf/install-managed-softnet.sh`](../deploy/jamf/README.md). The
  default `backend: auto` then uses softnet with zero user steps. To do the
  same by hand, see [Simulate a managed Mac locally](#simulate-a-managed-mac-locally).
- **Unmanaged Mac:** nothing to install. `auto` uses `hostOnly`, which needs
  no root but does need host IP forwarding off (P11).

Softnet needs root to create its vmnet interface, then drops privileges to
the user and group given by `--user`/`--group` (tart passes the invoking
user). Those flags are honored from any caller, so whoever may run the
privileged softnet can keep it running as root; the managed installer limits
that to one group (see [Jamf / managed deployment](#jamf--managed-deployment)).
Sand never runs `sudo` for you, never changes host settings, and only uses a
privileged softnet that a non-root user cannot replace:

- **Never make the Homebrew softnet setuid root or sudoers-allowed.**
  `/opt/homebrew` (and every Cellar directory under it) belongs to the user
  who installed Homebrew, so any process running as that user can rename the
  binary away and drop in its own: a local privilege escalation to root. P12
  refuses such a softnet: `backend: softnet` fails closed, `backend: auto`
  falls back to hostOnly with a warning and a `network.backend.fallback`
  audit event. Earlier versions of this document recommended exactly that
  `chown`/`chmod u+s`; undo it with `brew reinstall softnet`.
- Discovery order: `vm.run.network.softnetPath`, then the managed path
  `/usr/local/libexec/sand/softnet`, then the first `softnet` on PATH. An
  explicit path never falls back; a present managed install is used even if
  it fails (so it fails instead of silently trying PATH). Whatever is found
  must pass P12. A path containing `:` is rejected (tart splits PATH on it).
- Sand starts `tart run` by absolute path with `PATH` set to the checked
  binary's directory followed only by `/usr/bin:/bin:/usr/sbin:/sbin` (tart
  2.42 execs the first `softnet` on its PATH and needs nothing else from it
  for `run`), so tart execs exactly the binary Sand checked, and if that binary
  disappears tart fails instead of finding another one. Sand refuses to start
  tart under softnet without a checked binary. Nothing else in tart's
  environment changes.
- Disclosure: softnet runs its setup as root. It also rewrites the system
  bootpd preferences (`DHCPLeaseTimeSecs=600`) so ephemeral VMs do not exhaust
  DHCP leases.

## Configuration

```yaml
vm:
  run:
    network:
      profile: github                 # github (default) | offline
      backend: auto                   # auto (default) | hostOnly | softnet
      softnetPath: /usr/local/libexec/sand/softnet  # optional; see discovery order
      softnetSHA256: 2ea5572268f814317bc3944d1352032f1f4dafe00bfe453eefc64e9dc32627a3  # optional pin (0.26.0), checked before every VM
      presets: [npm, pypi, homebrew]  # optional extra built-in bundles
      allowedDomains:                 # optional; port defaults to 443
        - registry.example-artifacts.com
        - "*.cdn.example.com"
        - "git.example.org:8443"
      verify: basic                   # basic (default) | strict
      hostListeners: warn             # hostOnly: warn (default) | deny
      acceptedHostListeners: []       # with deny: e.g. [tcp/7000, udp/5353, udp/*]
      tlsInspection: fail             # fail (default) | trustHostCA
      ipForwarding: deny              # hostOnly: deny (default) | accept
      maxEnforcementFailures: 3       # consecutive failures before exit 78 (1-100)
      allowedCIDRs:                   # expert escape hatch, softnet backend only
        - { cidr: 203.0.113.10/32, port: 443, proto: tcp }
```

- **No `network` key** is the same as `profile: github` with `backend: auto`.
- **`backend`** applies to profiles:
  - `auto` (default) uses softnet when it is installed where only root can
    replace it (P12), new enough (P2) and privileged (P3), and hostOnly
    otherwise. It is resolved once at startup, where the full preflight and
    the listener posture are computed for it, and then pinned for the life of
    `sand run`. If the managed softnet later disappears, loses its privilege
    or stops matching its pin, the per-VM preflight fails and counts as an
    enforcement failure; Sand never silently downgrades later VMs to
    hostOnly. A managed install (or a `softnetPath`) is never a reason to
    fall back: when one is present, `auto` keeps softnet whatever is wrong
    with it (unsafe path P12, too old P2, unprivileged or not executable by
    this user P3, SHA-256 mismatch P13, old tart P1), and the preflight fails
    closed (exit 78). Only a softnet found on PATH, or none, lets `auto` pick
    hostOnly. When `auto` picks hostOnly
    because a PATH softnet was present but rejected (for example setuid root in a
    user-writable directory), startup logs a `WARNING`, preflight shows a
    `P0 backend auto` warning, and `network.backend.fallback` is audited. The
    policy hash differs per backend, and `network.policy.compiled` names the
    backend and the softnet binary. `sand network explain` prints what `auto`
    resolved to and why.
  - `hostOnly` works everywhere tart supports `--net-host` (preflight P1).
  - `softnet` requires a safely installed privileged softnet (P2, P3, P12,
    P13) and adds host-service and peer-VM isolation. Pin it where a Mac
    without any softnet installed must fail closed instead of using hostOnly.
- **`softnetPath`** (absolute, named `softnet`): use this binary instead of
  the managed path or PATH. **`softnetSHA256`**: the binary must hash to this
  value before every VM, in addition to the installer's manifest
  (`softnet.sha256` next to the binary, root-owned), when there is one.
- **`hostListeners`** (hostOnly only). After boot and before registration,
  Sand lists host TCP listeners and unconnected UDP sockets a guest can reach
  (bound to `*`, to the bridge address, or to any other non-loopback host
  address, which a guest reaches by routing via the bridge) and logs
  `network.host.listeners`. With `warn` it continues; with `deny` it destroys
  the VM unless every listener matches `acceptedHostListeners`
  (`tcp/PORT`, `udp/PORT`, `tcp/*`, `udp/*`). The guest egress check also probes
  each TCP listener from the guest and records what it actually reached
  (`host_services_reachable=` on `network.guest.verified`).
  Sources, all unprivileged: `netstat -an` (every user's sockets, when the host
  lets the caller see them), `lsof` (this user's sockets, with process names),
  and, when netstat is blind, a TCP connect probe of every reachable host IPv4
  address on well-known service ports. The audit line names the method. In
  `lsof+sweep` mode another user's (root) listener on an uncommon port, or a
  root UDP socket, can be missed: use `softnet` if that matters.
- **`ipForwarding`** (hostOnly only). `deny` (default) fails preflight P11,
  the per-VM check and, through the watchdog, a running job while
  `net.inet.ip.forwarding` or `net.inet6.ip6.forwarding` is on (or unreadable).
  `accept` runs anyway: P11 is a warning, every VM logs and audits
  `network.host.forwarding result=accepted`, and what the routed probes reach
  is recorded as `routed_reachable=` on `network.guest.verified`. `sand
  validate` warns about `accept`. Sand never changes the sysctl itself; see
  [Troubleshooting](#troubleshooting).
- **`tlsInspection`**: see [TLS-inspecting endpoint agents](#tls-inspecting-endpoint-agents-netskope-zscaler).
- **`maxEnforcementFailures`**: see [What happens at runtime](#what-happens-at-runtime).
- **`profile: offline`** removes direct egress with no proxy; only host SSH
  works. Use it for script provisioners that need no network. It is the only
  profile that accepts `verify: off`.
- **`mode: shared`** is the only way to get Tart's unrestricted shared NAT. It
  is required for host `mounts`. Sand warns on validate and on every boot.
- **`mode: softnet` and `mode: restricted`** keep their prototype meaning and
  always use softnet. Restricted also allows host SSH. Under a VPN with split
  DNS, plain softnet makes the steered GitHub names unreachable, because it
  blocks private destinations. Prefer the profile.

Validation rules:

- Setting both `profile` and `mode` is an error, and so is an empty
  `network: {}`. An unknown profile, mode, preset, backend, `hostListeners`,
  `tlsInspection` or `ipForwarding` value is also an error.
- `backend`, `hostListeners`, `acceptedHostListeners`, `tlsInspection` and
  `ipForwarding` require a profile; `tlsInspection` requires `profile: github`.
  `maxEnforcementFailures` must be 1-100 and is rejected with `mode: shared`.
- `allowedDomains` entries are lowercased and any trailing dot is stripped.
  - Each entry must use valid hostname labels. Give IDN names in punycode.
  - Two wildcard forms are allowed: a leading `*.` (at least two labels after
    it), and one `*` inside the first label (`build*.example.com`). Avoid
    either form on multi-tenant suffixes (`*.blob.core.windows.net`,
    `*.s3.amazonaws.com`, `*.cloudfront.net`, `*.github.io`): anyone can
    register a name there, so the wildcard admits their endpoints too.
  - These are rejected: IP literals, a bare `*`, `*.com`, `a.*.b`, and ports
    outside 1-65535. Ports 22 and 25 produce a warning.
- `allowedCIDRs` requires `backend: softnet` (hostOnly has no route off the
  host, and `auto` may resolve to hostOnly). Entries must be IPv4 /24 to /32
  and must set `port`.
  - Ranges that overlap private or CGNAT space are rejected unless
    `allowPrivate: true` is set, and that also warns.
  - Loopback, `0/8`, link-local/metadata (169.254/16), multicast and
    reserved space are rejected even with `allowPrivate`.
  - Preflight (P9) also fails if an entry contains a host address or overlaps
    a subnet attached to the host (the LAN, the vmnet bridge).
  - These rules bypass the proxy: there is no hostname check and no audit line.
- Isolated VMs may not use host mounts or `nested: true`. `noClipboard`
  defaults to true; setting it to false produces a warning.
- `allowGitHubSSH` and `transport: gateway` are reserved and rejected. Phase 1
  supports HTTPS checkout only.

`sand network explain --config sand.yml` prints each runner's compiled policy:
the backend, the tart arguments, every allowed destination, the steered names
and the policy hash that audit lines carry.

## Presets

The `github` preset is always included. Its exact names are:

- github.com, www.github.com, gist.github.com, api.github.com,
  codeload.github.com, uploads.github.com, lfs.github.com
- raw.githubusercontent.com, objects.githubusercontent.com,
  objects-origin.githubusercontent.com, release-assets.githubusercontent.com,
  github-releases.githubusercontent.com, github-registry-files.githubusercontent.com,
  github-cloud.githubusercontent.com, pkg-containers.githubusercontent.com
- github-cloud.s3.amazonaws.com (LFS)
- ghcr.io

Its wildcards are:

- `*.actions.githubusercontent.com`: pipelines, results, token and other
  Actions services
- `*.pkg.github.com`: GitHub Packages

Actions artifacts, logs and cache use GitHub's results storage accounts,
listed exactly as `productionresultssa0` to `productionresultssa19`
`.blob.core.windows.net`. A `productionresultssa*` glob is deliberately not
used: Azure storage account names are first-come, so a glob would also admit
an attacker-registered account such as `productionresultssaxyz12`.

Optional presets:

| preset | hosts |
| --- | --- |
| `github-attestations` | fulcio.githubapp.com, timestamp.githubapp.com, tuf-repo.github.com |
| `npm` | registry.npmjs.org |
| `pypi` | pypi.org, files.pythonhosted.org |
| `homebrew` | formulae.brew.sh, ghcr.io |
| `rubygems` | rubygems.org, index.rubygems.org |
| `cocoapods` | cdn.cocoapods.org |
| `swiftpm` | none extra (packages come from github.com) |

Preset lists live in `Sources/sand/Network/EgressPolicy.swift` together with
`EgressPreset.policyVersion`. The version is part of the policy hash.

## VPNs, BlastShield and split DNS

The proxy resolves names with `getaddrinfo`, so it sees exactly what every
other host process sees. On a Mac running BlastShield, split DNS steers
`github.com`, `www`, `gist`, `api`, `codeload` and `lfs` to private fronts in
172.16/12 on the VPN interface. Traffic through those fronts leaves via the
BlastShield egress IP, which satisfies the GitHub organisation's IP allow list.
On a Mac without a VPN, the same names resolve to public addresses. The config
is identical either way.

The destination guard normally refuses every private address. It makes one
exception:

- the name is one of the six **steered names** above; and
- the answer is RFC1918; and
- the answer is not the host's own address, not on a directly attached
  subnet, and not inside the VM's subnet; and
- the host routes the answer out the same interface the steered names used
  when the VM's proxy started (for example the BlastShield utun). Sand learns
  that interface per VM and logs it as `network.steering.learned`. A resolver
  that answers `github.com` with a tailnet or other VPN address is refused
  with `steered-route-mismatch`. If BlastShield reconnects on a different
  interface, steered connections fail closed until the next VM.

Point-to-point (utun) interfaces count only their own address as on-link,
whatever netmask the VPN client sets.

When all of these hold, the connection is allowed and audited with
`steered=true`. Any other allowlisted name that resolves to a private address
is denied. This is how DNS rebinding of user domains to corporate services is
blocked. The guest never gets the VPN route itself.

> **Reviewed exception (needs security sign-off).** The enterprise plan (§9)
> says the VM data plane must not reuse the host's BlastShield identity.
> GitHub's IP allow list forces GitHub traffic to leave through BlastShield.
> This design limits that reuse:
>
> - to exactly the six steered GitHub names, on TCP 443;
> - mediated by the proxy (SNI must match);
> - audit-logged per connection.
>
> In testing, the 172.16 fronts behaved as one-to-one GitHub forwarders: an SNI
> test against them reached only GitHub backends. The long-term fix is a
> registration broker or a dedicated egress identity for VM traffic.

Other interactions:

- **Netskope (or another TLS-inspecting client).** Proxy connections are host
  process flows, so the endpoint agent may intercept them. See
  [TLS-inspecting endpoint agents](#tls-inspecting-endpoint-agents-netskope-zscaler).
- **Disconnecting the VPN mid-run.** New connections resolve to public
  addresses and go out directly. A GitHub IP allow list then answers 403
  inside the job. That is a visible failure, not a leak.
- **VM subnet collisions.** The backend picks the VM's subnet (hostOnly:
  vmnet's host-only range, typically 192.168.128.0/24). If it overlaps a
  host route, such as the VPN's 172.16/16, it would shadow the steered fronts.
  Sand recreates the VM (up to three times) and fails if it keeps colliding.
  The watchdog also ends a job if a later route change creates an overlap.

## TLS-inspecting endpoint agents (Netskope, Zscaler)

The proxy's upstream connections are host-process flows, so an endpoint agent
may re-sign them with its own CA. The host trusts that CA (it is in the System
keychain with admin trust); the guest does not, so jobs fail TLS for exactly
the intercepted hosts. On the verification host, Netskope intercepted
`*.actions.githubusercontent.com`, `objects`, `raw`, `release-assets` and
`pkg-containers.githubusercontent.com`, but not `github.com` or `ghcr.io`.
The chain had two certificates: a self-signed root and an intermediate.

**Detection (preflight P10, generic).** For a representative set of
allowlisted hosts (the GitHub preset's concrete names, including
`pipelines`/`results-receiver.actions.githubusercontent.com` and
`productionresultssa0.blob.core.windows.net`, plus up to eight exact
user/preset names), the host completes a TLS handshake (no request is sent)
and builds the chain with its own trust settings. A chain whose anchor is not
an Apple-shipped root (not in
`/System/Library/Keychains/SystemRootCertificates.keychain`) was re-signed
locally. Nothing about any vendor or certificate is hardcoded. Hosts the host
cannot reach are a warning, not evidence of interception. The probe bypasses
any system proxy or PAC file (`preferNoProxies`), like the egress proxy's
upstream sockets.

**`tlsInspection: fail` (default).** Interception fails preflight and
`sand run` exits 78 before any clone. The message lists the intercepted hosts
and the CA subject and SHA-256, and gives the two fixes: ask IT to exempt those
hosts from inspection, or opt in below.

**`tlsInspection: trustHostCA` (opt-in).**

- Sand exports only the intercepting CA certificate(s) seen in those chains
  (every non-leaf certificate that is not an Apple root), and only the public
  certificate, with `security find-certificate -a -Z -p
  /Library/Keychains/System.keychain`. The PEM's SHA-256 must match the
  observed certificate.
- It refuses (P10 fails) when a CA is not in the System keychain, when the
  chain is a single self-signed leaf, or when the host holds a private key for
  the CA (`security find-identity`): a CA the host could sign with is never
  trusted in a guest.
- The fingerprints and subjects go to the audit log at startup
  (`network.tls.inspection`) and per VM (`network.tls.inspection.trusted`).
- In the guest, after the proxy settings and before preRun or registration:
  - the CA files and `~/.sand/ca-bundle.pem` = the guest's default bundle
    (`/etc/ssl/cert.pem` or the Linux equivalents) plus the CA. The default
    bundle is never replaced;
  - macOS: the root with `sudo -n security add-trusted-cert -d -r trustRoot
    -p ssl -p basic -k /Library/Keychains/System.keychain` (trusted for TLS
    server authentication only, never code signing or S/MIME), intermediates with
    `security add-certificates` (URLSession tools, Xcode, SwiftPM). Linux:
    `update-ca-certificates`. This step is best effort and logs WARN lines;
  - `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `GIT_SSL_CAINFO`
    point at the combined bundle and `NODE_EXTRA_CA_CERTS` at the CA file. They
    go wherever the proxy variables go: the runner's `.env`, the `config.sh`
    environment and the login shell profiles.

  If the combined bundle cannot be built, the VM is destroyed before
  registration.
- Trade-off: the inspection vendor can read the job's TLS to the intercepted
  hosts, as it already can for the host's own traffic. `sand validate` warns.
- Limit: the private-key check only sees keychain identities. A developer
  tool's CA (mitmproxy, Charles) whose key lives in a file, and which an admin
  added to the System keychain, would pass it. Check the subjects and
  fingerprints in `network.tls.inspection` before opting in.

## What happens at runtime

1. `sand run` compiles each runner's policy (resolving `backend: auto`) and
   logs `network.policy.compiled` with the hash and backend. It then runs the
   full preflight once per distinct policy. The checks are:
   - P1: tart supports `--net-host` (hostOnly) or `--net-softnet-allow` (softnet);
   - P0 (auto only): why `auto` chose hostOnly, a warning when a softnet was
     present but rejected;
   - P12 (softnet only): the softnet binary and every directory up to `/` are
     root-owned and not group/world-writable (a root-owned sticky directory
     such as `/private/tmp` is tolerated); symlinks are resolved first and
     judged by their target. Nothing (not `--help`, not `sudo -n`) is run
     from a path that fails;
   - P2, P3 (softnet only): softnet supports stateful rules (`proto`,
     `@host`) and is privileged (setuid root, or `sudo -n <resolved path>`);
   - P13 (softnet only): the binary matches `softnetSHA256` and the
     installer's `softnet.sha256` manifest when present (a managed install
     without a manifest is a warning);
   - P4: the host resolves GitHub and completes a TLS handshake to
     `api.github.com` (no API call, because of rate limits);
   - P5: an in-process proxy self-test (`github.com` → 200, `example.com` →
     403, `172.16.0.1:53` → 403);
   - P6, P7: ssh tools are present and there is enough disk space (statfs
     `f_bavail`: space available now, not purgeable space);
   - P9: `allowedCIDRs` clear of host subnets;
   - P10: TLS interception (above);
   - P11 (hostOnly only): host IP forwarding off, or `ipForwarding: accept`.

   Any failure exits with code 78 before a clone, and every failed check's
   fix is printed. With more than one hostOnly runner, `sand run` warns that
   peer-VM isolation is not guaranteed (`network.peer.isolation`). Each later
   boot re-checks resolution, softnet path, privilege and SHA-256 (softnet:
   P12, P3, P13) and IP forwarding (hostOnly); a failure there counts as an
   enforcement failure.
2. Clone, then `tart run` with the backend's arguments. Tart runs with
   `SENTRY_DSN` and `CIRRUS_SENTRY_TAGS` removed from its environment and,
   under softnet, with the checked softnet's directory first on `PATH`.
3. Wait for an IP that answers SSH. A stale softnet lease is re-resolved.
   **If tart exits first** (for example `Softnet process terminated
   prematurely`, or a `--net-host`/vmnet failure), the failure is classified
   (`softnet-terminated`, `softnet-privilege`, `softnet-failed`,
   `host-network-failed`, `tart-exited-early`) and audited as
   `network.enforcement.failed`. Under an isolated policy, tart still running
   but never getting an IP (`reason=no-ip`) counts the same way.
4. Check the VM subnet against host routes.
5. Start the proxy and the tunnel. Wait for guest `127.0.0.1:3128`.
6. hostOnly: re-read IP forwarding (`network.host.forwarding`), then report
   reachable host listeners (`network.host.listeners`); `hostListeners: deny`
   refuses the VM here.
7. Verify the guest, before preRun or registration. Each negative probe runs
   with the proxy variables unset and must fail. Under hostOnly the guest has
   no default route, so "the gateway" is the host's bridge address.
   - `basic`:
     - 1.1.1.1:443;
     - the resolved GitHub front on :443;
     - the gateway on :53 (always closed), :5000 and :22 (softnet: must be
       closed; hostOnly: host services, reported, and failing only under
       `hostListeners: deny` for an unaccepted port);
     - hostOnly: each host TCP listener found in step 6 (up to 8), reported;
     - DNS via the gateway and via 8.8.8.8;
     - IPv6;
     - hostOnly, adversarial (`R*`): the guest adds a host route via the
       host's bridge address (`sudo -n route add -host TARGET BRIDGE`, never
       the default route; removed after each probe and on exit) and probes
       1.1.1.1:443, the GitHub front, DNS via 8.8.8.8, DNS and TCP 53 to
       100.100.100.100, each IPv4 host DNS server from `scutil --dns`
       (`RD*`), the first address of each VPN route (`RT*`) and IPv6 via the
       bridge link-local address. Each must stay closed (OPEN fails unless
       `ipForwarding: accept`, where it is reported). Without passwordless
       sudo in the guest these are inconclusive, since the job cannot add
       routes either.
   - `strict` adds:
     - the host LAN gateway and the host's LAN address;
     - 100.100.100.100;
     - the 172.16.0.1 resolver;
     - 169.254.169.254;
     - DNS via 1.1.1.1;
     - the first address of each VPN route;
     - a proxied `example.com`, which must get a CONNECT 403.

   `api.github.com/zen` through the proxy must answer. An open, failing or
   missing probe destroys the VM and nothing is registered.
8. `tlsInspection: trustHostCA`: install the CA (above).
9. Provision. The GitHub provisioner writes `~/actions-runner/.env` before
   `config.sh`, runs `config.sh` with the proxy variables and
   `--disableupdate`, then runs `run.sh`.
10. The watchdog polls every 2 s. These events end the job: tart exits, the
    softnet child disappears (softnet), the tunnel exits, the proxy listener
    fails, a route overlap appears, or host IP forwarding turns on (hostOnly
    with `ipForwarding: deny`). The VM is stopped and deleted, the
    runner is deregistered (`network.enforcement.lost`), and the next VM is
    subject to the restart backoff. Expected teardown is not reported.

**Bounded failures.** Every network enforcement error goes through one
counter: the per-VM preflight, tart exiting (or never getting an IP) before
the VM is reachable, a repeated subnet overlap, the tunnel, verification, host
listeners, IP forwarding, the CA install, and enforcement lost during a job
(`stage=job reason=lost-<component>`). Each one is audited as
`network.enforcement.failed` with `stage`, `reason`, `attempt`, `max` and
`final`, and the VM is recreated with the same policy after the restart
backoff. Only a job that runs to the end with enforcement intact resets the
count, so a component that dies during every job still reaches the limit.
After `maxEnforcementFailures` (default 3) in a row, `sand run` stops every
slot's VM and exits 78, like a failed preflight, instead of re-cloning forever.

With `stopAfter` set, a failure before the job starts is retried the same way
and does not use up an iteration; at the limit `sand run` exits 78. Losing
enforcement during a job cannot be retried (the job was interrupted), so it
ends the run with 78 at once (`final=true`). `sand run` never exits 0 after an
enforcement failure it did not recover from.

## Reading audit lines

Network events go to the normal log. With `--log-file X.log` they are also
written as JSON lines to `X.network.jsonl`.

```
network.connect bytes_down=548251 bytes_up=583 decision=allow duration=0.3 host=github.com ip=172.16.7.60 port=443 steered=true
network.connect decision=deny host=example.com port=443 reason=not-allowlisted
network.connect decision=deny host=registry.npmjs.org port=443 reason="blocked-address(172.16.7.60=private)"
network.policy.compiled backend=hostOnly domains=39 hash=... profile=profile:github runner=r1 tart_args=--net-host
network.host.listeners count=2 listeners="tcp/5000 (ControlCe:1311),tcp/7000 (ControlCe:1311)" method=lsof+sweep policy=warn ...
network.enforcement.failed attempt=2 backend=softnet final=true max=2 reason=softnet-terminated stage=before-ip ...
```

Values with spaces, `=` or quotes are double-quoted (with `"` and `\` escaped)
in the text log; the JSON lines carry the raw value.

Deny reasons:

| reason | meaning |
| --- | --- |
| `not-allowlisted` | The name and port are not in the policy. Add a preset or an `allowedDomains` entry if the job really needs it. |
| `ip-literal` | The client connected by IP address. Allowlist the name, or (after review) add an `allowedCIDRs` entry. |
| `blocked-address(...)` | The name resolved only to private, host, on-link or reserved addresses. This is rebinding protection. A covered IP literal that hits the host, its LAN, loopback or link-local is also refused here. |
| `steered-route-mismatch` | A steered GitHub name resolved to a private address the host does not route out the learned VPN interface. |
| `sni-mismatch`, `no-sni`, `not-tls` | The tunnel did not start with a TLS ClientHello for the CONNECT host. Plain HTTP over CONNECT and domain fronting are refused. |
| `method-not-allowed`, `bad-request`, `header-too-large` | The request was not a well-formed `CONNECT host:port`. The host must be an IP literal or a strict hostname (letters, digits, `-`, dots between non-empty labels), so NUL bytes, `%`, `_` and control characters are refused here. |
| `tunnel-limit` | The VM already has 256 open tunnels. |

The guest sees only the bare reason code, in an `X-Sand-Deny` response header
(for example `blocked-address`). Resolved addresses and resolver or connect
errors stay in the host log, so guest code cannot use deny responses to read
DNS answers back. After 200 deny lines per VM, only one in 100 is logged (with
a `suppressed=` count), and at most 256 distinct denied hosts are tracked.

`network.session.summary` at teardown lists allowed and denied counts, bytes,
and the most-denied hosts. Audit fields never contain tokens or request paths
(CONNECT has none).

## Troubleshooting

- **"Network preflight failed".** Run `sand network preflight --config sand.yml`
  for the full report. P3 (softnet privilege), P12 (softnet path) and P13
  (softnet pin) only appear for the softnet backend. P12 means the softnet
  is not root-owned all the way up: install it with
  `deploy/jamf/install-managed-softnet.sh`, never by making the Homebrew copy
  setuid. P13 means the binary changed: reinstall it, or review it and update
  `softnetSHA256`. P10 (TLS inspection):
  ask IT for a bypass of the listed hosts or set `tlsInspection: trustHostCA`.
  P11 (host IP forwarding): check `sysctl net.inet.ip.forwarding
  net.inet6.ip6.forwarding`. VPN clients, Internet Sharing and container
  tools turn it on. If nothing needs it, run `sudo sysctl -w
  net.inet.ip.forwarding=0 net.inet6.ip6.forwarding=0` yourself (it may come
  back on reconnect or reboot). Otherwise use `backend: softnet`, or set
  `ipForwarding: accept` after reviewing what the host forwards to.
- **`sand run` exits 78 after a few boots.** `network.enforcement.failed`
  lines name the stage and reason (for example `softnet-terminated` when
  softnet loses its privilege). Fix the cause; Sand will not keep re-cloning.
- **Which host services can a hostOnly VM reach?** Boot a VM, then
  `sand network listeners --vm-ip "$(tart ip VM)"` prints exactly what the
  post-boot check reports. Rebind services to `127.0.0.1`, turn off AirPlay
  Receiver, or use `hostListeners: deny` with `acceptedHostListeners`.
- **A tool ignores the proxy.** Most tools honour `https_proxy`: git, curl,
  `@actions/*`, npm, pip, and brew (through curl). URLSession tools
  (xcodebuild, SwiftPM) use the macOS system proxy that Sand sets. For
  anything else, configure its own proxy setting to `http://127.0.0.1:3128`.
  Guest DNS points at loopback on purpose, so tools that resolve before
  proxying fail fast.
- **A job needs another host.** Find its `network.connect decision=deny ...
  reason=not-allowlisted` line and add a preset or an `allowedDomains` entry.
- **Plain HTTP and `git://` do not work.** Only TLS through CONNECT is
  supported. Use `https://` remotes. SSH checkout is not supported in Phase 1.
- **Reproducing the guest check by hand.** `sand network probe-script --verify strict`
  prints the exact probe script, and `--guest-setup` prints the guest proxy setup.
- **Debugging the proxy alone.** Run
  `sand network proxy --config sand.yml --listen 127.0.0.1:18080`, then
  `curl -x http://127.0.0.1:18080 https://github.com`.

## Jamf / managed deployment

Goal: on a managed Mac, secure softnet isolation with zero user steps; on an
unmanaged Mac, a safe fallback (hostOnly with the forwarding check) or a
fail-closed exit 78, never an insecure run. Everything is in
[`deploy/jamf/`](../deploy/jamf/README.md):

| File | Runs as | Does |
| --- | --- | --- |
| `install-managed-softnet.sh` | root (Jamf policy) | downloads the pinned softnet release, verifies the tarball and binary SHA-256, installs `/usr/local/libexec/sand/softnet` root:GROUP 4550 (runner group, default `staff`; or 0555 plus `/etc/sudoers.d/sand-softnet` for `%GROUP` with `--sudoers`), re-checks the installed file against the pin, writes `softnet.sha256`; optional `--enforce-no-forwarding` LaunchDaemon |
| `uninstall-managed-softnet.sh` | root | removes all of the above |
| `sand-readiness-ea.sh` | root (extension attribute) | reports `ready` / `ready-hostonly` / `not-ready` without executing softnet or tart |

Why `/usr/local/libexec/sand`: `/usr/local` and `/usr/local/libexec` ship
root:wheel 0755 on macOS (Homebrew on Apple Silicon lives in
`/opt/homebrew`; Intel Homebrew takes over several `/usr/local`
subdirectories, so on an Intel Mac check `ls -ld /usr/local/libexec`: if it is
not root-owned the installer refuses, and you pass `--install-dir` plus
`vm.run.network.softnetPath`), it is outside SIP, it is on nobody's
`PATH` (other tools never pick up the setuid binary), and `libexec` is the
conventional place for helper binaries. The installer refuses to install
below any path component that is a symlink, not root-owned, or
group/world-writable, and Sand checks the same thing (P12) before every VM.

What a fleet gets with no Sand config changes:

- Default `backend: auto` picks the managed softnet (P12, P2, P3, P13 all
  `ok`), so VMs get host-service and peer-VM isolation, and host IP
  forwarding (Tailscale, VPN clients) no longer matters (P11 is hostOnly-only).
- If the managed install is missing, `auto` uses hostOnly. If it is present
  but broken (not privileged, not executable by the runner account, directory
  loosened, binary changed), `auto` keeps softnet and fails closed: a fleet
  Mac is never quietly downgraded. A rejected PATH softnet (for example a stray
  setuid Homebrew copy) is a loud warning plus `network.backend.fallback`.
  Configs that must never run without softnet, even where it is not installed,
  set `backend: softnet` (see `fixtures/network_managed_softnet.yml`).
- The account that runs sand must be in the installer's runner group (`$8`,
  default `staff`); members of that group can run softnet as root with any
  arguments (including `--user root`, which keeps it from dropping
  privileges), so use a dedicated group where local accounts are untrusted.
- A modified managed binary fails P13 and exits 78 under either backend.
- Upgrading softnet: bump the pinned version and digests in the installer
  (or pass Jamf `$6`/`$7`), re-run the policy. Pinned `softnetSHA256` values
  in Sand configs must be updated in the same change.

Choose `--enforce-no-forwarding` only for dedicated runner Macs: it keeps
`net.inet.ip.forwarding` and `net.inet6.ip6.forwarding` at 0 (boot plus every
60 s), which breaks Internet Sharing, Tailscale subnet routing and exit
nodes, and VPN or VM tools that route through the Mac. It matters only for
hosts that fall back to hostOnly.

## Simulate a managed Mac locally

Run these once, in your own terminal, from a sand checkout. Sand itself never
runs `sudo`.

```sh
# 0. Undo any earlier Homebrew setuid/sudoers setup (P12 refuses it anyway).
ls -l "$(realpath "$(which softnet)")"   # must not be root-owned or show 's'; else: brew reinstall softnet
ls /etc/sudoers.d/                        # remove any NOPASSWD rule for /opt/homebrew/.../softnet

# 1. What the Jamf policy does: pinned softnet 0.26.0 release, tarball and binary
#    SHA-256 verified, installed setuid root (root:staff 4550) with a manifest.
#    Plain sudo, not sudo -E.
sudo deploy/jamf/install-managed-softnet.sh
#    Offline alternative from the Homebrew keg (must hash to the pinned 0.26.0 binary):
#    sudo deploy/jamf/install-managed-softnet.sh --from /opt/homebrew/Cellar/softnet/0.26.0/bin/softnet
#    Without root you can still check the download: deploy/jamf/install-managed-softnet.sh --verify-only

# 2. What Jamf's extension attribute would report.
sudo deploy/jamf/sand-readiness-ea.sh
```

Verify as yourself, without `sudo`:

```sh
ls -l /usr/local/libexec/sand
# -r-sr-x---  root  staff  softnet
# -r--r--r--  root  wheel  softnet.sha256
swift run sand network explain --config fixtures/network_github_default.yml | head -12
# "backend: auto resolved to softnet on this host"; "enforcement backend: softnet";
# "softnet binary: /usr/local/libexec/sand/softnet (managed) ..."
swift run sand network preflight --config fixtures/network_github_default.yml
# P12 softnet path ok, P2 softnet ok, P3 softnet privilege ok (setuid root),
# P13 softnet pin ok (matches /usr/local/libexec/sand/softnet.sha256); no P11
# Behind a TLS-inspecting proxy (Netskope) P10 still fails for this fixture:
# softnet does not change that. Add vm.run.network.tlsInspection: trustHostCA
# or get the GitHub hosts exempted; the live boot below uses profile: offline,
# which has no egress and so no P10.
```

Optional live boot (deletes the clone afterwards):

```sh
cat > /tmp/sand-managed.yml <<'YAML'
runners:
  - name: sand-nettest-managed
    stopAfter: 1
    vm:
      source: { type: oci, image: ghcr.io/cirruslabs/macos-runner:golden-gate }
      run:
        network: { profile: offline, verify: strict }
    provisioner:
      type: script
      config: { run: echo managed-softnet-ok }
YAML
swift run sand run --config /tmp/sand-managed.yml
# network.policy.compiled backend=softnet softnet=/usr/local/libexec/sand/softnet softnet_source=managed
# network.guest.verified ... backend=softnet; then the VM is stopped and deleted
tart list | grep sand-nettest || echo "no leftover clones"
```

To go back to an unmanaged Mac: `sudo deploy/jamf/uninstall-managed-softnet.sh`.

## Migration

- To keep shared NAT, add `network: { mode: shared }`. Do this for runners
  with host `mounts`, which isolated VMs reject.
- A legacy `mode: restricted` config keeps working and now allows host SSH.
- Profiles now default to `backend: auto`: softnet where a managed softnet
  is installed, hostOnly (no root) elsewhere. Add `backend: hostOnly` to keep
  the previous default regardless of the host, or `backend: softnet`
  (required for `allowedCIDRs`) to require softnet. `auto` is pinned at
  startup: a VM never silently changes backend in the middle of a run.
- A setuid or sudoers-allowed Homebrew softnet is no longer accepted (P12).
  Run `brew reinstall softnet` to drop the setuid bit, remove any sudoers
  rule for it, and install the managed copy instead.
- Hosts with IP forwarding on (common with VPN clients) now fail preflight P11
  under hostOnly. Turn forwarding off, use `backend: softnet`, or set
  `ipForwarding: accept`.

## Residual risks

- **Exfiltration through allowed platforms.** A job can upload to GitHub
  itself or to shared CDNs and blob storage (Fastly, Azure Front Door, Azure
  blob storage). SNI equality and byte counts in the audit log reduce this.
  Secrets isolation (plan §8 and §9) is still required.
- **Domain fronting on shared front ends.** The proxy checks SNI, not the
  encrypted HTTP `Host` header. On S3, Azure blob storage and Fastly-fronted
  hosts, a client can send an allowed SNI and route to another tenant by
  `Host`. Only a TLS-terminating proxy could close this.
- **Upstream connect before SNI check.** The proxy opens the upstream TCP
  connection before it reads the ClientHello. The name is already allowlisted
  and resolved through the guard at that point, but a refused tunnel still
  costs one host-originated SYN.
- **ECH.** With Encrypted Client Hello, the proxy sees only the outer SNI.
  Mismatches are refused, but the inner name cannot be checked.
- **Shared BlastShield identity.** The guest shares the host's BlastShield
  identity for the six steered GitHub names. See the reviewed exception above.
- **hostOnly: host services and peer VMs.** Host services bound to any
  non-loopback host address are reachable from a guest that routes via the
  bridge, and peer isolation depends on tart placing VMs on separate bridges.
  Both are reported (`network.host.listeners`, `network.peer.isolation`);
  `hostListeners: deny` refuses the VM, and `backend: softnet` removes both. A
  host service that is itself a proxy or resolver would be an egress path;
  DNS on the bridge and to each host DNS server is probed as egress, other
  proxies are only reported. In `lsof+sweep` mode a root listener on an
  uncommon port can be missed.
- **hostOnly relies on vmnet host mode and host IP forwarding being off.**
  There is no rule set to inspect: the guarantee is that vmnet's host-only
  network has no NAT and that the host does not forward guest packets. P11,
  the per-VM check and the watchdog (every 2 s) enforce forwarding off; the
  adversarial verifier re-checks routed reach on every boot. Between watchdog
  polls a guest could send a few packets after forwarding turns on. Under
  `ipForwarding: accept` this exposure is accepted: anything the host forwards
  to with a return path (seen live: the tailnet resolver) is reachable, and
  one-way UDP exfiltration works everywhere. A pf/NAT rule that bridges the
  vmnet bridge without enabling forwarding is not detected.
- **trustHostCA.** The inspection vendor can read job TLS to intercepted hosts.
- **No softnet policy attestation yet.** The watchdog checks that processes are
  alive; it cannot read back the rules softnet enforces. softnet 0.26 answers
  `softnet.policy.get` on its JSON-RPC control channel, and tart 2.42 passes
  one through with `--net-softnet-control-fd=N`, but N must be a connected
  Unix stream socket inherited by tart. Sand starts tart through Foundation
  `Process`, which closes every descriptor above 2 in the child, so this
  needs a `posix_spawn` launcher with explicit file actions plus a small
  JSON-RPC client. Follow-up: call `softnet.policy.get` after boot and compare
  it with the compiled `SoftnetRuleSet` before registration. Until then the
  binary itself is pinned (P12, P13) and the guest egress verifier checks the
  behaviour on every boot.
- **Managed softnet trust.** P12 trusts root and the binary's directory
  chain, and P13 trusts the manifest written by root. Anyone with root (or an
  admin who can `sudo`) can replace both; that is outside Sand's threat model.
  The manifest catches drift and partial upgrades; `softnetSHA256` in the
  config is the pin that root on the host cannot silently change.
- **Privileged softnet arguments.** In both install modes, members of the
  runner group can run softnet as root with any arguments. softnet 0.26 takes
  `--user`/`--group` from its caller, so `--user root` keeps it root for its
  whole life with a vmnet interface the caller feeds (L2 frames onto the VM
  bridge, reaching other sand VMs and the host's bridge address) and
  `--expose` forwards. The installer limits this to one group (default
  `staff`, so not service accounts); use a dedicated runner group on Macs with
  untrusted local accounts. Upstream fix: ignore or refuse `--user`/`--group`
  naming uid 0 when the real uid is not 0.
- **IPv4-only rules.** Softnet rules are IPv4 only. IPv6 is dropped entirely
  rather than filtered. hostOnly gives the guest no IPv6 route by default; a
  guest route via the host's link-local address is probed (R6), and IPv6
  forwarding is covered by P11.
- **sshpass.** The `sshpass` password is still visible in the host process
  list (pre-existing).
- **Host SSH config.** Every ssh, scp and tunnel session runs with
  `-F /dev/null`, `ForwardAgent=no`, `ForwardX11=no`, `ControlMaster=no` and
  `PermitLocalCommand=no`, and without `SSH_AUTH_SOCK`. Exec and scp sessions
  also set `ClearAllForwardings=yes`. A `Host *` entry in `~/.ssh/config` can
  therefore no longer hand the guest the user's agent or extra forwards.
- **Point-in-time host facts.** Host addresses and routes are read when each
  VM's proxy starts. An IPv6 temporary address or a VPN that appears later is
  not in the guard's host list until the next VM.

## Enterprise plan, Phase 1 status

This branch delivers these Phase 1 items:

- A root-free enforcement backend (tart `--net-host`), and softnet for
  host-service and peer-VM isolation, chosen by the default `backend: auto`
  when a managed softnet is installed where only root can replace it.
- Tart (and, for softnet, softnet) preflight before VM boot, with no
  shared-network fallback.
- Generic detection of TLS-inspecting endpoint agents, failing closed or,
  opt-in, trusting only the detected CA's public certificate in the guest.
- Host SSH provisioning that is separate from guest egress (the `in proto tcp
  @host port 22` rule versus the proxy tunnel).
- Allowed GitHub traffic through an approved proxy, and denied
  host/LAN/VPN/corporate/internet traffic, including IPv6, DNS and UDP. The
  in-guest verifier checks both on every boot.
- Fail-closed behaviour when softnet, the proxy or the tunnel crashes, on
  route changes and when host IP forwarding turns on, with one bounded retry
  count for every enforcement failure and exit 78 (also under `stopAfter`).

Still open:

- signed and retained evidence (packet traces);
- the live failure-injection runs from the test plan;
- security sign-off on the BlastShield exception above.

## Verified on this host: hostOnly backend (2026-11-27)

Same host as below (tart 2.42.0, BlastShield, Netskope, no root, no
passwordless sudo). Disposable clones named `sand-nettest-*`, all deleted.

- **Raw `tart run --no-graphics --net-host`, no root.** The guest got
  192.168.128.3 on host `bridge100` 192.168.128.1, with no default route. From
  the guest these were CLOSED: 1.1.1.1:443, 140.82.112.3:443, the BlastShield
  GitHub front 172.16.7.60:443, a corporate 172.16.7.64:443, the LAN gateway
  10.0.0.1:80, 100.100.100.100:53 and the host's LAN address 10.0.0.152:5000.
  DNS to 8.8.8.8 and to the bridge timed out, and IPv6 failed. Host-to-guest
  SSH worked. Host services bound to all interfaces were OPEN on the bridge
  address (ControlCenter `:5000`, `:7000`). That result holds only for a guest
  that leaves its routes alone; see "guest root and host IP forwarding" below.
- **`sand run`, default policy.** Preflight P10 detected Netskope generically:
  the chains for `*.actions.githubusercontent.com`, `objects`, `raw`,
  `release-assets` and `pkg-containers.githubusercontent.com` ended in the
  admin-trusted `certadmin` root via a `<tenant>.goskope.com` intermediate, neither of
  them an Apple root. `sand run` exited 78 before cloning, listing the hosts
  and both fingerprints.
- **`sand run` with `verify: strict` and `tlsInspection: trustHostCA`.**
  - `network.host.listeners` reported 14 listeners using `lsof+sweep`: netstat
    shows no Internet sockets to a child process on this macOS release.
  - The strict guest check passed (23 probes) and recorded
    `host_services_reachable=tcp/5000,tcp/7000,tcp/57765`.
  - `sudo -n security add-trusted-cert` over SSH succeeded (`keychain=ok`).
  - In the job, curl to `objects.githubusercontent.com` and
    `pipelines.actions.githubusercontent.com` (both intercepted) completed TLS,
    with `SSL_CERT_FILE=/Users/admin/.sand/ca-bundle.pem`.
- **Guest root and host IP forwarding (review finding, confirmed).** The
  host has `net.inet.ip.forwarding=1` and `net.inet6.ip6.forwarding=1`, and
  passwordless sudo is not available to turn them off. In a guest on
  `bridge100`, `sudo route -n add -host 100.100.100.100 192.168.128.1` made
  `dig @100.100.100.100 example.com` resolve (tailnet MagicDNS answered through
  the host); 1.1.1.1:443, GitHub and corporate fronts stayed CLOSED (no NAT,
  no return route). The review also reached the host's LAN address
  (`:5000`, `:7000`) once the guest routed via the bridge. With the fixes:
  - `sand network preflight` and `sand run` on the zero-config file fail
    P11 (and P10) and exit 78 before any clone, printing both fixes.
  - `sand run` with `ipForwarding: accept` and `tlsInspection: trustHostCA`
    (`stopAfter: 1`): P11 warned, `network.host.forwarding result=accepted`
    was audited, and the verifier ran 22 probes, 11 of them routed via the
    host. It recorded
    `routed_reachable` for R4 (DNS to 100.100.100.100) and R5
    (100.100.100.100:53/tcp); R1-R3, the host DNS servers (RD*) and the VPN
    route targets (RT*) stayed CLOSED. The guest had no leftover gateway
    routes afterwards. Under the default `deny` these OPEN results fail
    verification.
  - `network.host.listeners` now inspected 10 host addresses (bridge, LAN,
    VPN/utun) instead of the bridge only.
- **Peer VMs.** Two raw `--net-host` VMs got separate bridges
  (192.168.128.0/24 on `bridge100`, 192.168.129.0/24 on `bridge101`). From the
  first, the second's :22 and its bridge's host address were CLOSED, also with
  a host route via the first bridge (one-way: no return route). This is
  observed tart 2.42 behaviour, not a guarantee.
- **Inspection-CA scope.** With the fix, `security dump-trust-settings -d` in
  the guest shows only the `certadmin` root, trusted for the `SSL` and `Apple
  X509 Basic` policies only. The intermediate is added untrusted. `curl
  https://github.com` through the proxy returned 200, and the job saw
  `NODE_USE_ENV_PROXY=1`.
- **Enforcement lost mid-job with `stopAfter: 1`.** Killing the tunnel's
  `ssh -N -R 127.0.0.1:3128:...` during the job stopped and deleted the VM,
  audited `network.enforcement.lost component=tunnel` and
  `network.enforcement.failed stage=job reason=lost-tunnel final=true`, and
  `sand run` exited 78 (it exited 0 before the fix).
- **Runtime backend failure.** `backend: softnet` with a non-escalating test
  shim in place of sudo let preflight pass, then softnet died
  (`RuntimeFailed(why: "Softnet process terminated prematurely")`). Sand
  logged `network.enforcement.failed reason=softnet-terminated stage=before-ip`
  twice (`maxEnforcementFailures: 2`), deleted the VM each time, never used
  shared NAT, and exited 78.

## Verified on this host: softnet backend (2026-11-27)

The test host was an Apple silicon Mac running tart 2.42.0 and softnet 0.26.0,
with BlastShield signed in, a Netskope client and a personal tailnet. Softnet
was **not** yet setuid on this host and passwordless sudo was not available.
Tests used disposable `tart clone`s, all deleted afterwards.

**BlastShield split DNS.** Through the system resolver, `github.com` and
`codeload.github.com` resolved to private fronts in 172.16/12, routed out the
BlastShield utun. `api.github.com`, `lfs.github.com` and other names flipped
between a private front and public 140.82.x within one session. `dig`, which
bypasses the system resolver, always returned public addresses. Corporate
domains (redacted) resolve through BlastShield's own resolvers. Consequences:

- The proxy follows the host resolver for each connection and logs
  `steered=true|false`. When a name resolves publicly, that connection does
  not leave through BlastShield. A GitHub IP allow list may then refuse API
  calls from the job. That is a visible failure, not a leak.
- The preflight P4 "steered" result is a snapshot, not a guarantee.

**What works:**

| Check | Result |
| --- | --- |
| Policy compiles from zero config (`sand network explain`) | deny-all plus host SSH 22, GitHub preset, stable hash |
| Preflight on a host without the softnet privilege | P3 fails with the one-time fix; `sand run` exits 78 before any clone |
| Softnet dies after preflight passed | tart exits, sand deletes the VM, and every retry keeps the deny-all arguments (never shared NAT) |
| Proxy plus `ssh -R` tunnel from a real guest | `github.com`, `codeload` (steered), `api.github.com`, `ghcr.io`, `uploads`, `lfs` and `git ls-remote` work |
| Certificates seen in the guest for steered names | public CA (TLS passes through BlastShield untouched) |
| `mode: shared` | allowed only when explicit, and `sand validate` warns |

**What is denied through the proxy:**

- names that are not allowlisted, including corporate domains (403
  `not-allowlisted`);
- suffix tricks such as `x.actions.githubusercontent.com.evil.example` (403);
- IP literals, including BlastShield fronts, the corporate resolver, the LAN
  gateway, the tailnet resolver and public IPv6 (403 `ip-literal`);
- plain `GET` proxying, including the metadata address (405);
- `github.com:22` (403);
- an SNI that differs from the CONNECT host (tunnel closed, `sni-mismatch`);
- a NUL byte or other non-hostname byte in the CONNECT host (400);
- with the proxy or the tunnel killed, the guest's next request fails at once.

**Not yet verified live:**

- Direct guest egress under softnet. With softnet unprivileged, no VM could
  boot under `--net-softnet-block=0.0.0.0/0`.
- The strict probe script under shared NAT reported OPEN for 1.1.1.1, a
  BlastShield front, host services, gateway DNS, the LAN gateway, the tailnet
  and the corporate resolver. That is exactly the reach that `mode: shared`
  gives a guest, and the verifier caught every path. Under softnet each of
  these must be CLOSED. The verifier now reports `NOTARGET`, which fails, when
  a probe has no target (for example, no default gateway in the guest).

**Open blockers and caveats on this host:**

- **Netskope intercepts proxy flows** (now detected by P10 and handled by
  `tlsInspection`, see above). The host proxy's upstream connections
  to `*.actions.githubusercontent.com` (pipelines, results-receiver),
  `objects.githubusercontent.com` and `raw.githubusercontent.com` are
  TLS-intercepted. The guest sees the inspection CA and fails TLS. Sand fails
  closed, but **Actions jobs will not work on this host** until IT adds a
  bypass for these hosts or an opt-in guest trust of the inspection CA is
  approved.
- **Runtime softnet failure** (fixed). Sand used to recreate the VM forever
  when softnet died after preflight. It now classifies the failure, audits
  `network.enforcement.failed` and exits 78 after `maxEnforcementFailures`.
- **IPv6.** Softnet rules are IPv4 only, so the guest's IPv6 is dropped. The
  proxy can still connect to public IPv6 upstreams for allowlisted names.
  NAT64, 6to4, Teredo and IPv4-compatible forms are denied.
- **DNS.** The guest has no direct DNS. Names are resolved only on the host,
  for allowlisted names, and the answers are never returned to the guest.
  A guest that ignores the proxy settings times out on DNS (about 5 s) rather
  than failing at once.
- **Throughput.** The SSH tunnel roughly halves throughput: about 18 MB/s
  through the tunnel versus about 40 MB/s host-direct.

## Live test plan (sacrificial Mac)

Stages A and B below are for the softnet backend (after
[Simulate a managed Mac locally](#simulate-a-managed-mac-locally); put the
managed softnet first on PATH for the raw tart commands, as Sand does:
`export PATH=/usr/local/libexec/sand:$PATH`). For the hostOnly backend, no
setup is needed:

```sh
tart clone ghcr.io/cirruslabs/macos-runner:golden-gate sand-nettest-ho
tart run --no-graphics --net-host sand-nettest-ho &
IP=$(tart ip sand-nettest-ho --wait 120)
sand network listeners --vm-ip "$IP"                     # what the post-boot check reports
sand network probe-script --verify strict --no-proxy --host-gateway "${IP%.*}.1" > probe.sh   # host-only has no default route
tart exec -i sand-nettest-ho bash -s < probe.sh   # all CLOSED except host services on $GW (reported)
tart stop sand-nettest-ho; tart delete sand-nettest-ho
sand network preflight --config fixtures/network_enterprise_hostonly.yml   # P1 --net-host, P10 TLS inspection
```

Softnet stages:

Run every stage yourself. Clone test VMs with `tart clone`, which uses APFS
copy-on-write, and delete them afterwards.

```sh
# Stage 0: a disposable clone
tart clone ghcr.io/cirruslabs/macos-runner:golden-gate sand-nettest-proxy

# Stage A: raw softnet rules, no Sand
tart run --no-graphics --net-softnet --net-softnet-block=0.0.0.0/0 \
  "--net-softnet-allow=in proto tcp @host port 22" sand-nettest-proxy &
IP=$(tart ip sand-nettest-proxy --wait 120)
sshpass -p admin ssh -o StrictHostKeyChecking=no admin@$IP true       # SSH works
sand network probe-script --verify strict --no-proxy > probe.sh
tart exec -i sand-nettest-proxy bash -s < probe.sh   # every SANDPROBE line must be CLOSED (tart exec uses the guest agent, not the network)

# Stage B: proxy and tunnel by hand
swift run sand network proxy --config fixtures/network_github_default.yml --listen 127.0.0.1:18080 --log-file proxy.log &
sshpass -p admin ssh -N -o ExitOnForwardFailure=yes -R 127.0.0.1:3128:127.0.0.1:18080 admin@$IP &
sshpass -p admin ssh admin@$IP 'curl -x http://127.0.0.1:3128 -sI https://github.com | head -1'   # 200, steered=true in the proxy log
sshpass -p admin ssh admin@$IP 'curl -x http://127.0.0.1:3128 -s -o /dev/null -w "%{http_connect}" https://example.com'  # 403

# Stage C: a full run against a test repo (default network), then Stage D failure injection:
#   pkill -f 'softnet --vm-fd'; kill the tunnel ssh; kill the proxy; toggle the VPN; toggle Wi-Fi
# Stage E: repeat A and B with BlastShield off; expect steered=false and the same allow/deny results.

# Cleanup
tart stop sand-nettest-proxy; tart delete sand-nettest-proxy; tart list
```
