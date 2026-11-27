# VM network isolation

Sand isolates every VM's network **by default**. A runner with no
`vm.run.network` key gets `profile: github`:

1. **Softnet deny-all.** Tart starts the VM with
   `--net-softnet --net-softnet-block=0.0.0.0/0 "--net-softnet-allow=in proto tcp @host port 22"`.
   The guest's IPv4 traffic is dropped except for host-to-guest SSH replies.
   Softnet drops all IPv6. Guest DNS to the gateway is blocked as well, so
   there is no split-DNS leak and no DNS tunnel.
2. **A host-side allowlisting proxy.** Sand runs a per-VM HTTPS CONNECT proxy
   bound to `127.0.0.1` on the host. It checks the hostname against the
   policy, resolves it with the host's system resolver, refuses private or
   host-local addresses, and requires the TLS ClientHello's SNI to equal the
   CONNECT host.
3. **An SSH reverse tunnel.** The guest reaches the proxy as `127.0.0.1:3128`
   through `ssh -N -R 127.0.0.1:3128:127.0.0.1:<port>`, which runs over the
   SSH session Sand already uses. Nothing on the host listens on the VM bridge.
   If the tunnel dies, egress dies with it.
4. **Guest settings for usability only.** Sand writes `https_proxy`,
   `http_proxy` and `no_proxy` into the runner's `.env` and the login shell
   profiles. On macOS it also sets the system web proxy and points DNS at
   loopback. Enforcement never depends on these settings: a tool that ignores
   them just fails to connect.
5. **Fail closed at every stage:**
   - preflight before any clone;
   - a guest egress check before any runner registers;
   - a watchdog from SSH-ready until teardown.

   Sand never falls back to shared NAT.

## Threat model

The guest runs untrusted workflow code as a root-capable user. The guest must
be able to reach GitHub (and approved package hosts) to run Actions jobs. It
must never reach:

- the host's own services (ControlCenter, rapportd, a local sshd, agents);
- the developer's LAN, Tailscale/tailnet (100.64/10) or peer VMs;
- corporate networks reachable over the host's VPN (for example BlastShield
  172.16/12 routes, or 172.16.0.1 resolvers);
- cloud metadata (169.254.169.254) or anything link-local;
- arbitrary internet destinations, over UDP/QUIC, IPv6 or DNS.

The guest is not trusted to honour proxy variables. Softnet removes every
direct path, so the only way out is the host proxy, and the proxy enforces the
policy outside the guest.

## One-time host setup

Softnet needs root to create its vmnet interface. It drops privileges after
setup. Run this in your own terminal; Sand never runs `sudo` for you:

```sh
brew install cirruslabs/cli/tart openai/tools/softnet
sudo chown root:wheel "$(realpath "$(which softnet)")" && sudo chmod u+s "$(realpath "$(which softnet)")"
sand doctor          # or: sand network preflight --config sand.yml
```

- `brew upgrade softnet` installs a fresh binary without the setuid bit, so
  re-run the two `sudo` commands after every upgrade. Sand re-checks before
  every clone and refuses to boot until you do.
- Instead of setuid you can add a sudoers `NOPASSWD` rule for both
  `/opt/homebrew/bin/softnet` and its Cellar path. Tart then uses
  `sudo --non-interactive softnet`. Sand's preflight checks the same thing
  with `sudo -n <softnet> --help`, which never prompts.
- Disclosure: softnet runs its setup as root. It also rewrites the system
  bootpd preferences (`DHCPLeaseTimeSecs=600`) so ephemeral VMs do not exhaust
  DHCP leases.

## Configuration

```yaml
vm:
  run:
    network:
      profile: github                 # github (default) | offline
      presets: [npm, pypi, homebrew]  # optional extra built-in bundles
      allowedDomains:                 # optional; port defaults to 443
        - registry.example-artifacts.com
        - "*.cdn.example.com"
        - "git.example.org:8443"
      verify: basic                   # basic (default) | strict
      allowedCIDRs:                   # expert escape hatch, see below
        - { cidr: 203.0.113.10/32, port: 443, proto: tcp }
```

- **No `network` key** is the same as `profile: github`.
- **`profile: offline`** applies softnet deny-all with no proxy; only host SSH
  works. Use it for script provisioners that need no network. It is the only
  profile that accepts `verify: off`.
- **`mode: shared`** is the only way to get Tart's unrestricted shared NAT. It
  is required for host `mounts`. Sand warns on validate and on every boot.
- **`mode: softnet` and `mode: restricted`** keep their prototype meaning.
  Restricted now also allows host SSH. Under a VPN with split DNS, plain
  softnet makes the steered GitHub names unreachable, because it blocks
  private destinations. Prefer the profile.

Validation rules:

- Setting both `profile` and `mode` is an error, and so is an empty
  `network: {}`. An unknown profile, mode or preset is also an error.
- `allowedDomains` entries are lowercased and any trailing dot is stripped.
  - Each entry must use valid hostname labels. Give IDN names in punycode.
  - Two wildcard forms are allowed: a leading `*.` (at least two labels after
    it), and one `*` inside the first label (`build*.example.com`). Avoid
    either form on multi-tenant suffixes (`*.blob.core.windows.net`,
    `*.s3.amazonaws.com`, `*.cloudfront.net`, `*.github.io`): anyone can
    register a name there, so the wildcard admits their endpoints too.
  - These are rejected: IP literals, a bare `*`, `*.com`, `a.*.b`, and ports
    outside 1-65535. Ports 22 and 25 produce a warning.
- `allowedCIDRs` must be IPv4 /24 to /32 and must set `port`.
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
the tart arguments, every allowed destination, the steered names and the
policy hash that audit lines carry.

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
  process flows, so the endpoint agent may intercept them. A guest then sees
  the inspection CA and fails TLS. This fails closed, but jobs break. Either
  ask IT for a bypass for the affected hosts, or wait for the planned opt-in to
  install the inspection CA in the guest. Guest traffic under the old shared
  NAT bypassed Netskope entirely.
- **Disconnecting the VPN mid-run.** New connections resolve to public
  addresses and go out directly. A GitHub IP allow list then answers 403
  inside the job. That is a visible failure, not a leak.
- **VM subnet collisions.** Softnet picks the VM's subnet. If it overlaps a
  host route, such as the VPN's 172.16/16, it would shadow the steered fronts.
  Sand recreates the VM (up to three times) and fails if it keeps colliding.
  The watchdog also ends a job if a later route change creates an overlap.

## What happens at runtime

1. `sand run` compiles each runner's policy and logs `network.policy.compiled`
   with the hash. It then runs the full preflight once per distinct policy.
   The checks are:
   - tart supports `--net-softnet-allow`;
   - softnet supports stateful rules (`proto`, `@host`);
   - softnet is privileged;
   - the host resolves GitHub and completes a TLS handshake to
     `api.github.com` (no API call, because of rate limits);
   - an in-process proxy self-test (`github.com` → 200, `example.com` → 403,
     `172.16.0.1:53` → 403);
   - ssh tools are present and there is enough disk space.

   Any failure exits with code 78 before a clone. Each later boot re-checks
   privilege and resolution.
2. Clone, then `tart run` with the softnet arguments. Tart runs with
   `SENTRY_DSN` and `CIRRUS_SENTRY_TAGS` removed from its environment.
3. Wait for an IP that answers SSH. A stale softnet lease is re-resolved.
4. Check the VM subnet against host routes.
5. Start the proxy and the tunnel. Wait for guest `127.0.0.1:3128`.
6. Verify the guest, before preRun or registration. Each negative probe runs
   with the proxy variables unset and must fail:
   - `basic`:
     - 1.1.1.1:443;
     - the resolved GitHub front on :443;
     - the gateway on :5000, :53 and :22;
     - DNS via the gateway and via 8.8.8.8;
     - IPv6.
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
7. Provision. The GitHub provisioner writes `~/actions-runner/.env` before
   `config.sh`, runs `config.sh` with the proxy variables and
   `--disableupdate`, then runs `run.sh`.
8. The watchdog polls every 2 s. These events end the job: tart exits, the
   softnet child disappears, the tunnel exits, the proxy listener fails, or a
   route overlap appears. The VM is stopped and deleted, the runner is
   deregistered (`network.enforcement.lost`), and the next VM is subject to the
   restart backoff.

## Reading audit lines

Network events go to the normal log. With `--log-file X.log` they are also
written as JSON lines to `X.network.jsonl`.

```
network.connect bytes_down=548251 bytes_up=583 decision=allow duration=0.3 host=github.com ip=172.16.7.60 port=443 steered=true
network.connect decision=deny host=example.com port=443 reason=not-allowlisted
network.connect decision=deny host=registry.npmjs.org port=443 reason=blocked-address(172.16.7.60=private)
```

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

- **"Network preflight failed".** Run the printed `sudo` commands, or
  `sand network preflight --config sand.yml` for the full report.
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

## Migration

- To keep shared NAT, add `network: { mode: shared }`. Do this for runners
  with host `mounts`, which isolated VMs reject.
- A legacy `mode: restricted` config keeps working and now allows host SSH.

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
- **No softnet policy attestation yet.** The watchdog checks that processes are
  alive; it cannot read back the rules softnet enforces.
- **IPv4-only rules.** Softnet rules are IPv4 only. IPv6 is dropped entirely
  rather than filtered.
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

- Softnet and Tart preflight before VM boot, with no shared-network fallback.
- Host SSH provisioning that is separate from guest egress (the `in proto tcp
  @host port 22` rule versus the proxy tunnel).
- Allowed GitHub traffic through an approved proxy, and denied
  host/LAN/VPN/corporate/internet traffic, including IPv6, DNS and UDP. The
  in-guest verifier checks both on every boot.
- Fail-closed behaviour when softnet, the proxy or the tunnel crashes, and on
  route changes.

Still open:

- signed and retained evidence (packet traces);
- the live failure-injection runs from the test plan;
- security sign-off on the BlastShield exception above.

## Verified on this host (2026-11-27)

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

- **Netskope intercepts proxy flows.** The host proxy's upstream connections
  to `*.actions.githubusercontent.com` (pipelines, results-receiver),
  `objects.githubusercontent.com` and `raw.githubusercontent.com` are
  TLS-intercepted. The guest sees the inspection CA and fails TLS. Sand fails
  closed, but **Actions jobs will not work on this host** until IT adds a
  bypass for these hosts or an opt-in guest trust of the inspection CA is
  approved.
- **Runtime softnet failure.** When softnet cannot start after preflight
  passed, sand recreates the VM with backoff indefinitely, logging "ip not
  ready". It never uses shared NAT, but it does not yet classify this as
  `network.enforcement.lost` or stop after N attempts.
- **IPv6.** Softnet rules are IPv4 only, so the guest's IPv6 is dropped. The
  proxy can still connect to public IPv6 upstreams for allowlisted names.
  NAT64, 6to4, Teredo and IPv4-compatible forms are denied.
- **DNS.** The guest has no direct DNS. Names are resolved only on the host,
  for allowlisted names, and the answers are never returned to the guest.
  A guest that ignores the proxy settings times out on DNS (about 5 s) rather
  than failing at once.
- **Throughput.** The SSH tunnel roughly halves throughput: about 18 MB/s
  through the tunnel versus about 40 MB/s host-direct.

## Live test plan (sacrificial Mac, after the one-time setup)

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
