# sand

Self-hosted macOS CI Runners powered by Tart - Apple's Virtualization framework.

## Requirements

- macOS 15+ running on Apple Silicon machines.
- Tart installed and available in PATH
- sand uses tart. it helps understanding tart before using sand (https://tart.run/quick-start/)

## Caveats

macOS DHCP leases last 24 hours by default, causing IP exhaustion if you run more than ~253 VMs per day. To reduce lease time to 10 minutes:

```
sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.InternetSharing.default.plist bootpd -dict DHCPLeaseTimeSecs -int 600
```

## Install

```
brew trust khoi/sand openai/tools
brew tap khoi/sand
brew tap openai/tools
brew install sand
```

Homebrew only loads formulae from taps you have trusted; the second tap provides Tart.

## Usage

```
sand run --config config.yml
sand destroy --config config.yml
sand run --dry-run --config config.yml
```

## Local test suite

To run the local bash e2e tests (no CI):

```
./Tests/run
```

These tests spin up real VMs and require `tart`, `ssh`, and `sshpass` on your machine. See `Tests/README.md` for environment overrides (image, timeout, SSH creds, etc).

## Start up on boot

Create your config at `~/sand.yml`, then let Homebrew manage a LaunchAgent for it:

```
brew services start sand
```

The service restarts sand if it exits, runs it as an interactive process so launchd doesn't throttle its CPU and I/O (or the VMs it starts), and writes output to `~/Library/Logs/sand.log`. Stop it with `brew services stop sand`.

## Logs

sand logs to macOS default logging system using `os_log`. To see the log

```
log show --predicate "subsystem == \"sand\"" --last 1h --info --debug
log stream --predicate 'subsystem == "sand"' --debug --info --style compact --color always
```

You can also write logs to a file:

```
sand run --config config.yml --log-file /tmp/sand.log
```

## Configuration

Create a `config.yml` and run the CLI with `--config`. 

### VM source

`vm.source` selects the base VM that sand clones for each ephemeral runner.

OCI image pulled from a registry:

```
vm:
  source:
    type: oci
    image: ghcr.io/cirruslabs/macos-runner:tahoe
```

Existing local Tart VM, referenced by name (as shown by `tart list`):

```
vm:
  source:
    type: local
    name: expo-runner
```

For `local` sources sand skips the registry pull and clones the named VM directly (`tart clone <name> <ephemeral>`), so the VM must already exist in `~/.tart/vms`.

### VM network isolation (secure by default)

> **Breaking change:** a runner with no `vm.run.network` key now gets
> `profile: github` instead of Tart's shared NAT. It needs **no root and no host
> setup**. To keep the old unrestricted behaviour, opt out explicitly with
> `network: { mode: shared }` (required for host `mounts`).

With no configuration, every VM boots on Tart's host-only network
(`tart run --net-host`: no route off the host, no DNS, no IPv6) and reaches the
internet only through a per-VM, host-side HTTPS CONNECT proxy that Sand runs on
loopback and forwards into the guest as `127.0.0.1:3128` over the SSH session.
The proxy allows GitHub (github.com, the Actions service, release/LFS/package
CDNs, ghcr.io) and nothing else, so the guest cannot reach the LAN, the
tailnet, corporate ranges or the internet directly. Because it resolves names
with the host's own resolver, VPN split DNS (for example BlastShield steering
github.com to a private front so traffic satisfies an org IP allow list) works
with no configuration.

The host-only network does not isolate host services bound to all interfaces
(for example AirPlay Receiver on `:5000`/`:7000`) or other VMs on the same
bridge. Sand reports those services before registering a runner
(`hostListeners: deny` refuses the VM) and warns when several runners share
the bridge. For full host and peer isolation use `backend: softnet`, which
needs a privileged softnet (one-time `sudo` setup in the docs), or
`backend: auto` to use softnet only where it is privileged.

```yaml
vm:
  run:
    network:
      profile: github                # default; or offline (no egress at all)
      backend: hostOnly              # default (no root) | softnet | auto
      presets: [npm, pypi, homebrew] # optional extra destination bundles
      allowedDomains:                # optional; port defaults to 443
        - registry.example-artifacts.com
        - "*.cdn.example.com"
      hostListeners: warn            # or deny (hostOnly)
      tlsInspection: fail            # or trustHostCA (Netskope/Zscaler hosts)
      maxEnforcementFailures: 3      # then sand run exits 78
```

**TLS-inspecting endpoint agents.** If an agent such as Netskope re-signs the
proxy's upstream TLS, preflight detects it generically (the chain ends in a CA
that Apple does not ship) and `sand run` exits 78, listing the hosts to ask IT
to exempt. Opt in with `tlsInspection: trustHostCA` to install only that CA's
public certificate in the guest (keychain plus a combined bundle exported as
`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO` and
`NODE_EXTRA_CA_CERTS`). Its SHA-256 fingerprint is written to the audit log.

`sand doctor` or `sand network preflight --config sand.yml` checks the host.
Repeated network enforcement failures at runtime (for example softnet dying
after preflight) stop `sand run` with exit 78 instead of re-cloning forever.

`sand network explain --config sand.yml` prints each runner's compiled policy
and hash. See [docs/network-isolation.md](docs/network-isolation.md) for the
threat model, presets, VPN/BlastShield behaviour, audit lines, troubleshooting
and residual risks.

### GitHub Actions setup

1) Create a GitHub App and grant `Self-hosted runners` permission set to `Read & Write` at the organization level. https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/registering-a-github-app
2) Install the app on the organization or the specific repository you want to run against.
3) Configure `appId`, `organization`, `repository` (optional), and exactly one of `privateKeyPath` or `privateKeyKeychainLabel` in your config.
4) Optionally set `runnerGroup` to register organization-level runners into a runner group (requires omitting `repository`).

Each VM boot registers the runner as `<runnerName>-<5 hex chars>` so a VM killed mid-session never collides with the next boot's GitHub session. Sand deletes that registration from GitHub when it tears the VM down.

### GitHub Actions runner provisioner
```
runners:
  - name: runner-1
    vm:
      source:
        type: oci
        image: ghcr.io/cirruslabs/macos-runner:tahoe
      cache:
        host: ~/.cache/sand/actions-runner
    provisioner:
      type: github
      config:
        appId: 123456
        organization: my-org
        repository: my-repo
        privateKeyPath: ~/my-app.private-key.pem
        runnerName: runner-1
    healthCheck:
      command: "pgrep -fl /Users/admin/actions-runner/run.sh"
      interval: 30
      delay: 60
```

### macOS Keychain signing (optional)

Instead of a PEM path, sand can sign GitHub App JWTs using an RSA private key held in the macOS Keychain. This uses Security.framework's SecKeyCreateSignature and does not export the private key into sand's process.

1. Import the GitHub App's existing RSA private key into your login Keychain. Substitute the actual path to your installed sand executable:

   ```bash
   security import github-app.pem \
     -k ~/Library/Keychains/login.keychain-db \
     -t priv -x -T /absolute/path/to/sand
   ```

2. In Keychain Access, find the imported private key and give it a unique name, such as sand-github-app. The configured label must match the key's actual Keychain label.
3. Replace privateKeyPath with privateKeyKeychainLabel:

   ```yaml
   provisioner:
     type: github
     config:
       appId: 123456
       organization: my-org
       privateKeyKeychainLabel: sand-github-app
       runnerName: runner-1
   ```

4. Verify signing works under the **same macOS user and launchd context** that will run sand before deleting the original PEM and any backups. Unattended operation requires that the Keychain be unlocked and the signing operation be authorized; an access prompt or a locked login Keychain can otherwise prevent jobs from starting.

The imported RSA key is not a Secure Enclave key (the Secure Enclave cannot sign RS256). Marking the key non-extractable with -x blocks normal Keychain export but does not make the key hardware-backed. This feature does not prevent an authorized or compromised sand process from requesting signatures.

Sand downloads the Actions runner on the host, checks it against the SHA-256 digest GitHub publishes for the release, and copies the verified tarball into each VM over `scp`. The guest never downloads the runner and never gets write access to the cache, so a job cannot tamper with the runner used by later VMs.

Verified tarballs are kept in `vm.cache.host` (default `~/.cache/sand/actions-runner`), with a `.sha256` file next to each and the three newest versions retained per platform. Sand checks for a new runner release once a day; if GitHub is unreachable it falls back to the newest verified tarball in the cache.

Common pitfalls:
- `vm.cache.host` must be a directory (missing paths are created; file paths are rejected).
- `vm.cache` is ignored unless the provisioner type is `github`.
- `scp` must be available on the host.

### Custom provisioner script

```
runners:
  - name: runner-1
    vm:
      source:
        type: oci
        image: "ghcr.io/cirruslabs/ubuntu:latest"
      hardware:
        ramGb: 4
      ssh:
        user: admin
        password: admin
        port: 22
    provisioner:
      type: script
      config:
        run: |
          echo "Hello World" && sleep 10
    healthCheck:
      command: "true"
```

If `healthCheck` is omitted, sand runs `echo healthcheck` every 30s after a 60s delay.

### VM run options

`vm.run` controls how each VM is booted via `tart run`:

```
runners:
  - name: runner-1
    vm:
      run:
        noGraphics: true    # default true; pass --no-graphics
        noClipboard: true   # default true when network is isolated (the default), false with mode: shared
        nested: false       # default false; pass --nested for nested virtualization
        rootDiskOpts: null  # optional; passed as --root-disk-opts
        network:            # optional; omitted means profile: github (see above)
          profile: github
```

Set `nested: true` to boot the VM with `tart run --nested`, enabling nested virtualization inside the guest. This requires an Apple Silicon host and guest that support it (see the [Tart docs](https://tart.run/)).

Set `rootDiskOpts` to tune the root disk with `tart run --root-disk-opts`. Since runner VMs are thrown away after each job, `caching=cached,sync=none` trades crash consistency for much faster guest fsync.

Full configurations keys can be found at [fixtures/sample_full_config.yml](fixtures/sample_full_config.yml) or [fixtures/sample_on_prod.yml](fixtures/sample_on_prod.yml)

## Acknowledgements

- https://github.com/cirruslabs/tart - doing all the heavy lifting interacting with VMs.
- https://github.com/traderepublic/Cilicon - sand is heavily inspired by Cilicon
