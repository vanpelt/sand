# Experimental VM network isolation

This opt-in prototype adds Softnet network policies to Sand. It does **not**
implement the enterprise admission broker, employee-to-repository authorization,
Touch ID approval, BlastShield integration, DNS-aware egress allowlisting or
a host-enforced per-job proxy. Do not treat it as a production security boundary
without validating the host and guest traffic paths.

Softnet is provided by Tart's `--net-softnet` option. This implementation
adds the options **at VM launch**, so there is no unrestricted bootstrap window
caused by installing policies after the VM starts.

## Prerequisites

- Apple silicon host running macOS 26+ and a Tart version supporting
  `--net-softnet`, `--net-softnet-block` and `--net-softnet-allow`.
- Install Softnet with `brew install openai/tools/softnet`, then follow
  the upstream guidance for its privileged launcher. Softnet requires
  elevated privileges to create a vmnet interface and drops them after
  initialization. Do not disable system protections to make it work.
- Configure the host's security product explicitly: BlastShield and other
  host VPN or endpoint filters may affect VM traffic in surprising ways.

## Modes

`vm.run.network.mode` defaults to `shared` for compatibility.

### Softnet isolated

```yaml
vm:
  run:
    noClipboard: true
    network:
      mode: softnet
```

Equivalent Tart flag: `--net-softnet`.

This blocks most host/private IPv4 access but **permits globally routable
IPv4 destinations**. It is a useful first connectivity and isolation test;
it is not a default-deny Internet policy.

### Restricted IPv4 egress

```yaml
vm:
  mounts: []
  run:
    noClipboard: true
    nested: false
    network:
      mode: restricted
      allowCIDRs:
        - 10.42.10.25/32 # EXAMPLE ONLY: dedicated egress proxy
```

Equivalent Tart flags:

```sh
--net-softnet --net-softnet-block=0.0.0.0/0 --net-softnet-allow=10.42.10.25/32
```

The allowlist is deliberately constrained to explicit IPv4 CIDRs of /24–/32
to reject broad accidental bypasses. A restricted policy requires at least
one CIDR and disallows host mounts, clipboard sharing and nested virtualization.

**Important:** The CIDR example is not a working GitHub egress configuration.
GitHub Actions needs multiple changing destinations and DNS. Route the guest
through an externally enforced, restricted proxy with a stable IP and configure
proxy settings inside the guest/runner; **Sand does not set those proxy
variables yet**. If the proxy is a local or corporate IP, verify that it does
not also expose unrelated host/corporate services. The host still downloads
the runner tarball outside the guest and is subject to its own network policy.

Softnet's documented enforcement covers forwarded IPv4 traffic. This
prototype does not independently verify IPv6, DNS, gateway exceptions, return
traffic, port restrictions, host access, or BlastShield/VPN routing. These
require negative integration tests and additional controls before enterprise use.

## Manual validation protocol

1. On a sacrificial managed Mac, install Tart and Softnet. Start with
   `mode: softnet` and verify the VM boots, Sand reaches SSH and a GitHub
   Actions job completes.
2. From **inside the guest**, test that the Mac's address, other RFC1918
   destinations and any corporate VPN addresses are unreachable; verify
   external public GitHub URLs still work. Capture packet traces on the host
   if possible.
3. Switch to `mode: restricted` and an *actual* isolated proxy IP.
   Confirm an approved HTTPS request via the proxy succeeds but direct
   requests to an arbitrary public IP, host/private IP and internal service
   fail. Confirm TCP and UDP, DNS, IPv6 and attempts to change guest routes.
4. Kill/disable Softnet or provide malformed rules and verify **no runner
   registers and no VM receives unrestricted fallback networking**.
5. Repeat when BlastShield is enabled, disabled, on/off VPN, and after
   interface/network changes. Check that policies cannot be bypassed by a
   privileged user inside the VM.
6. Inspect artifacts and logs for unintended exposure of host credentials,
   proxy credentials or corporate routes.

Do not assign sensitive workflow jobs to a restricted VM until every denial
path is tested with both successful and unsuccessful controls.

## Future enterprise work

- Dedicated proxy integration with domain-aware logging and GitHub-specific
  allowlists; handle dynamic DNS, CDN hosts and TLS without guest bypass.
- Per-device/employee broker and repository-scoped, just-in-time registration.
- Workflow actor validation and per-job authorization (GitHub runner labels
  alone are not a binding to a specific GitHub job).
- Touch ID-backed approvals tied to workflow identity and permissions.
- Enforcement and attestation of host network controls, plus fail-closed
  termination on policy degradation.
