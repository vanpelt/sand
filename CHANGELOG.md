# Changelog

## Unreleased

### BREAKING: secure network default

- A runner without `vm.run.network` now runs with `profile: github`: softnet
  deny-all plus Sand's host-side allowlisting HTTPS proxy. Previously it used
  Tart's shared NAT, which gives the guest unrestricted reach to the host, LAN,
  VPN/tailnet and corporate networks.
- Hosts need the one-time softnet setup (`brew install openai/tools/softnet`
  plus setuid root, see docs/network-isolation.md). Without it `sand run` exits
  with code 78 before cloning any VM; `sand doctor` reports the same failure.
- To keep the old behaviour, set `vm.run.network: { mode: shared }`. Host
  `mounts` and `nested: true` now require it. Sand logs a warning on every boot
  of a shared-mode VM.
- `noClipboard` defaults to true for isolated VMs.
- `mode: restricted` now also allows host-to-guest SSH (the prototype's
  `block 0.0.0.0/0` dropped it).

### Added

- `profile: offline`, built-in `presets`, `allowedDomains`, `allowedCIDRs`
  (reviewed direct allows) and `verify: basic|strict`.
- Guest egress verification before registration, an enforcement watchdog,
  network audit events (also as `<log-file>.network.jsonl`).
- `sand network explain`, `sand network preflight`, `sand network proxy`.

### Fixed

- The runner release lookup (`releases/latest`) authenticates with the GitHub
  App installation token, so a shared VPN egress IP that is already
  rate-limited no longer blocks a host with an empty runner cache.
