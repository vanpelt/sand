# Sand Enterprise: security architecture and delivery plan

**Status:** Proposal / implementation roadmap (November 2026)  
**Audience:** Endpoint Security, Infrastructure, Developer Productivity, GitHub administrators  
**Scope:** Opt-in employee MacBooks as ephemeral macOS GitHub Actions runners, with a path to dedicated managed Macs  
**Related work:** [Keychain signing and host logging (#1)](https://github.com/vanpelt/sand/pull/1) · [Softnet network-isolation prototype (#2)](https://github.com/vanpelt/sand/pull/2)

> This is a design proposal, **not** a statement that the current Sand implementation satisfies enterprise controls. Each security claim below is conditional on implementation, verification, monitoring, and organizational policy approval. A passing Swift test suite does not establish VM isolation.

## 1. Goals and non-goals

### Goals

1. Permit **automatic execution** of eligible, ordinary CI jobs on a managed employee MacBook **only when the authorized GitHub triggering identity is the device's assigned employee**.
2. Require a **fresh Touch ID-backed (or explicitly approved local-authentication) authorization** for dormant or materially changed workflows, jobs requesting a more privileged tier, and workflows permitted to consume secrets.
3. Bind registration eligibility to a **specific enrolled and compliant device**, its assigned employee, and an approved corporate Sand distribution. Do not distribute a reusable GitHub App private key to developer laptops.
4. Limit each runner to **repositories the employee currently has access to**, subject to a separate stricter workflow/job admission policy.
5. Execute one job in a **disposable, isolated macOS VM** with no inherited host credentials, files, SSH agent, clipboard, or corporate network authority.
6. Enforce **default-deny network access outside the guest**, with a tightly scoped proxy for GitHub and approved package/artifact services. **Do not inherit the employee's BlastShield permissions**.
7. Make every authorization and execution **auditable and revocable**. Fail closed if device posture, policy, network enforcement, or attribution cannot be verified.

### Non-goals for the initial release

- Running arbitrary public-fork PR code or unreviewed workflows on employee machines.
- Production deployments or access to production credentials from employee MacBooks.
- Treating a corporate code signature, Jamf enrollment, or Apple device attestation **alone** as remote proof of the identity of the running process.
- Guaranteeing that an allowlisted service such as GitHub cannot be used to exfiltrate data. Destination allowlisting is not content or intent inspection.
- Giving a guest the endpoint's BlastShield identity or corporate VPN routes.
- Creating a custom GitHub Actions protocol; use documented runner/JIT APIs where possible.

## 2. Existing foundation versus required work

| Capability | Current status | Enterprise gap |
| --- | --- | --- |
| Disposable Tart VM per Sand runner lifecycle | Existing | Verify one-job lifecycle, isolation and cleanup on all failure paths |
| GitHub App registration | Existing | App registration authority currently reaches the endpoint; move privileged credentials to broker |
| macOS Keychain-based GitHub App signing | Proposed in #1 | Useful local prototype; **not** the enterprise credential distribution model |
| Runner tarball digest verification/cache | Existing | Pin image/runner provenance and harden cache/update supply chain |
| Terminal logs and smoke test | Proposed in #1 | Central structured audit, secret redaction and incident diagnostics |
| Softnet IPv4 network modes | Prototype in #2 | Live negative tests; DNS/IPv6/host/BlastShield controls, enforced proxy, health monitoring |
| Employee/repository policy | Not implemented | Broker and identity/permission integration |
| Per-job admission and owner attribution | Not implemented | Trigger-actor verification and race-free GitHub scheduling admission |
| Touch ID approval leases | Not implemented | Secure Enclave/Keychain key, challenge protocol, lease lifecycle |
| Secret tiers and external issuance | Not implemented | Protected environments / OIDC-based secrets broker |

**Important dependency:** #2 is stacked on #1. This documentation-only plan is independent of both implementation branches.

## 3. Threat model and trust boundaries

Assume workflow code is **hostile** even when it originates in a private repository. Consider a malicious dependency, compromised GitHub Action, insider, changed workflow definition, unexpected actor, compromised developer session, compromised host process, stolen token, and an attacker-controlled service on an otherwise allowed destination.

| Boundary | Protected assets | Minimum invariant |
| --- | --- | --- |
| GitHub → broker | Broker webhook state and scheduler | Verify signature; re-fetch authoritative job/run/repo metadata from GitHub; reject replay/stale events |
| Endpoint → broker | Runner registration privilege | Authenticated managed device + authenticated mapped employee + current policy before issuance |
| Local agent → host | MacBook files, VPN/BlastShield identity, credential stores | Signed and managed agent; hardened privileges, least-permission daemon/CLI; no VM access to host credentials |
| Host → VM | Corporate network, peer VMs, host services | Host-enforced isolation before VM startup; no unrestricted fallback; no mounts/clipboard |
| VM → Internet | Registries, GitHub, data exfil destinations | Default-deny egress; separate scoped proxy identity; measured exceptions |
| CI → secrets | Repository/environment/production credentials | Explicit secrets classification and approvals; no production secrets on employee laptops |
| VM → broker | Registration configuration and audit | One-purpose, short-lived configuration; no privileged GitHub App key in guest |

### Explicitly limited security claim

A Secure Enclave key can bind proof of possession to an endpoint; Jamf posture can indicate whether that endpoint is managed; Apple attestation can provide evidence about the device. **None, by itself, proves to a remote server that a particular company-signed Sand binary produced a request.** Local code-signature validation, hardened runtime, managed installation, endpoint controls, key access control and host compromise assumptions must be stated separately.

A root-compromised host may tamper with the VM, networking and local agent. The design must make that risk measurable and limit the resulting GitHub registration blast radius, not claim an impossible host-compromise guarantee.

## 4. Target architecture

\`\`\`text
GitHub workflow_job webhook + GitHub API
                  |
                  v
       +--------------------------+
       | Enterprise Sand broker   |
       | - GitHub App authority   |
       | - user/repo/workflow ACL |
       | - device + Jamf posture  |
       | - trust lease / approval |
       | - JIT runner allocation  |
       | - audit + revocation     |
       +--------------------------+
                  |
       authenticated control plane
                  |
                  v
       +--------------------------+
       | Managed MacBook          |
       | signed Sand agent        |
       | Secure Enclave identity  |
       | local approval UI        |
       +--------------------------+
                  |
        isolated VM + egress policy
                  |
                  v
       +--------------------------+        +---------------------+
       | Disposable Tart macOS VM | -----> | Scoped egress proxy |
       | one approved CI job      |        | GitHub/registries   |
       | no host identity/mounts  |        | NO corporate VPN ACL|
       +--------------------------+        +---------------------+
                  |
                  v
           GitHub Actions
\`\`\`

The **broker** retains GitHub App credentials in a managed secrets system/KMS/HSM as appropriate. Jamf provisions device-specific authentication identities, not the GitHub App signing key. The agent authenticates to the broker; the broker authorizes repository/job requests and obtains repository-scoped just-in-time (JIT) runner configuration.

The **VM** receives only the minimum runner configuration required for its job, and must not see device authentication keys or broker service credentials. Local Sand still controls Tart, host-side runner image/cache, SSH provisioning, cleanup and logging.

## 5. Identity, device posture and binary trust

### Endpoint enrollment

- Jamf scopes a **signed, notarized, hardened** Sand agent to eligible Apple silicon Macs and a dedicated managed configuration profile.
- Provision a **unique, hardware-protected per-device key/certificate** where supported, using Managed Device Attestation / ACME only after testing the specific Jamf, OS, hardware and certificate enrollment path.
- Broker validates device identity, fresh challenge, certificate validity, MDM enrollment, assigned primary user, policy version and current compliance. Recheck regularly and at each allocation.
- Map employee IdP subject ↔ GitHub immutable user ID ↔ Jamf device assignment. Treat usernames, email aliases and host-reported identity strings as insufficient proof.
- Immediately deny new registrations on employee departure, GitHub access loss, Jamf unenrollment, certificate revocation, device compromise or policy downgrade.

### Process integrity

- Jamf-managed installer and endpoint policy enforce the expected Team ID / designated code-signing requirement on Sand and privileged helpers.
- Restrict the device-authentication key's use to authorized contexts as far as macOS allows. Avoid placing bearer secrets in process args, world-readable config, guest mounts, runner logs or shared Keychains.
- Broker never accepts a *self-reported* code hash as attestation. Document the gap between device-level trust and process-level trust.
- Add signed update provenance, controlled rollout/rollback and revocation of vulnerable versions.

**Acceptance:** A non-enrolled device, expired/revoked certificate, wrong employee, removed Jamf scope and missing/invalid posture must all be denied registration; the correct signed agent on a compliant device must succeed. Simulate loss of management connectivity and confirm **no permissive fallback**.

## 6. Job eligibility, authorization and scheduling

### Admission policy

A job is eligible only if **all** conditions are satisfied:

1. Webhook is authentic, unique and fresh; broker independently fetches GitHub job/run/repository metadata.
2. Repository is explicitly enabled for Sand, is allowed by corporate policy, and is accessible to the endpoint's assigned GitHub user **at decision time**. Distinguish read access from required execution authorization.
3. Event type is eligible (initially: push by the owner or manual dispatch by the owner on an allowed ref). Reject public-fork PRs, bots, schedules, untrusted PR heads, ambiguous actor identity and reruns started by another user by default.
4. The **user who caused this specific run** is the device owner. Do not equate the original \`github.actor\` with \`github.triggering_actor\` for reruns; define and test event-specific actor semantics.
5. Workflow identity, source revision, permissions tier, job metadata and host network policy match an approved policy or an unexpired trust lease.
6. Selected endpoint is enrolled, compliant, online, available, consented to opt-in and able to enforce the required isolation.
7. Runner configuration is repository-scoped, ephemeral, unique and allocated for this narrowly approved request.

Use immutable GitHub user IDs and repository IDs, not just mutable name strings. Handle repo transfers, renamed repositories, fork relationships, membership changes, enterprise org policy and user/device reassignment.

### Critical job-binding limitation

**Repository-scoped JIT runner registration does not itself cryptographically pin the runner to a particular queued job.** GitHub's normal runner labels/group matching can select another eligible matching job in that repository. Inventing a unique label is not equivalent to job-level authorization.

Therefore, **no enterprise automatic execution until we demonstrate an effective job admission gate**. Candidate approaches to research and test:

- Strictly allowed workflows/refs and dedicated GitHub runner groups, with GitHub workflow restrictions where supported.
- Broker-issued, per-job unique allocation plus authoritative assignment verification and a runner-side pre-execution gate that can reject unexpected work **before any workflow-controlled code or secret exposure**.
- If GitHub's runner protocol/API does not permit reliable pre-execution authorization, restrict the initial product to specific trusted workflows on protected refs or dedicate per-repository runners with sharply reduced privileges. Explicitly document any remaining scheduling race.

**Acceptance:** Concurrent jobs (including another employee's job, a rerun, an edited workflow and a malicious matching-label job) cannot execute on the owner's Mac without authorization. Demonstrate rejection *before* running checkout, job steps or third-party Actions; log the rejected job ID and cause. If we cannot prove this, it is a launch blocker.

### Registration lifecycle

- Receive queued job → verify it → allocate an eligible endpoint → attest/authorize policy → install VM network boundary → request JIT registration → start guest → accept only intended job → destroy VM and deregister.
- Bind broker allocation to repository ID, job/run/attempt IDs, approved workflow identity and revision, device ID, employee ID, policy version, trust tier, expiration and a unique nonce.
- Limit outstanding registrations, enforce timeouts and avoid pre-registering idle laptops in arbitrary repositories.
- Garbage collect orphaned runners after crashes/offline devices; handle GitHub API rate limits, runner version changes, lost webhooks and replay.
- Use a single idempotent state machine with audit transitions: \`queued → authorized → allocated → registered → running → cleaning → closed\` (or explicit denied/expired/failure branches).

## 7. Touch ID and time-limited workflow trust

### Desired user experience

- **Auto-run:** Recent, unchanged, ordinary non-secret CI workflows triggered by the Mac's owner run without an interactive prompt.
- **Prompt:** A workflow not run for a configurable idle period (pilot default: **14 days**), a materially changed workflow or an elevated security tier requires approval.
- **Secrets:** Any workflow authorized for secrets beyond the ordinary minimal GitHub token requires at least a separate elevated approval; high-value credentials remain prohibited on employee machines.
- **Deny/timeout:** Decline, cancel, locked screen, absent employee or failed local authentication means no authorization; an approved job may wait or move to a dedicated runner pool instead.

### Lease design

A broker nonce/challenge is bound to **device + employee + repo + workflow identifier/ref/content digest + workflow/job policy tier + allowed network policy + expiration + nonce**. Sand requests local authentication to use an approval key whose private material remains protected by macOS; the broker verifies the signature and issues a scoped, revocable workflow trust lease.

Treat \`LocalAuthentication\` and Keychain access control carefully: the choice between biometric-only and macOS passcode fallback must be explicit; testing must cover user-presence semantics, Touch ID availability and headless/locked sessions. A local success bool alone is *not* cryptographic proof of user approval.

- Record last **successful trusted execution**, not only last approval, for inactivity-based prompts.
- Renew approvals only within policy limits (e.g. <=30 days maximum validity); revoke on device/user/repo change, workflow digest change, expanded permissions, changed secret classification or network scope expansion.
- Hashing one YAML file is not sufficient to capture referenced reusable workflows, action versions, runtime downloads and mutable dependencies. Define **what code/policy is actually covered** by a trust lease; require pinned dependencies for higher tiers.
- Never allow a workflow to self-assert \`noSecrets\` or its own approval tier.

**Acceptance:** Approval on device A does not authorize device B, user B, another repo, a changed workflow, a more privileged network policy or a replayed challenge. Test biometric failure, expiry and forced revocation.

## 8. Secrets and execution tiers

| Tier | Allowed on employee Mac? | Typical rules |
| --- | --- | --- |
| A — ordinary CI | Yes | Owner-triggered, trusted workflow/ref, repository-scoped runner, read-only \`GITHUB_TOKEN\`, no additional repo/env secrets, restricted egress |
| B — elevated build | With explicit approval and additional controls | Touch ID-backed lease, named secret/network policy, protected source/workflow, external short-lived credentials where possible |
| C — production / privileged deployment | **No**, initially | Dedicated corporate runners and separate release approvals |

**Important:** GitHub does not provide a universal, authoritative pre-execution inventory of all secrets arbitrary scripts and Actions might consume. Branch checks and searching YAML for \`secrets.\` are inadequate. A repository with broadly available repository secrets may not be eligible for Tier A unless their exposure can be technically excluded.

Proposed mechanisms to evaluate:

- GitHub environments with protection rules for gated jobs and environment-scoped secrets, with plan/feature compatibility verified against the company's GitHub tier.
- A separate OIDC-based secrets broker that verifies GitHub run/repo/ref/environment claims plus Sand broker approval and issues **short-lived, narrowly scoped** secrets.
- Repository/org policy that blocks high-privilege or broad secrets from ordinary employee runners; tightly scoped default \`GITHUB_TOKEN\` permissions.
- Redaction and log hygiene; never print auth, JIT config, approval challenges, downloaded credential contents or proxy bearer tokens.

## 9. VM isolation and BlastShield-aware network design

### Non-negotiable invariant

**A VM may not register or accept a job unless an independent host-enforced network policy is active, complete and healthy.** Never silently fall back to Tart's normal shared networking.

Separate:

- **Host Sand control plane:** authenticates to broker over the company's approved host network/BlastShield identity.
- **VM data plane:** **no reuse of host BlastShield/VPN identity**; a distinct short-lived network authorization limited to required Internet services.

Use an enforced VM boundary (evaluate Tart Softnet plus system/network extension or equivalent) and a **controlled egress proxy** with policy keyed to broker allocation/job identity. Avoid placing general corporate BlastShield credentials in the guest. Test whether a subset/service-only BlastShield policy behind the proxy is feasible; do **not** assume the existing endpoint agent automatically isolates VM traffic.

### Egress baseline

- Default-deny **IPv4 and IPv6** and all protocols/ports except explicitly authorized management + proxy flows. Prevent alternate interfaces, DNS tunneling, gateway/host-local bypass, direct UDP/QUIC, unexpected VPN routes and host bridge paths.
- No guest access to the host, the Mac's SSH/agent sockets, RFC1918 and corporate networks, metadata services, peer VMs or developer LAN services unless an explicitly reviewed exception is essential.
- Use a dedicated DNS policy and restricted HTTP(S) CONNECT proxy (or equivalent). Account for GitHub Actions control traffic, checkout, artifacts, LFS, release downloads and approved package registries; pin exceptions to documented service functions rather than broad CDN ranges wherever viable.
- The proxy must enforce destination and service identity, policy version, scope, TTL and telemetry **outside the guest**. Access to an allowed public platform can still enable exfiltration, so secrets isolation is mandatory.
- Maintain a separate narrowly scoped host policy for Sand's image/runner downloads. The host downloads verified runner tarballs in the current architecture; that is **not** guest egress.
- If policy cannot install, Softnet is missing, the proxy is unavailable, policy health degrades or connectivity changes, fail closed: refuse registration, pause allocations, terminate affected guests and audit. Define a safe teardown path that cannot re-enable unrestricted guest networking.

### What #2 proves—and does not prove

[PR #2](https://github.com/vanpelt/sand/pull/2) prototypes **IPv4** \`shared\`, \`softnet\` and \`restricted\` modes with CIDR validation and launch flags. It does **not** provide tested IPv6/DNS enforcement, complete proxy integration, BlastShield isolation or continuously verified enforcement.

Do not call the network design secure because unit tests pass. Run **live positive and negative tests** with host BlastShield on/off, corporate VPN on/off, guest root, DNS/IPv6, connectivity changes, service crashes, alternate network interfaces, host services and arbitrary public destinations.

## 10. Supply chain, operations, incident response

- Publish signed/notarized agent packages through managed deployment; attest/version-gate upgrades and offer revocation/kill switch.
- Pin/verify VM images, Tart and runner binaries, and document provenance/approval for OCI sources; prevent unsigned guest image substitution.
- No guest host mounts, clipboard, broad file sharing or inherited environment secrets. Use a minimal provisioning channel and rotate/default-disable insecure image credentials before enterprise rollout.
- Limit CPU, RAM, disk, job lifetime, concurrency, battery/thermal impact and device availability; never run without explicit endpoint opt-in.
- Ship structured audit events: timestamp, employee ID, device ID, Jamf posture version, code/build version, repo ID, workflow digest, run/job/attempt ID, triggering actor ID, policy decision, approval lease, network policy version, runner ID, start/end, teardown state.
- Broker logs must be tamper-evident, privacy-reviewed and retention-controlled. Central metrics: denied allocations, unexpected actor/job, missing posture, policy enforcement failures, orphaned runners, proxy bypass attempts, leaked credentials and cleanup failure.
- Provide emergency revocation of devices, employees, workflows, runner groups, proxy identities and all broker-issued configurations; test rapid shutdown and orphan cleanup.
- Failures must have actionable, **redacted** diagnostics. Never hide GitHub/network permission errors behind an endless VM destroy/recreate loop.

## 11. Delivery phases and security acceptance gates

### Phase 0 — ADRs, threat model, and pilot policy

**Deliver:** Architecture decision records for actor semantics, job admission, process integrity, network enforcement, BlastShield integration and secret tiers. Document concrete policies and ownership (Security/IT, DevEx, GitHub admins).

- [ ] Select permitted event types, source refs, repo scope and authorized user mapping.
- [ ] Validate organizational GitHub API/runner-group/environment capabilities and permissions.
- [ ] Write attacker stories and pre-execution race test cases.
- [ ] Define pilot exit criteria, exception process, rollback and risk owners.

**Gate:** Security signs off on what is *not* yet guaranteed, especially process identity and GitHub job binding.

### Phase 1 — Network-isolation proof on sacrificial managed Macs

**Deliver:** A reproducible egress policy, isolated proxy, packet-level verification harness, and failure-injection tests built on #2.

- [ ] Softnet and Tart preflight before VM boot; no shared-network fallback.
- [ ] Test host SSH provisioning separately from guest outbound access.
- [ ] Demonstrate allowed GitHub checkout/artifacts/package requests via approved proxy.
- [ ] Demonstrate denied host/LAN/VPN/BlastShield/corporate/peer VM and arbitrary Internet access, including IPv6, DNS and UDP.
- [ ] Demonstrate fail-closed behavior on Softnet/proxy crash and interface changes.
- [ ] Capture signed/retained evidence: test commands, host posture, packet traces and expected outcomes.

**Gate:** Security can reproduce successful authorized traffic **and** every required denial with an untrusted root-capable guest. If IPv6 or host-path isolation cannot be demonstrated, do not proceed to MacBooks.

### Phase 2 — Device identity and registration broker

**Deliver:** Central GitHub App credential, device challenge/authentication, Jamf+IdP+GitHub authorization, repository-scoped JIT allocation, cleanup/audit.

- [ ] Device enroll/renew/revoke and compliance lookup; bound employee mapping.
- [ ] Privileged GitHub signing authority remains broker-side.
- [ ] Broker API with nonce, expiry, mTLS/challenge proof, rate limiting, idempotency and audit.
- [ ] Enrollment-/permission-loss tests deny registration promptly.
- [ ] Deploy first to **dedicated Jamf-managed Macs**, not broad developer laptops.

**Gate:** No privileged GitHub App key or unrestricted registration authority lives on endpoints; stolen endpoint material cannot authorize another repo/device/user.

### Phase 3 — Owner-triggered automatic job admission

**Deliver:** Webhook queue integration, actor/ref/workflow verification, job-specific admission experiment, explicit policy and scheduling tests.

- [ ] Verify GitHub actor semantics for push, dispatch, rerun, bots, PRs, merge queues.
- [ ] Verify current user repo access and workflow allowlist on every allocation.
- [ ] Reproduce malicious concurrent matching-label job and scheduling races.
- [ ] Deny unexpected work **before code execution** or reduce supported scheduling scope until provable.
- [ ] One-job VM teardown, runner deregistration, retries with bounded backoff.

**Gate:** Exactly the approved actor/workflow/job gets execution on the selected endpoint; otherwise no automatic personal-MacBook scheduling.

### Phase 4 — Touch ID workflow leases and secrets policy

**Deliver:** Local approval UI, protected signing key, broker lease issuance/revocation, inactivity tracking, tiered secrets.

- [ ] Owner-triggered Tier A auto-exec; 14-day dormant-workflow reapproval pilot.
- [ ] Reapprove material workflow/policy changes and Tier B secret access.
- [ ] Verify nonce-bound signatures and non-transferability of approvals.
- [ ] Integrate protected environments/OIDC secrets brokerage where supported.
- [ ] Prohibit production Tier C credentials on personal endpoints.

**Gate:** Fresh approvals and tier escalation cannot be bypassed through edited YAML, reruns, mutable dependencies or unexpected actors.

### Phase 5 — Managed employee pilot, red team, gradual rollout

**Deliver:** Small opt-in Jamf MacBook cohort, operational dashboards/runbooks, red-team report, staged rollout policy.

- [ ] Red-team guest-to-host and guest-to-corporate escape, allowed-destination exfil, credential misuse, scheduler race, policy degradation.
- [ ] Validate battery, thermal, disk, multi-user sessions, offline mode and wake/sleep handling.
- [ ] Exercise org/user/device revocation and kill switch; show cleanup across crashes.
- [ ] Measure authorization denial rate, job success, queue latency and incidents.
- [ ] Publish clear employee consent and privacy expectations.

**Gate:** Security approval to expand beyond pilot after review of test evidence, unmitigated risks and rollback readiness.

## 12. Concrete first implementation tasks

Recommended starting tickets, in order:

1. **Softnet integration test harness**: launch real Tart guest, assert deny/allow paths and fail-closed startup/teardown under fault injection.
2. **Egress proxy proof-of-concept**: allow GitHub Actions + selected registries, block LAN/VPN and arbitrary domains, with per-job policy logs.
3. **Broker API contract and local mock**: schema for device identity, user/repo/job identity, policy version, JIT registration TTL and audit events; do not add privileged production GitHub credentials.
4. **Jamf/attestation spike**: certificate provisioning and endpoint identity validation under macOS user/launchd contexts.
5. **GitHub job-admission spike**: reproduce queued-job races and assess whether pre-execution authorization is technically enforceable.
6. **Touch ID key/lease spike**: Secure Enclave-protected approval key with nonce challenge and local-authentication policy; integration test on real hardware.

## 13. Open decisions for Security and Platform owners

1. Can BlastShield provide a dedicated service identity **behind** the egress proxy, with no transitive access to the employee's corporate policy? Or do we need an independent proxy/network extension?
2. How will we prevent another valid repository job from being assigned to a JIT runner after broker approval? What is the actual pre-execution enforcement point?
3. Which GitHub events count as genuinely "triggered by the owner" when the commit author, pusher, dispatch actor, rerun initiator and workflow actor differ?
4. What is the precise definition of an approved workflow version when it references third-party Actions and reusable workflows?
5. Can we technically exclude repository-level secrets from ordinary Tier A jobs, or must eligible repositories use protected environments / external issuance exclusively?
6. What fallback should apply when Touch ID is unavailable: macOS password, owner presence on another approved device, dedicated runner, or deny?
7. What is the organization-approved host-compromise threat model and what evidence is required before supporting employee MacBooks?
8. Do jobs remain pinned to a single owner device, or may an employee opt into a managed pool once identity and authorization are established?

## 14. Definition of enterprise-ready

Sand is **not** enterprise-ready until Security can independently reproduce all of the following:

- **Identity:** unapproved binary/device/user cannot obtain a useful registration; loss of eligibility revokes it.
- **Authorization:** employee repo rights are enforced, and an unexpected triggering actor or matching job cannot execute.
- **Approval:** dormant, changed and secret-capable workflows demand valid scoped approval; a replayed/expired lease fails.
- **Isolation:** guest root cannot reach host secrets, BlastShield-protected corporate systems, alternate routing paths or unapproved network destinations.
- **Credentials:** no broad GitHub App signing key or production secret reaches the endpoint/VM.
- **Operations:** fail-closed behavior, bounded retries, one-job teardown, orphan cleanup, kill switch, audit and incident response all pass fault injection.
- **Evidence:** the test matrix, red-team results, limitations, and accepted residual risks are versioned with the release.

**Bottom line:** A MacBook may donate compute, but it must not donate the employee's GitHub authority, corporate network authority, or secrets to arbitrary CI code.
