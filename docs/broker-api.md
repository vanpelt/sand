# Sand broker API, v1

This document is the contract between Sand on an endpoint (the *device*) and the Sand registration broker. The machine-readable form is `docs/broker/openapi.yaml`.

The design rationale is in `docs/adr/0001-job-admission.md`.

The local development implementation is `sand broker mock`. It implements this contract on loopback and holds a GitHub App key on the developer's own Mac. **It must never be pointed at enterprise endpoints, and no production credentials are used with it.**

## 1. Principles

- **The privileged GitHub App key lives only in the broker.**
  - The device gets a single-use, repository-scoped, ephemeral JIT runner config.
  - The guest VM gets nothing but that JIT config and the allocation nonce.
- **The broker decides admission from GitHub REST.**
  - Values sent by the device or the guest are *hints* used to find the job.
  - They are never treated as evidence.
- **Every decision fails closed.** Any error, timeout or unavailable dependency means `deny`, or no allocation.
- **Identifiers are immutable numeric GitHub ids** (`repository_id`, `actor.id`, `runner.id`, job id). Names are only for display.

## 2. Transport and authentication

- **TLS:** HTTPS (TLS 1.2 or later) is required. Plain `http://` is accepted only when the host is `127.0.0.1`, `::1` or `localhost` (the mock).
  - mTLS with a Jamf-issued device certificate is planned for Phase 2. It does not change these bodies.
- **Body format:** JSON with UTF-8 encoding. `Content-Type: application/json`. Request bodies are at most 16 KiB.
- **Timestamps** are RFC 3339 UTC with second precision. The broker clock is authoritative.
- **Device sessions:**
  - Every endpoint except the challenge, session and health endpoints takes `Authorization: Bearer <session_token>`.
  - Sessions last 15 minutes. Sand re-authenticates when a session is within 60 s of expiry, or on a `401 session_expired`.
- **Request ids:** every request carries a `Sand-Request-Id` header (a UUID). The broker echoes it back and records it in audit.
- **Mutating POSTs** (allocations, release, audit) need an `Idempotency-Key` header (a UUID). See §6.1.

### 2.1 Device challenge and response

| Step | Call |
| --- | --- |
| 1 | `POST /v1/device/challenges {device_id}` returns `201 {challenge_id, challenge, expires_at}`. The `challenge` is 32 random bytes in base64url. It lives for 60 s and can be used once. |
| 2 | The device signs the message below with its device key (ECDSA P-256, SHA-256). |
| 3 | `POST /v1/device/sessions {device_id, key_id, challenge_id, signature}` returns `201 {session_token, expires_at, device_id, owner:{github_user_id, github_login}, policy_version}`. |

The message the device signs is exactly these bytes:

```
sand-broker-v1\n
device-session\n
<device_id>\n
<challenge_id>\n
<challenge>
```

- Each line ends with a single `\n`. There is no trailing newline after `<challenge>`.
- `signature` is the raw 64-byte `r||s` value in base64url, which is CryptoKit's `rawRepresentation`.

**Keys:**

- This iteration (development) uses a P-256 key in a file with mode 0600.
- Phase 2 moves to a Secure Enclave key (`SecureEnclave.P256.Signing`) and adds Jamf posture checks before issuing a session.

**Errors:**

- `401 challenge_invalid`: the challenge is unknown, expired or already used.
- `401 signature_invalid`
- `403 device_revoked`
- `403 device_noncompliant` (later)

The broker maps each `device_id` to exactly one owner: an immutable GitHub user id plus an employee id later. The device cannot choose its owner.

## 3. Resources and state machine

An **allocation** is one JIT runner registration for one VM, which is allowed to run at most one admitted job.

```
requested ─► registered ─► assigned ─► admitted ─► cleaning ─► closed
                 │             │           │
                 ├─► expired   └─► denied  └─► failed
                 └─► released (before any job)
```

The states map to the plan §6 states as follows:

| Broker state | Plan state |
| --- | --- |
| `registered` | `allocated → registered` |
| `assigned` | GitHub assigned a job, seen in REST |
| `admitted` | `running` |

`denied`, `expired`, `failed` and `released` all pass through `cleaning` (runner deletion, with retries) on their way to `closed`.

## 4. Endpoints

### 4.1 `GET /v1/health`

Returns `200 {status:"ok", version, policy_version}`. It needs no authentication.

### 4.2 `POST /v1/allocations`

Requests a JIT runner for a repository.

**Request body:**

```json
{
  "repository": {"owner": "vanpelt", "name": "sand"},
  "runner_name_prefix": "laptop-runner",
  "sand": {"version": "0.9.0", "network_policy_hash": "sha256:…", "vm_name": "laptop-runner"},
  "capabilities": {"admission_hook": true, "assignment_verifier": true, "oidc": false}
}
```

**`201` response:**

```json
{
  "allocation_id": "alc_01JDQ7Z6S8V4N3K2M1P0R9T8W7",
  "state": "registered",
  "nonce": "<43-char base64url, 32 bytes>",
  "created_at": "2026-11-27T05:00:00Z",
  "expires_at": "2026-11-27T05:15:00Z",
  "repository": {"id": 1473742157, "owner": "vanpelt", "name": "sand"},
  "runner": {"id": 34, "name": "sand-dev-laptop-3f9a1c2e", "labels": ["self-hosted","macOS","ARM64","sand"], "runner_group_id": 1, "ephemeral": true},
  "jit_config": "<base64; SECRET>",
  "admission": {"deadline_seconds": 60, "require_oidc": false, "oidc_audience": "sand-broker"},
  "policy_version": "pilot-1"
}
```

**Broker behaviour:**

1. Check the following, in order:
   - The session is valid.
   - The device is not revoked.
   - The repository is enabled in policy, and its id is resolved by the broker.
   - The device has no other allocation in `registered`, `assigned` or `admitted` (otherwise `409 allocation_outstanding`).
   - The rate limits allow the request.
   - The denial circuit breaker is closed (otherwise `429 circuit_open`).
2. **Demand check.** If the policy has `requireQueuedJob` and no queued run in the repository passes the policy's event, actor, workflow and ref checks, return `409 no_eligible_demand` with `retry_after_seconds`.
3. Call `POST /repos/{o}/{r}/actions/runners/generate-jitconfig` with:
   - `name`: `sand-<device_id>-<8 hex>`;
   - `runner_group_id`: 1 for user repos, or the group id from policy for org repos;
   - `labels`: from policy;
   - `work_folder`: `_work`.
4. Store `runner.id`, `runner.name` and the labels **returned** by GitHub. Reject the allocation, delete the runner and return `502`, if `ephemeral != true`.
5. Generate the nonce (32 bytes from a CSPRNG) and set the expiry to now plus `idleTTLSeconds` (900 by default).

**Rules for `jit_config`:**

- It is returned **only in the first 201**.
- Replaying the same `Idempotency-Key` returns `200` with the same allocation but **without** `jit_config`.
- A device that lost the config must release the allocation and request a new one.

**If the allocation expires** in `registered` (no job taken), the broker deletes the runner. This succeeds because the runner is idle, and the allocation goes to `expired`.

**Errors:**

| Code | Meaning |
| --- | --- |
| `400 invalid_request` | |
| `401` | |
| `403 repository_not_allowed` | |
| `409 allocation_outstanding` | |
| `409 no_eligible_demand` | |
| `422 idempotency_mismatch` | |
| `429 rate_limited` | |
| `429 circuit_open` | |
| `403 tier_precondition_failed` | The repository does not meet the Tier A preconditions (§4.2.1). |
| `502 github_error` | |
| `503 github_timeout` | GitHub (or App JWT signing) did not answer within 20 s. |
| `503 unavailable` | |

#### 4.2.1 Tier A preconditions

The job message (secrets and `GITHUB_TOKEN`) reaches the guest before the gate runs (ADR 0001, R1). A denied job is harmless only while the repository gives jobs nothing worth stealing. So before issuing an allocation the broker checks, cached for 5 minutes:

| Check | Required |
| --- | --- |
| `GET /repos/{o}/{r}/actions/secrets` `total_count` | 0 |
| `GET /repos/{o}/{r}/actions/organization-secrets` `total_count` | 0 (a 404 or 422 counts as 0 only on a user-owned repository) |
| `GET /repos/{o}/{r}/environments` `total_count` | 0 (environment secrets reach jobs that name the environment) |
| `GET /repos/{o}/{r}/actions/permissions/workflow` `default_workflow_permissions` | `read` |
| `GET /repos/{o}/{r}/actions/permissions/fork-pr-contributor-approval` `approval_policy` | `all_external_contributors` (R9) |

A check that cannot run (missing App permission, GitHub down) counts as failed. Policy `tierAPreconditions: enforce` (the default) refuses the allocation with `403 tier_precondition_failed`; `warn` (development only) allocates and audits `allocation.precondition`.

### 4.3 `GET /v1/allocations/{allocation_id}`

The host-side `AssignmentVerifier` polls this endpoint.

**Response:**

```json
{
  "allocation_id": "alc_…",
  "state": "assigned",
  "expires_at": "…",
  "runner": {"id": 34, "name": "sand-dev-laptop-3f9a1c2e"},
  "observed_job": {"id": 140863154515, "run_id": 46107413025, "run_attempt": 1, "status": "in_progress", "observed_at": "…"},
  "admitted_job": null,
  "decision": null,
  "observed_ok_at": "…"
}
```

- **`observed_job`** is the broker's *own* REST view of the job that holds `runner.id`. The broker finds it from `workflow_job` webhooks in production. The mock instead scans every page of `actions/runs?status=in_progress` and then each attempt's jobs, cached for 5 s. The mock also observes undecided allocations on its own 2 s tick, so assignment and `admission_timeout` do not depend on the device polling.
- It is `null` until the runner has taken a job.
- **`observed_ok_at`** is when the broker last completed an observation in which every GitHub call succeeded. A `null` `observed_job` means "nothing running" only while `observed_ok_at` keeps advancing. Before admission, the device's verifier destroys the VM when `observed_ok_at` has not advanced for its deadline (`assignment.unadmitted`, reason `observation_stale`). A rate-limited or failing GitHub therefore cannot hide a job that skipped the hook.
- **Owner check:** an allocation that belongs to another device returns `404`, not `403`.

### 4.4 `POST /v1/allocations/{allocation_id}/admissions`

The host relay calls this on behalf of the guest hook. It asks: *may the job that our runner just acquired run?*

**Request body:**

```json
{
  "nonce": "<from allocation>",
  "hints": {
    "repository_id": 1473742157,
    "run_id": 46107413025,
    "run_attempt": 1,
    "runner_name": "sand-dev-laptop-3f9a1c2e",
    "job_key": "smoke"
  },
  "oidc_token": null,
  "relay": {"received_at": "…", "vm_name": "laptop-runner"}
}
```

**Hint formats:**

| Field | Format |
| --- | --- |
| `repository_id`, `run_id`, `run_attempt` | Positive integers. |
| `runner_name` | `^[A-Za-z0-9._-]{1,64}$` |
| `job_key` | `^[A-Za-z_][A-Za-z0-9_-]{0,99}$`, or empty. It is informational only. |

**`200` response.** It is always `200` once the broker has *decided*, for both allow and deny:

```json
{
  "admission_id": "adm_…",
  "decision": "deny",
  "reasons": ["actor_not_owner", "triggering_actor_not_owner"],
  "job": {"id": 140863154515, "run_id": 46107413025, "run_attempt": 1, "workflow_path": ".github/workflows/spike-decoy.yml",
          "head_sha": "c905f1da…", "head_branch": "spike/job-admission", "event": "push",
          "actor_id": 17, "triggering_actor_id": 17, "labels": ["self-hosted","sand"]},
  "policy_version": "pilot-1",
  "decided_at": "…"
}
```

`job` is `null` when no job could be identified.

**Decision procedure.** All checks run, and every failing reason is reported.

1. **Allocation checks.**
   - The allocation belongs to the session's device. Otherwise `404`.
   - Its state is `registered` or `assigned`. Any other state gives `deny allocation_state`.
   - It has not expired (`allocation_expired`).
   - The nonce matches, compared in constant time (`nonce_mismatch`).
   - The hints are well formed (`hint_invalid`).
   - `hints.repository_id == allocation.repository.id` (`repository_mismatch`).
2. **Find the job.** Fetch `GET /repos/{o}/{r}/actions/runs/{run_id}/attempts/{run_attempt}/jobs?per_page=100`, all pages. Select the jobs with `runner_id == allocation.runner.id`.
   - If there are none, retry with 1 s backoff for up to `admissionWaitSeconds` (15 by default).
   - Still none after that: `job_not_found_for_runner`.
   - More than one: `multiple_jobs_for_runner`.
   - Status not `in_progress`: `job_not_in_progress`.
   - `runner_name` mismatch: `runner_name_mismatch`.
3. **Fetch the run attempt.** `GET /repos/{o}/{r}/actions/runs/{run_id}/attempts/{run_attempt}`.
4. **Apply the policy** (ADR §5):

   | Reason | Fails when |
   | --- | --- |
   | `repository_mismatch` | the run's repository id differs from the allocation's |
   | `fork_head` | `head_repository.id != repository.id` |
   | `event_not_allowed` | the event is not allowlisted |
   | `actor_not_user` | the actor or triggering actor is not `type: User` |
   | `actor_not_owner` | the actor id is not the owner id |
   | `triggering_actor_not_owner` | the triggering actor id is not the owner id |
   | `workflow_not_allowed` | `path` is not allowlisted |
   | `reusable_workflow_not_allowed` | `referenced_workflows` is non-empty |
   | `ref_not_allowed` | `head_branch` is not allowlisted |
   | `labels_mismatch` | the job's labels are not a subset of the runner's labels |
5. **OIDC.** If `require_oidc` is set, verify `oidc_token` against GitHub's JWKS (`iss`, `aud`, `exp`, `nbf`), then check `check_run_id == job.id`, `repository_id`, `run_id`, `run_attempt` and `runner_environment == self-hosted`.
   - Possible reasons: `oidc_required`, `oidc_invalid`, `oidc_claim_mismatch`.
   - The mock answers `oidc_unsupported` whenever its policy requires OIDC.
6. **Rate limit.** If the circuit breaker is open, the decision is `circuit_open`.
7. **GitHub failure.** Any failure talking to GitHub, including 403/429 rate limits and 5xx errors, gives `github_unavailable`. This is a **deny**.
8. **Record the outcome.**
   - **On allow:** set the state to `admitted`, set `admitted_job` and spend the nonce.
   - **On deny:** set the state to `denied`, spend the nonce, increment the device's denial counter, and start cleanup (§4.5).

**Retries and second admissions:**

| Situation | Result |
| --- | --- |
| Same `(allocation_id, run_id, run_attempt)` and same nonce, after a decision | Returns the stored decision, unchanged. This makes a relay retry idempotent. |
| A different `(run_id, run_attempt)` after a decision | `deny already_admitted` (or `allocation_state`). |

**Non-200 codes** mean that no decision was made, and the relay treats them as deny: `400`, `401`, `404`, `429 rate_limited`, `503`.

### 4.5 `POST /v1/allocations/{allocation_id}/release`

Sand calls this after the VM is destroyed, for every outcome. It is idempotent.

**Request body:**

```json
{"reason": "completed", "job_id": 140856307124, "detail": "provisioner exited"}
```

`reason` is one of `completed`, `denied`, `vm_failed`, `verifier_kill`, `shutdown`, `expired` or `unused`.

**`202` response:**

```json
{"state": "cleaning", "runner_deleted": false, "next_attempt_at": "…"}
```

`state` is `cleaning` or `closed`.

**Broker behaviour:**

1. Move the allocation to `cleaning`.
2. If the reason is `denied` and the policy sets `cancelDeniedRuns`, send `POST /repos/{o}/{r}/actions/runs/{run_id}/cancel`.
   - This needs the `actions: write` App permission. A 403 is logged, not fatal.
   - It cancels the *entire run*.
3. Send `DELETE /repos/{o}/{r}/actions/runners/{runner.id}`.
   - **On 422** (the runner is still assigned a job), retry with exponential backoff: 30 s doubling to a 5 min cap, for up to 6 hours. The 6 hours matches GitHub's default maximum job time.
   - **On 404**, treat the runner as already gone.
4. Move the allocation to `closed`.

**Orphan GC.** Every 5 minutes, and at broker start, the broker lists the repository's runners. It deletes any runner whose name starts with `sand-` that no live allocation owns.

### 4.6 `POST /v1/audit-events`

The device sends its own events in batches of up to 100.

- Request body: `{events:[AuditEvent…]}`.
- Response: `202 {accepted:n}`.
- The broker adds its own events, with `source: "broker"`, to the same store.

## 5. Audit event schema

```json
{
  "schema": "sand.audit.v1",
  "event_id": "UUID",
  "time": "2026-11-27T05:00:01Z",
  "source": "device | broker | relay",
  "type": "admission.denied",
  "level": "info | warning | error",
  "device_id": "dev-laptop",
  "allocation_id": "alc_…",
  "repository_id": 1473742157,
  "runner_id": 34,
  "run_id": 46107413025,
  "run_attempt": 1,
  "job_id": 140863154515,
  "decision": "deny",
  "reasons": ["workflow_not_allowed"],
  "policy_version": "pilot-1",
  "sand_version": "0.9.0",
  "fields": {"vm_name": "laptop-runner", "elapsed_ms": "1840"}
}
```

**Event types:**

| Area | Types |
| --- | --- |
| Device sessions | `device.session.created`, `device.session.denied` |
| Allocations | `allocation.created`, `allocation.refused` (with a reason code), `allocation.expired`, `allocation.assigned`, `allocation.precondition` (Tier A precondition failures, §4.2.1) |
| Admissions | `admission.allowed`, `admission.denied`, `admission.relay_error`, `admission.relay_rejected` (unauthenticated relay request; no kill), `assignment.unadmitted` (verifier: job seen without admission `admission_timeout`, broker observation stale `observation_stale`, guest `Runner.Worker` without admission `worker_unadmitted`, broker unreachable `broker_unreachable`), `assignment.mismatch` (verifier: observed job differs from admitted) |
| VM | `vm.killed` (with a `cause`) |
| Runners and runs | `runner.deregistered`, `runner.deregister_retry`, `runner.deregister_failed`, `run.cancelled`, `gc.runner_deleted` |

**Field rules:**

- `fields` holds strings only, with at most 32 keys and 512 bytes per value.
- **Never include:** `jit_config`, `nonce`, `session_token`, `oidc_token`, signatures, installation tokens, App JWTs, proxy credentials, or the free-text values `GITHUB_WORKFLOW`, `HEAD_REF` and commit messages.
- Workflow paths and branch names from **REST** are allowed, because GitHub has already validated them.

## 6. Cross-cutting rules

### 6.1 Idempotency

- `Idempotency-Key` (a UUID) is required on `POST /v1/allocations`, `/release` and `/audit-events`.
- The broker keeps `(device_id, key) → (request hash, response)` for 24 hours.
  - Same key with the same body returns the stored response, minus `jit_config`.
  - Same key with a different body returns `422 idempotency_mismatch`.
- Admissions are idempotent on `(allocation_id, run_id, run_attempt)`, as described in §4.4.

### 6.2 Nonce, expiry and replay

| Item | Rule |
| --- | --- |
| Challenge | 60 s, single use. |
| Session | 15 min. Revoked immediately if the device is revoked. |
| Allocation nonce | 32 bytes. Valid only for its allocation and only until its first decided admission. Compared in constant time. Never logged. |
| Allocation expiry (`expires_at`) | Applies while `registered`. Once `assigned`, the admission deadline applies instead: an observed job with no admission within `deadline_seconds` is denied by the broker with `admission_timeout`, and cleaned up. |
| Clock skew | The device must not depend on its own clock for any security decision. It only displays expiry times. |

### 6.3 Rate limits (per device; the defaults are policy settings)

| Limit | Default |
| --- | --- |
| Challenges | 10/min |
| Sessions | 10/h |
| Allocations | 30/h, with 1 outstanding at a time |
| Admissions | 10/min |
| Audit batches | 60/min |
| **Denial circuit breaker** | 6 denials in a rolling hour opens the circuit for 1 h. While it is open, every allocation returns `429 circuit_open` and the broker emits a warning event. |

A `429` response carries a `Retry-After` header and `error.retry_after_seconds`.

### 6.4 Errors

```json
{"error": {"code": "no_eligible_demand", "message": "human text, no secrets", "retry_after_seconds": 30}, "request_id": "…"}
```

### 6.5 Redaction

- **Sand side:**
  - `jit_config`, `nonce`, `session_token` and `oidc_token` are passed to the logger's `secrets:` list. They are never printed, even at debug level.
  - Secrets never travel as process arguments. `ps` shows every local user the arguments of the host's `sshpass`/`ssh` for as long as they run, and the runner's SSH session lasts the whole job. Sand writes `jit_config` to that SSH session's **stdin**; the guest command (`IFS= read -r`) moves it into `ACTIONS_RUNNER_INPUT_JITCONFIG`, detaches stdin and starts `run.sh`. The hook script, which embeds the nonce, is installed the same way (`cat >` from stdin).
  - **Remaining guest-side exposure:** the variable is in the *initial* environment of `run.sh`, `run-helper.sh` and `Runner.Listener` for the life of the job. The runner masks the value and removes it from its own environment (`CommandSettings.cs:110-139`), but that does not change the initial environment the kernel holds, so a same-user process in the guest can read it (`ps -wwE`). Before admission no workflow code runs; after admission, an admitted job's steps run as the same user and can read it. The JIT config is single-use and the runner is ephemeral, but a step that sends it out could register an impersonating runner elsewhere until the job ends. Closing this needs the patched-runner gate or a runner that reads the config from a file it deletes (ADR 0001 §8).
- **The guest hook** prints only fixed strings.
- **Broker side:** structured logs whitelist their fields. Request bodies are never logged.

## 7. Guest-to-host relay (Sand internal, not part of the broker API)

The relay runs per VM on host `127.0.0.1:<ephemeral>`, reached from the guest as `127.0.0.1:3129` through `ssh -R`.

- **Request:** `POST /v1/admission` with body `{allocation_id, nonce, hints}`. The body is at most 4 KiB and arrives on a single connection.
- **Response:** `200` with the plain-text body `allow` or `deny`. There is nothing else.
- **Authentication first.** The relay requires `Content-Type: application/json`, a parsable body of at most 4 KiB, and an `allocation_id` and `nonce` that match the allocation it holds (constant time). A request that fails any of these gets `deny` (415, 400 or 403) and an `admission.relay_rejected` audit event, but **does not kill the VM and does not use up the admission**: any local process (or a browser page sending a no-cors POST) can reach the loopback port, and it must not be able to destroy the VM.
- **One admission per VM.** After the nonce matched, the first request is forwarded; any later request gets `deny`.
- **Timeouts nest:** broker REST wait (policy, at most 30 s) < relay → broker call (45 s) < hook `curl --max-time` (50 s) < verifier deadline (at least 60 s). A slow but legitimate admission is never cut off by an outer layer first.
- **On anything but an allow** (after the nonce matched), the relay records the kill, answers `deny` at once, and runs the host kill path (cancel provisioning, destroy the VM, release) in its own task. The hook gets its answer and kills the runner without waiting for the VM teardown.

## 8. GitHub App permissions used by the broker

| Permission | Needed for | Required? |
| --- | --- | --- |
| Administration: write | JIT config, runner delete and list | Yes |
| Actions: read | runs, attempts, jobs | Yes |
| Metadata: read | | Yes |
| Actions: write | `cancelDeniedRuns` | Optional |
| Secrets: read | Tier A precondition: repository and organization secret counts | Yes under `tierAPreconditions: enforce` |
| Administration: read | Tier A precondition: default workflow permissions and fork-PR approval (covered by Administration: write) | Yes |
| Environments: read | Tier A precondition: environment count | Yes under `enforce` |
