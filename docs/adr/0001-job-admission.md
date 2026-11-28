# ADR 0001: Job admission and owner attribution

- **Status:** Proposed (pilot scope). It must be accepted before automatic scheduling on any employee Mac.
- **Date:** 2026-11-27
- **Relates to:** `docs/enterprise-plan.md` §6 (critical job-binding limitation), §7, §8, §11 Phases 2 and 3, §12 tasks 3 and 5, §13 Q2 and Q3; `docs/broker-api.md`; `docs/network-isolation.md`.
- **Evidence:**
  - Live spike on vanpelt/sand: branch `spike/job-admission` (commits 5cc3de4..9758732), runner 2.338.2.
  - Source reading of actions/runner v2.338.0 (HEAD 4812b901).

## 1. Context

Sand registers an ephemeral GitHub Actions runner inside a fresh Tart VM on the owner's Mac. We want a job to run there automatically only when the device owner caused that specific job, the job comes from an approved workflow and ref, and the job is in an approved tier.

GitHub does not let a runner choose its job:

- The JIT config API (`POST /repos/{o}/{r}/actions/runners/generate-jitconfig`) takes only `name`, `runner_group_id`, `labels` and `work_folder`. It has no job id.
- The service picks the job and sends the runner an opaque reference. The runner acquires the job (`src/Runner.Listener/Runner.cs:708-752`).
- From then on the job belongs to that runner. A rejection can only happen after acquisition, and a rejected job fails. It never goes back to the queue.

So admission has two parts:

1. **Do not register a runner without reason.**
2. **After acquisition, before any workflow-controlled code runs, decide whether the acquired job may run, and destroy the VM if not.**

## 2. Evidence summary

| # | Finding | Source |
| --- | --- | --- |
| E1 | **A unique label does not bind a runner to a job.** A runner with labels `[self-hosted, macOS, ARM64, sand, sand-spike-<nonce>]` was given the generic `[self-hosted, sand]` decoy in cycle c4, and the nonce-targeted job in c3 and c5. There was no FIFO order and no preference for the more specific match. | live, cycles c3 to c5 |
| E2 | **A job-started hook that exits 1 fails open.** With the hook at exit 1, these still ran: "Pre Run pre-probe" (a remote action's `pre:`), the `if: always()` step, and "Post Run pre-probe". The docs claim the job "will not run". | live, job 140861510284; `JobExtension.cs:304-313`, `StepsRunner.cs:202-236`, `ActionManifestManager.cs:458,480` |
| E2b | **Blocking in the hook while the host destroys the VM stops all workflow code.** Steps 3 to 6 stayed `pending` and no step log was uploaded. Side effects: the job stayed `in_progress` until `timeout-minutes` plus about 5 minutes, then ended `cancelled`. `DELETE runner` returned 422 ("currently running a job") until then. | live, job 140863154515 |
| E3 | **Re-runs keep the same values.** A re-run keeps `run_id`, `head_sha` and `workflow_sha`, increments `run_attempt` and creates a new job id. `actor` and `triggering_actor` come from REST `runs/{id}/attempts/{n}`. A re-run by a different user was **not tested** (only one account was available). | live, run 46106880191 |
| E4 | **REST shows the assignment before the hook starts.** REST `started_at` comes 1 to 2 s before the hook starts. A host poller saw `in_progress` with our `runner_name`/`runner_id` within 1.2 to 2.1 s of hook start. | live, 4 jobs |
| E5 | **The workflow cannot change the hook.** The hook path comes from the runner's `.env` (`Program.cs:172-199`), which Sand writes, and it overrides the OS environment. Job-level `env:` (`FOO`, `BASH_ENV`, `ACTIONS_RUNNER_HOOK_JOB_STARTED`) did not reach the hook. | live; `JobHookProvider.cs:74` |
| E6 | **What the hook can see.** `GITHUB_TOKEN`, `ACTIONS_RUNTIME_TOKEN` and the cache/results URLs are absent from the hook environment. `ACTIONS_ID_TOKEN_REQUEST_*` is present only when the job grants `id-token: write`. | live |
| E7 | **What has already happened when the hook runs:** the job message (secrets plus job token) is in the guest's `Runner.Worker` memory, the "Set up job" log has been uploaded, action tarballs are in `_work/_actions`, and `event.json` is on disk. No step, `pre:` script or checkout has run. | live and source (`Worker.cs:62-96`, `JobExtension.cs:301`) |
| E8 | **The current repo has no extra protections.** vanpelt/sand is a public, user-owned repo. It has only runner group 1 "Default", no workflow restrictions, and fork-PR approval set to `first_time_contributors`. | read-only REST |

## 3. Decision

For the pilot, Sand admits jobs with **broker-issued JIT runners plus a blocking job-started gate that the host enforces**. The decision is made from GitHub's REST view of which job our `runner_id` acquired. The hook's own claims are never used as evidence.

1. **Credentials stay with the broker.**
   - Sand holds no GitHub App key in broker mode. It authenticates as a device (challenge and response) and asks the broker for an *allocation*.
   - The broker mints a repository-scoped, ephemeral JIT config. It records `runner.id`, `runner.name`, a 256-bit single-use nonce, `expires_at` and the policy version.
   - At most one allocation is outstanding per device.
2. **Demand first.**
   - The broker issues an allocation only if at least one queued run in that repo passes the admission policy (`409 no_eligible_demand` otherwise).
   - This is a heuristic that cuts down idle registrations. It is **not** a binding: by E1, the runner may still be given a different job.
3. **Sand installs the hook; workflow code cannot.**
   - Before `run.sh`, Sand writes `~/.sand/hooks/job-started.sh` (mode 0555, outside `actions-runner`, nonce embedded).
   - It also writes `ACTIONS_RUNNER_HOOK_JOB_STARTED=<absolute path>` into `~/actions-runner/.env`. This happens whether or not egress isolation is enabled.
4. **The hook blocks and asks the host.**
   - It sends `{allocation_id, nonce, hints:{repository_id, run_id, run_attempt, runner_name, job_key}}` to a per-VM host **admission relay**. The relay listens on guest `127.0.0.1:3129`, which is an SSH reverse tunnel to a loopback listener on the host.
   - The hook sends only these fixed-format values, after checking each against a regex. It never echoes them.
   - The relay adds the device session and calls `POST /v1/allocations/{id}/admissions`.
5. **The broker decides from GitHub REST, not from the hints.**
   - It fetches `runs/{run_id}/attempts/{attempt}` and that attempt's jobs.
   - It requires **exactly one** job whose `runner_id == allocation.runner.id` (and `runner_name` matches) with status `in_progress`. It waits up to 15 s for REST to catch up (E4).
   - It applies the policy (§5) to that job and its run attempt, and records the job id.
   - It admits at most one job per allocation. The nonce is single-use.
6. **Allow means exit 0.** The hook prints the fixed string `sand: job admitted` and exits 0.
7. **Everything else means the VM is destroyed.** This covers deny, error, timeout and an unreachable relay.
   - The relay answers `deny`, and the host immediately cancels provisioning, destroys the VM and emits `admission.denied` with the job id and reason codes. It then calls `POST /v1/allocations/{id}/release {reason: denied}`.
   - Independently, the hook runs `pkill -KILL` on `Runner.Listener` and `Runner.Worker` (each `|| true`) and then sleeps forever. **The hook never exits non-zero** (E2).
   - The hook runs under `set +e`, because the runner starts `.sh` hooks with `bash -e`, and a failing `pkill` under `-e` would end the script with an error, which fails open.
8. **The host also watches without the hook (defense in depth).**
   - A host `AssignmentVerifier` polls `GET /v1/allocations/{id}`. The broker reports the job it observes for our `runner_id`.
   - The host destroys the VM in three cases:
     - a job is observed but no admission arrives within 30 s;
     - the observed job id differs from the admitted job id;
     - the allocation is `expired` or `denied`.
   - This covers a hook that was skipped or tampered with, at the cost of a bounded exposure window.
9. **Cleanup is idempotent and retried.**
   - The broker deletes the runner by id. On 422 (job still assigned) it retries with backoff, and a periodic GC deletes orphaned runners that carry the broker's name prefix.
   - Cancelling a denied run needs `actions: write` and cancels the *whole run*, so it is opt-in and off by default.

A **local mock broker** (`sand broker mock`) implements the same contract for development. It holds the App key on the developer's own Mac and is never used for enterprise endpoints.

## 4. Alternatives considered

| Option | Why not (for the pilot) |
| --- | --- |
| Unique label per allocation as the binding | Disproved live (E1). It only helps if the runner has *no* generic labels and every workflow targets the nonce. That fits only a broker-dispatched `workflow_dispatch` flow, so it is kept as a future hardening mode (§8). |
| Hook exits 1 on deny | Fails open (E2): `pre:` scripts, `always()` steps and `post:` scripts run. |
| Guest calls the broker directly through the egress proxy | The guest would need broker credentials or a bearer nonce good for a network call. The host would not learn the verdict, and only the host can destroy the VM. A loopback or private broker is also refused by `DestinationGuard`. The host relay keeps device credentials out of the guest. |
| Trust the hook's `GITHUB_*` values | They are partly workflow-controlled (`HEAD_REF`, `WORKFLOW`, event payload), and a compromised guest can forge all of them. They are used only as lookup hints. |
| OIDC token from the hook as the primary evidence | It requires `id-token: write` in every workflow and has no `triggering_actor` claim. It is kept as an optional, stronger binding (`check_run_id == job.id`) for higher tiers. The contract defines it; the mock does not implement it in this iteration. |
| Patched runner that validates between `GetJobMessageAsync` (`Runner.cs:752`) and `jobDispatcher.Run` (`Runner.cs:780`) | This is the only stock-free way to gate *before* secrets reach the Worker and before action download. The cost is maintaining a fork. It is the chosen fallback for any tier that has secrets (§8). |
| Runner groups with "selected workflows" | They do not exist for user-owned repos (E8). Where the org plan supports them, they should be used in addition to this gate. |

## 5. Admission policy (pilot, Tier A only)

A job is admitted only if **all** of the following hold. They are evaluated on REST data, using immutable numeric ids.

1. **Allocation:**
   - The allocation exists, belongs to the calling device, is in state `registered` and has not expired.
   - The nonce matches (constant-time comparison).
   - No job has been admitted on it yet.
2. **Repository:** `run.repository.id == allocation.repository_id == hints.repository_id`, and `run.head_repository.id == run.repository.id` (no fork heads).
3. **Job binding:**
   - Exactly one job in `runs/{run_id}/attempts/{run_attempt}/jobs` has `runner_id == allocation.runner.id`.
   - That job's status is `in_progress`, its `run_attempt` equals the hint, and its `labels` are a subset of the registered runner labels.
4. **Event:** `run.event` is `push` or `workflow_dispatch`.
5. **Attribution:**
   - `run_attempt.actor.id == owner.id` **and** `run_attempt.triggering_actor.id == owner.id`.
   - Both have `type == "User"`.
   - Ids are always taken from the **attempt** endpoint, never from the plain run endpoint, which describes the latest attempt.
6. **Workflow:** `run.path` is in the policy's workflow allowlist, and `run.referenced_workflows` is empty, because reusable workflows are not covered by this pilot.
7. **Ref:** `run.head_branch` matches the ref allowlist (exact name or `prefix/*`).
8. **Optional, when the policy requires OIDC:** a valid GitHub OIDC token with `aud == "sand-broker"`, `check_run_id == job.id`, and matching `repository_id`, `run_id`, `run_attempt`, plus `runner_environment == "self-hosted"`.
9. **Rate limits:** the device's denial circuit breaker is closed (§6.4 of the API contract).

**GitHub unavailable:** when GitHub REST cannot be reached or rate-limits the broker, the result is **deny** (`github_unavailable`). The policy never fails open.

### Supported event types for the pilot

| Event | Admitted? | Notes |
| --- | --- | --- |
| `push` to an allowlisted branch, pushed by the owner | Yes | `actor` is the pusher, not the commit author. Commits authored by others but pushed by the owner are admitted. This is a deliberate, documented choice. |
| `workflow_dispatch` by the owner on an allowlisted ref | Yes | |
| Owner re-run of an owner-caused run (any attempt) | Yes | Both `actor` and `triggering_actor` must be the owner. |
| Re-run by the owner of someone else's run | No | `actor != owner`. |
| Re-run by someone else of the owner's run | No | `triggering_actor != owner`. Untested live, because a second account is needed. |
| `pull_request`, `pull_request_target`, `merge_group`, `schedule`, `workflow_run`, `repository_dispatch`, `issue_comment`, `release`, others | No | The actor is ambiguous or not attributable to a fresh owner action. |
| Any bot actor (`type == "Bot"`) | No | |
| Tag pushes | Not distinguished | REST `head_branch` holds the tag name. The pilot allowlist must name branches that cannot collide with tag names. Residual R7. |

## 6. Threat analysis

| Threat | Outcome under this design |
| --- | --- |
| **Scheduling race:** another eligible or ineligible job matching `[self-hosted, sand]` is queued alongside the intended one | The runner may take either (E1). If the taken job fails the policy, the VM is destroyed before any step runs. The intended job stays queued, and Sand allocates again after cleanup (demand check). Not prevented: the misrouted job is consumed and fails. A flood of matching jobs is limited by the denial circuit breaker. That turns it into a denial of service, not code execution (R4). |
| **Malicious matching-label job** from another collaborator's push, an unlisted workflow, a fork PR or a bot | Denied by attribution, event or workflow checks. Killed in "Set up runner", before checkout, `pre:` and steps (E2b). Its secrets and token were in guest memory and were destroyed with the VM (R1). |
| **Re-run** | Same `run_id`, new attempt and new job id. The attempt endpoint gives `triggering_actor`, and both ids must be the owner's. A re-run by another user is denied, but that is untested live (R6). |
| **Edited workflow** | Another user's edit reaches us only through their push, or a PR that the event check denies. A push by another user fails attribution. An edit pushed by the owner, to an allowlisted path and branch, is **admitted**: Tier A trusts owner-triggered changes. Content-digest leases are Phase 4 (§7 of the plan). A renamed or copied workflow fails the path allowlist. |
| **Forged hints** from a compromised guest or a malicious image | Hints are only lookup keys. If they point at a run where our `runner_id` holds no job, the result is `job_not_found_for_runner`, which means deny. They cannot make the broker approve a job that our runner does not hold. |
| **Nonce replay or a second admission** | The nonce is single-use and bound to one allocation and one `runner_id`. Each VM has its own relay. A second admission for a different job is denied (`already_admitted`). An identical retry returns the stored verdict. |
| **Hook bypass by workflow code** | Impossible before the hook runs: no workflow code executes before "Set up runner" (E7). `.env` overrides the OS environment, and job `env:` does not reach the hook (E5). |
| **Hook bypass by a compromised guest image** (malware in the golden image skips the hook or fakes allow) | Not prevented by the hook. The `AssignmentVerifier` destroys the VM when the broker sees our runner on a job with no admission (≤ 30 s plus poll interval), or on a different job. The exposure is bounded, not zero (R3). Mitigation: signed, digest-pinned golden images and a fresh clone per job. |
| **Hook output injection** | The hook prints only fixed strings. Untrusted values never reach stdout, where workflow-command processing would act on them. |
| **Exit-code bypass** | The hook never exits non-zero on deny. It uses `set +e` and `|| true` on every kill. Unit tests assert this. |
| **Stolen device key or session** | The holder can request allocations for policy repositories and receive the owner's admitted jobs on a machine that is not the owner's. Limited by short sessions (15 min), one outstanding allocation, per-device rate limits, revocation, and later Secure Enclave keys and Jamf posture (Phase 2). Residual R5. |
| **Denied run left `in_progress`** | Expected (E2b). `release` retries `DELETE runner` and GC removes orphans. Optional `cancelDeniedRuns` cancels the whole run, which is visible to and disruptive for the run's author. Off by default. |
| **Compromised host (root)** | Out of scope for the gate (§3 of the plan). A root attacker can admit anything locally. The broker still limits issuance to policy repositories and audits every allocation and admission. |

## 7. Guarantees and residual risks

**Guaranteed (stock runner, with the gate implemented as specified and an uncompromised golden image):**

- **G1:** No step, checkout, `pre:` or `post:` script, or `always()` step from a non-admitted job executes in the VM.
- **G2:** Every admitted job is the unique job that our allocation's `runner_id` holds in REST. Its run attempt passed the policy on actor ids, triggering-actor ids, event, workflow path, ref and repository id.
- **G3:** At most one job per allocation, one allocation per device, and no App key on the endpoint in broker mode.
- **G4:** Every allocation, admission (allow or deny, with job id and reason codes), kill and deregistration is audited.
- **G5:** Any failure (broker, GitHub, relay, tunnel or timeout) results in no execution.

**Residual risks (must be accepted by Security for the pilot):**

| Id | Risk |
| --- | --- |
| R1 | **The job is delivered before the gate.** The job message, including the secrets GitHub includes and the job's `GITHUB_TOKEN`, is in the guest's Worker memory before the hook runs. Action tarballs are already downloaded through the egress proxy, and `event.json` is on disk. Nothing executes them. Consequence: **the pilot is Tier A only.** The repositories must have no repo or org secrets beyond `GITHUB_TOKEN` that are available to the job, and must use a read-only default token. Any tier with secrets needs the patched-runner gate (§8) or external OIDC-brokered secrets. Which secrets the service includes is unconfirmed. |
| R2 | **A misrouted job is consumed.** It fails, or sits `in_progress` until its timeout, and is not requeued. |
| R3 | **A compromised golden image can skip the hook.** Detection is bounded by the verifier's grace period. |
| R4 | **Denial of service** by queueing matching jobs, up to the circuit-breaker limit. |
| R5 | **Device credential theft** lets the holder receive the owner's admitted jobs until revocation. |
| R6 | **Actor semantics** for a re-run by a different user, `schedule`, `merge_group` and fork PRs are unverified live. Those events are denied regardless. |
| R7 | **Tags versus branches** are not distinguished by `head_branch`. |
| R8 | **Owner-pushed content is not pinned.** A changed workflow or a mutable action is admitted (Phase 4). |
| R9 | **The public repo** (vanpelt/sand) lets returning fork contributors run without approval, which feeds R2 and R4. Set fork-PR approval to `all_external_contributors`, or test enterprise flows in a private repo. |

## 8. Fallbacks

These apply if the gate cannot be trusted, for example if acceptance tests fail or Security rejects R1 or R3.

1. **Patched runner gate (preferred hardening).**
   - Sand already ships a host-verified runner tarball with self-update disabled.
   - The patch calls the same admission endpoint between job acquisition and Worker start (`Runner.cs:752` to `780`). That is before secrets reach any Worker and before action downloads.
   - A deny makes the Listener exit without dispatching.
   - It is required for Tier B.
2. **Exclusive nonce labels with broker dispatch.**
   - The runner is registered with *only* `[sand-<nonce>]`, with no default labels. This needs E5a (JIT default-label behaviour) to be verified.
   - Eligible workflows take `runs-on: ${{ inputs.runner_label }}`, and the broker triggers them with `workflow_dispatch`.
   - Push workflows are then never served automatically.
3. **Platform restrictions.** On org repos, use a dedicated runner group restricted to selected workflows on protected refs (where the plan supports it), private repos only.
4. **No automatic scheduling.** The owner starts `sand run` attended, local mode only. This is the state today.

## 9. Consequences

- Sand gains a broker provisioner mode, a host admission relay (a second reverse tunnel), a guest hook, an assignment verifier and audit events. Local App-key mode is unchanged and has no gate.
- The pilot is limited to Tier A, owner `push`/`workflow_dispatch`, allowlisted workflow paths and branches, and no reusable workflows.
- Denied jobs show up to their authors as failed or timed-out runs.

## 10. Acceptance tests (live, before the ADR moves to Accepted)

1. **Decoy denied.**
   - Run `spike-decoy.yml`, which is not allowlisted and uses the pre-probe action plus an `always()` step, with the broker mock.
   - Expect a deny with reason `workflow_not_allowed`, steps after "Set up runner" `pending`, no `SPIKE-MARKER` in any log, the VM destroyed in under 5 s, and an audit line carrying the job id.
2. **Target admitted.** Run an allowlisted owner `push` and expect allow and success.
3. **Race.** Queue the decoy and target together over three or more cycles. Every decoy is denied, every target admitted, and no marker appears.
4. **Re-run.** An owner re-run is allowed. Setting the mock owner id to a different value denies with `actor_not_owner` and `triggering_actor_not_owner`.
5. **Broker down at hook time.** The VM is destroyed and no step runs (fail closed).
6. **Hook missing.** Use a test-only build that omits the `.env` line. The verifier kills the VM within the grace period, and the audit records `assignment.unadmitted`.
7. **Cleanup.** After all of the above, `tart list` shows no `sand-*` clones, and repo runners are 0 once the denied jobs have timed out or GC has run.

## 11. Remaining experiments

- E5a: does JIT auto-add read-only labels?
- A re-run by a second account.
- `workflow_job` runner fields on `queued`.
- The runner-lost timing when a cancel is issued.
- Which secrets are present in the job message.
