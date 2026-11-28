import Foundation

/// The admission timeouts, ordered so a slow but legitimate admission is never
/// cut off by an outer layer first (ADR 0001 §3.8):
/// broker REST wait (policy, ≤ 30 s) < relay → broker call (45 s)
/// < hook curl (50 s) < verifier deadline (≥ 60 s).
enum AdmissionTimeouts {
    static let maxBrokerWaitSeconds = 30
    static let relaySeconds: TimeInterval = 45
    static let hookCurlSeconds = 50
    static let minimumVerifierDeadline: TimeInterval = 60

    /// The deadline the verifier enforces: the broker's, but never shorter
    /// than the relay and hook timeouts allow for.
    static func verifierDeadline(_ brokerDeadline: TimeInterval) -> TimeInterval {
        max(brokerDeadline, minimumVerifierDeadline)
    }
}

/// Host-side defense in depth (ADR 0001 §3.8): polls the broker's view of the
/// job our runner holds and kills the VM when a job runs without an admission,
/// a different job than the admitted one runs, or the allocation was denied or
/// expired. Works even when the guest hook was skipped or tampered with.
///
/// Before admission, "no job observed" is trusted only while the broker's
/// observation stays fresh (`observed_ok_at` keeps advancing): a broker whose
/// GitHub calls fail or are rate limited cannot hide a running job. An
/// optional guest probe (`pgrep` for `Runner.Worker` over SSH) adds a check
/// that does not depend on GitHub at all.
struct AssignmentVerifier: Sendable {
    typealias Sleeper = @Sendable (TimeInterval) async throws -> Void
    /// True when a `Runner.Worker` process runs in the guest (a job started).
    typealias WorkerProbe = @Sendable () async throws -> Bool

    let controller: AdmissionController
    let broker: BrokerClienting
    let deadlineSeconds: TimeInterval
    var preAdmissionInterval: TimeInterval = 5
    var postAdmissionInterval: TimeInterval = 30
    var workerProbe: WorkerProbe?
    var now: @Sendable () -> Date = Date.init
    var sleep: Sleeper = { try await Task.sleep(nanoseconds: UInt64(max(0, $0) * 1_000_000_000)) }
    var warn: @Sendable (String) -> Void = { _ in }

    var effectiveDeadline: TimeInterval { AdmissionTimeouts.verifierDeadline(deadlineSeconds) }

    /// Bookkeeping carried between polls.
    struct State: Sendable {
        var firstObserved: (id: Int, at: Date)?
        /// Local time the broker's `observed_ok_at` last advanced (or the start).
        var lastFresh: Date
        var lastObservedOkAt: Date?
        var workerSeenAt: Date?
    }

    /// Polls until cancelled or the VM was killed.
    func run() async {
        let allocationId = controller.allocation.allocationId
        var lastContact = now()
        var state = State(lastFresh: now())
        while !Task.isCancelled {
            if await controller.wasKilled { return }
            let admitted = await controller.admittedJob
            do {
                let status = try await broker.status(allocationId: allocationId)
                lastContact = now()
                if let kill = evaluate(status, admitted: admitted, state: &state) {
                    await controller.kill(kill)
                    return
                }
            } catch is CancellationError {
                return
            } catch {
                if admitted == nil, now().timeIntervalSince(lastContact) > effectiveDeadline {
                    await controller.kill(Self.kill("assignment.unadmitted", ["broker_unreachable"], nil))
                    return
                }
                warn("assignment verifier: broker status failed: \(error)")
            }
            if admitted == nil, let workerProbe, await controller.admittedJob == nil {
                if let kill = await probeWorker(workerProbe, state: &state) {
                    await controller.kill(kill)
                    return
                }
            }
            let interval = admitted == nil ? preAdmissionInterval : postAdmissionInterval
            do {
                try await sleep(interval)
            } catch {
                return
            }
        }
    }

    /// The GitHub-independent check: a Worker running with no admission past
    /// the deadline means the hook did not run (or did not gate) this job.
    func probeWorker(_ probe: WorkerProbe, state: inout State) async -> AdmissionController.Kill? {
        let running: Bool
        do {
            running = try await probe()
        } catch is CancellationError {
            return nil
        } catch {
            warn("assignment verifier: guest worker probe failed: \(error)")
            return nil
        }
        guard running else {
            state.workerSeenAt = nil
            return nil
        }
        if await controller.admittedJob != nil { return nil }
        let seen = state.workerSeenAt ?? now()
        state.workerSeenAt = seen
        if now().timeIntervalSince(seen) > effectiveDeadline {
            return Self.kill("assignment.unadmitted", ["worker_unadmitted"], nil)
        }
        return nil
    }

    /// One poll's decision. Pure apart from the `state` bookkeeping.
    func evaluate(_ status: AllocationStatus, admitted localAdmitted: JobRef?, state: inout State) -> AdmissionController.Kill? {
        let observed = status.observedJob
        switch status.state {
        case .denied:
            return Self.kill("admission.denied", ["allocation_denied"], observed)
        case .expired:
            return Self.kill("allocation.expired", ["allocation_expired"], observed)
        case .failed, .closed, .released, .cleaning:
            return Self.kill("assignment.mismatch", ["allocation_\(status.state.rawValue)"], observed)
        default:
            break
        }
        let admitted = localAdmitted ?? status.admittedJob
        if let admitted, let brokerAdmitted = status.admittedJob, brokerAdmitted.id != admitted.id {
            return Self.kill("assignment.mismatch", ["admitted_job_mismatch"], brokerAdmitted)
        }
        if let admitted {
            guard let observed else { return nil }
            return observed.id == admitted.id ? nil : Self.kill("assignment.mismatch", ["observed_job_mismatch"], observed)
        }
        // Before admission: a missing observation counts only while fresh.
        if let okAt = status.observedOkAt, okAt != state.lastObservedOkAt {
            state.lastObservedOkAt = okAt
            state.lastFresh = now()
        }
        if let observed {
            if state.firstObserved?.id != observed.id {
                state.firstObserved = (observed.id, now())
            }
            if let first = state.firstObserved, now().timeIntervalSince(first.at) > effectiveDeadline {
                return Self.kill("assignment.unadmitted", ["admission_timeout"], observed)
            }
        }
        if now().timeIntervalSince(state.lastFresh) > effectiveDeadline {
            return Self.kill("assignment.unadmitted", ["observation_stale"], observed)
        }
        return nil
    }

    static func kill(_ type: String, _ reasons: [String], _ job: JobRef?) -> AdmissionController.Kill {
        .init(type: type, reasons: reasons, jobId: job?.id, runId: job?.runId, runAttempt: job?.runAttempt, byVerifier: true)
    }

    /// The guest command behind the worker probe. `[.]` keeps the pattern from
    /// matching the probing shell's own command line.
    static let workerProbeCommand = "if /usr/bin/pgrep -f 'bin/Runner[.]Worker' >/dev/null 2>&1; then echo SAND_WORKER_UP; else echo SAND_WORKER_DOWN; fi"

    static func parseWorkerProbe(_ output: String) throws -> Bool {
        if output.contains("SAND_WORKER_UP") { return true }
        if output.contains("SAND_WORKER_DOWN") { return false }
        throw BrokerClientError.invalidResponse
    }
}
