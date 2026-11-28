import Foundation

/// Host-side defense in depth (ADR 0001 §3.8): polls the broker's view of the
/// job our runner holds and kills the VM when a job runs without an admission,
/// a different job than the admitted one runs, or the allocation was denied or
/// expired. Works even when the guest hook was skipped or tampered with.
struct AssignmentVerifier: Sendable {
    typealias Sleeper = @Sendable (TimeInterval) async throws -> Void

    let controller: AdmissionController
    let broker: BrokerClienting
    let deadlineSeconds: TimeInterval
    var preAdmissionInterval: TimeInterval = 5
    var postAdmissionInterval: TimeInterval = 30
    var now: @Sendable () -> Date = Date.init
    var sleep: Sleeper = { try await Task.sleep(nanoseconds: UInt64(max(0, $0) * 1_000_000_000)) }
    var warn: @Sendable (String) -> Void = { _ in }

    /// Polls until cancelled or the VM was killed.
    func run() async {
        let allocationId = controller.allocation.allocationId
        var lastContact = now()
        var firstObserved: (id: Int, at: Date)?
        while !Task.isCancelled {
            if await controller.wasKilled { return }
            let admitted = await controller.admittedJob
            do {
                let status = try await broker.status(allocationId: allocationId)
                lastContact = now()
                if let kill = evaluate(status, admitted: admitted, firstObserved: &firstObserved) {
                    await controller.kill(kill)
                    return
                }
            } catch is CancellationError {
                return
            } catch {
                if admitted == nil, now().timeIntervalSince(lastContact) > deadlineSeconds {
                    await controller.kill(.init(type: "assignment.unadmitted", reasons: ["broker_unreachable"], jobId: nil, runId: nil, runAttempt: nil, byVerifier: true))
                    return
                }
                warn("assignment verifier: broker status failed: \(error)")
            }
            let interval = admitted == nil ? preAdmissionInterval : postAdmissionInterval
            do {
                try await sleep(interval)
            } catch {
                return
            }
        }
    }

    /// One poll's decision. Pure apart from `firstObserved` bookkeeping.
    func evaluate(_ status: AllocationStatus, admitted localAdmitted: JobRef?, firstObserved: inout (id: Int, at: Date)?) -> AdmissionController.Kill? {
        let observed = status.observedJob
        func kill(_ type: String, _ reasons: [String], _ job: JobRef?) -> AdmissionController.Kill {
            .init(type: type, reasons: reasons, jobId: job?.id, runId: job?.runId, runAttempt: job?.runAttempt, byVerifier: true)
        }
        switch status.state {
        case .denied:
            return kill("admission.denied", ["allocation_denied"], observed)
        case .expired:
            return kill("allocation.expired", ["allocation_expired"], observed)
        case .failed, .closed, .released, .cleaning:
            return kill("assignment.mismatch", ["allocation_\(status.state.rawValue)"], observed)
        default:
            break
        }
        let admitted = localAdmitted ?? status.admittedJob
        if let admitted, let brokerAdmitted = status.admittedJob, brokerAdmitted.id != admitted.id {
            return kill("assignment.mismatch", ["admitted_job_mismatch"], brokerAdmitted)
        }
        guard let observed else { return nil }
        if let admitted {
            return observed.id == admitted.id ? nil : kill("assignment.mismatch", ["observed_job_mismatch"], observed)
        }
        if firstObserved?.id != observed.id {
            firstObserved = (observed.id, now())
        }
        if let first = firstObserved, now().timeIntervalSince(first.at) > deadlineSeconds {
            return kill("assignment.unadmitted", ["admission_timeout"], observed)
        }
        return nil
    }
}
