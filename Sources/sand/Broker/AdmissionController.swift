import Foundation

/// Per-allocation state shared by the admission relay, the assignment verifier
/// and the runner: the admitted job, whether (and why) the VM was killed, and
/// the release reason. The kill path runs at most once, whichever side fires first.
actor AdmissionController {
    struct Kill: Sendable, Equatable {
        /// Audit type: `admission.denied`, `admission.relay_error`,
        /// `assignment.unadmitted`, `assignment.mismatch`, `allocation.expired`.
        let type: String
        let reasons: [String]
        let jobId: Int?
        let runId: Int?
        let runAttempt: Int?
        /// Set by the relay (a broker verdict) vs. the host verifier.
        let byVerifier: Bool
    }

    typealias KillAction = @Sendable (_ cleanupReason: String) async -> Void

    let allocation: Allocation
    let deviceId: String
    private let audit: AdmissionAudit
    private let killAction: KillAction
    private(set) var admittedJob: JobRef?
    private(set) var admittedDecision: AdmissionDecision?
    private(set) var kill: Kill?
    private var completed = false
    private var released = false

    init(allocation: Allocation, deviceId: String, audit: AdmissionAudit, kill: @escaping KillAction) {
        self.allocation = allocation
        self.deviceId = deviceId
        self.audit = audit
        self.killAction = kill
    }

    var wasKilled: Bool { kill != nil }

    func recordAllow(_ decision: AdmissionDecision) {
        guard kill == nil, admittedJob == nil, let job = decision.job else { return }
        admittedJob = JobRef(id: job.id, runId: job.runId, runAttempt: job.runAttempt, status: "in_progress", observedAt: nil)
        admittedDecision = decision
        audit.emit(event("admission.allowed", level: .info, jobId: job.id, runId: job.runId, runAttempt: job.runAttempt, decision: .allow, reasons: [], fields: [
            "workflow_path": job.workflowPath ?? "", "head_branch": job.headBranch ?? "", "event": job.event ?? ""
        ]))
    }

    /// Runs the kill path once: audit, then the injected action (mark the health
    /// check failed, terminate provisioning, destroy the VM; destroying it runs
    /// the release through the shutdown coordinator).
    func kill(_ kill: Kill) async {
        guard self.kill == nil else { return }
        self.kill = kill
        let denyReasons = kill.reasons.compactMap(DenyReason.init(rawValue:))
        audit.emit(event(kill.type, level: .error, jobId: kill.jobId, runId: kill.runId, runAttempt: kill.runAttempt,
                         decision: .deny, reasons: denyReasons,
                         fields: ["reasons": kill.reasons.joined(separator: ","), "source": kill.byVerifier ? "verifier" : "relay"]))
        audit.emit(event("vm.killed", level: .warning, jobId: kill.jobId, runId: kill.runId, runAttempt: kill.runAttempt,
                         decision: nil, reasons: nil, fields: ["cause": kill.type]))
        let job = kill.jobId.map { "job \($0)" } ?? "unidentified job"
        await killAction("admission denied \(job): \(kill.reasons.joined(separator: ","))")
    }

    func markCompleted() {
        completed = true
    }

    /// The release body for this allocation, given the shutdown coordinator's
    /// cleanup reason. Returns nil after the first call (release once).
    func takeRelease(cleanupReason: String) -> ReleaseRequest? {
        guard !released else { return nil }
        released = true
        if let kill {
            return ReleaseRequest(reason: kill.byVerifier ? .verifierKill : .denied, jobId: kill.jobId, detail: kill.type)
        }
        if completed {
            return ReleaseRequest(reason: admittedJob == nil ? .unused : .completed, jobId: admittedJob?.id, detail: "provisioner exited")
        }
        if cleanupReason == "signal shutdown" {
            return ReleaseRequest(reason: .shutdown, jobId: admittedJob?.id, detail: "signal shutdown")
        }
        return ReleaseRequest(reason: .vmFailed, jobId: admittedJob?.id, detail: String(cleanupReason.prefix(200)))
    }

    private func event(_ type: String, level: AuditEvent.Level, jobId: Int?, runId: Int?, runAttempt: Int?,
                       decision: AdmissionVerdict?, reasons: [DenyReason]?, fields: [String: String]) -> AuditEvent {
        AuditEvent.make(
            type: type, source: .device, level: level, deviceId: deviceId, allocationId: allocation.allocationId,
            repositoryId: allocation.repository.id, runnerId: allocation.runner.id, runId: runId, runAttempt: runAttempt,
            jobId: jobId, decision: decision, reasons: reasons, policyVersion: allocation.policyVersion,
            fields: fields.filter { !$0.value.isEmpty }, secrets: [allocation.nonce, allocation.jitConfig ?? ""]
        )
    }
}
