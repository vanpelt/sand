import Foundation

/// The admission policy (ADR 0001 §5). Pilot scope: Tier A only.
struct AdmissionPolicy: Codable, Sendable, Equatable {
    var version: String
    var labels: [String]
    var events: [String] = ["push", "workflow_dispatch"]
    var workflows: [String]
    var branches: [String]
    var allowReusableWorkflows: Bool? = false
    var requireQueuedJob: Bool? = true
    var requireOIDC: Bool? = false
    var cancelDeniedRuns: Bool? = false
    var admissionWaitSeconds: Int? = 15
    var admissionDeadlineSeconds: Int? = 60
    var idleTTLSeconds: Int? = 900
    /// `enforce` (default) refuses allocations while a Tier A precondition
    /// fails; `warn` allocates and audits the failure (development only).
    var tierAPreconditions: String? = "enforce"

    var waitSeconds: Int { admissionWaitSeconds ?? 15 }
    var deadlineSeconds: Int { admissionDeadlineSeconds ?? 60 }
    var enforcesTierAPreconditions: Bool { tierAPreconditions != "warn" }
    var idleTTL: Int { idleTTLSeconds ?? 900 }
    var requiresQueuedJob: Bool { requireQueuedJob ?? true }
    var requiresOIDC: Bool { requireOIDC ?? false }
    var cancelsDeniedRuns: Bool { cancelDeniedRuns ?? false }

    /// Exact name, or `prefix/*` matching any branch below `prefix/`.
    func branchAllowed(_ branch: String?) -> Bool {
        guard let branch, !branch.isEmpty else { return false }
        return branches.contains { pattern in
            if pattern.hasSuffix("/*") {
                let prefix = String(pattern.dropLast(1))
                return branch.hasPrefix(prefix) && branch.count > prefix.count
            }
            return pattern == branch
        }
    }
}

/// Everything the evaluator needs to know about the allocation.
struct AllocationFacts: Sendable, Equatable {
    let repositoryId: Int
    let runnerId: Int
    let runnerName: String
    let runnerLabels: [String]
}

/// Pure admission decision from REST data (`docs/broker-api.md` §4.4, steps 2-4).
/// Hints are only lookup keys; every check uses GitHub's own ids.
enum AdmissionEvaluator {
    struct Result: Sendable, Equatable {
        let decision: AdmissionVerdict
        let reasons: [DenyReason]
        let job: AdmissionJob?
    }

    /// Selects the one job our runner holds. Returns the job or the reason it could not.
    static func selectJob(_ jobs: [GitHubJob], allocation: AllocationFacts) -> (GitHubJob?, DenyReason?) {
        let mine = jobs.filter { $0.runnerId == allocation.runnerId }
        if mine.isEmpty { return (nil, .jobNotFoundForRunner) }
        if mine.count > 1 { return (nil, .multipleJobsForRunner) }
        return (mine[0], nil)
    }

    static func evaluate(allocation: AllocationFacts, hints: AdmissionHints, run: GitHubRun, jobs: [GitHubJob], policy: AdmissionPolicy, ownerId: Int) -> Result {
        var reasons: [DenyReason] = []
        if hints.repositoryId != allocation.repositoryId { reasons.append(.repositoryMismatch) }
        let (selected, selectionFailure) = selectJob(jobs, allocation: allocation)
        if let selectionFailure { reasons.append(selectionFailure) }
        if let job = selected {
            if job.status != "in_progress" { reasons.append(.jobNotInProgress) }
            if job.runnerName != allocation.runnerName { reasons.append(.runnerNameMismatch) }
            if job.runId != hints.runId || (job.runAttempt ?? hints.runAttempt) != hints.runAttempt { reasons.append(.hintInvalid) }
            if !Set(job.labels).isSubset(of: Set(allocation.runnerLabels)) { reasons.append(.labelsMismatch) }
        }
        if run.id != hints.runId || (run.runAttempt ?? hints.runAttempt) != hints.runAttempt {
            reasons.append(.hintInvalid)
        }
        reasons += runReasons(run: run, policy: policy, ownerId: ownerId, repositoryId: allocation.repositoryId)
        let unique = reasons.reduce(into: [DenyReason]()) { if !$0.contains($1) { $0.append($1) } }
        let job = selected.map { job in
            AdmissionJob(
                id: job.id, runId: job.runId, runAttempt: job.runAttempt ?? hints.runAttempt,
                workflowPath: run.path, headSha: run.headSha, headBranch: run.headBranch, event: run.event,
                actorId: run.actor?.id, triggeringActorId: run.triggeringActor?.id, labels: job.labels
            )
        }
        return Result(decision: unique.isEmpty ? .allow : .deny, reasons: unique, job: job)
    }

    /// Run-level checks, shared with the allocation demand check.
    static func runReasons(run: GitHubRun, policy: AdmissionPolicy, ownerId: Int, repositoryId: Int) -> [DenyReason] {
        var reasons: [DenyReason] = []
        if run.repository.id != repositoryId { reasons.append(.repositoryMismatch) }
        if run.headRepository?.id != run.repository.id { reasons.append(.forkHead) }
        if !policy.events.contains(run.event) { reasons.append(.eventNotAllowed) }
        if run.actor?.type != "User" || run.triggeringActor?.type != "User" { reasons.append(.actorNotUser) }
        if run.actor?.id != ownerId { reasons.append(.actorNotOwner) }
        if run.triggeringActor?.id != ownerId { reasons.append(.triggeringActorNotOwner) }
        if !policy.workflows.contains(run.path) { reasons.append(.workflowNotAllowed) }
        // A missing field fails closed like every other missing fact.
        if (run.referencedWorkflows.map { !$0.isEmpty } ?? true) && !(policy.allowReusableWorkflows ?? false) {
            reasons.append(.reusableWorkflowNotAllowed)
        }
        if !policy.branchAllowed(run.headBranch) { reasons.append(.refNotAllowed) }
        return reasons
    }
}
