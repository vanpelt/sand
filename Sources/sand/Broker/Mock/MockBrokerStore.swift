import CryptoKit
import Foundation

/// The GitHub calls the broker makes (repository scope). `GitHubService`
/// implements it; tests substitute a fake.
protocol BrokerGitHubAPI: Sendable {
    func repositoryInfo() async throws -> GitHubRepositoryInfo
    func generateJITConfig(name: String, labels: [String], runnerGroupId: Int, workFolder: String) async throws -> GitHubJITConfig
    func runs(status: String) async throws -> [GitHubRun]
    func runAttempt(runId: Int, attempt: Int) async throws -> GitHubRun
    func attemptJobs(runId: Int, attempt: Int) async throws -> [GitHubJob]
    func deleteRunner(id: Int) async throws -> DeleteRunnerResult
    func listRunners() async throws -> [GitHubService.RunnersResponse.Runner]
    func cancelRun(id: Int) async throws
}

extension GitHubService: BrokerGitHubAPI {}

struct BrokerAPIError: Error, Equatable {
    let status: Int
    let code: String
    let message: String
    var retryAfterSeconds: Int?

    static func notFound() -> BrokerAPIError { .init(status: 404, code: "not_found", message: "allocation not found") }
    static func invalid(_ message: String) -> BrokerAPIError { .init(status: 400, code: "invalid_request", message: message) }
}

/// In-memory state of the mock broker: challenges, sessions, allocations,
/// idempotency records, denial windows and the runner cleanup queue. Time,
/// randomness and sleeping are injected so tests drive every timer.
actor MockBrokerStore {
    typealias Clock = @Sendable () -> Date
    typealias Sleeper = @Sendable (TimeInterval) async throws -> Void

    struct DeviceRecord: Sendable {
        let id: String
        let publicKey: P256.Signing.PublicKey
        let owner: BrokerOwner
        var revoked: Bool
    }

    struct AllocationRecord: Sendable {
        var allocation: Allocation
        let deviceId: String
        var state: AllocationState
        var observedJob: JobRef?
        var observedAt: Date?
        var firstObservedAt: Date?
        var admittedJob: JobRef?
        var decision: AdmissionDecision?
        var decidedKey: [Int]?
        var admissionInFlight = false
        var runnerDeleted = false
        var nextCleanupAt: Date?
    }

    struct CleanupEntry: Sendable {
        let allocationId: String
        let runnerId: Int
        var cancelRunId: Int?
        var nextAttemptAt: Date
        var delay: TimeInterval
        let deadline: Date
    }

    private struct IdempotencyRecord {
        let hash: String
        let allocationId: String
        let storedAt: Date
    }

    static let challengeTTL: TimeInterval = 60
    static let sessionTTL: TimeInterval = 900
    static let cleanupInitialDelay: TimeInterval = 30
    static let cleanupMaxDelay: TimeInterval = 300
    static let cleanupDeadline: TimeInterval = 6 * 3600
    static let observedCacheSeconds: TimeInterval = 5

    let config: MockBrokerConfig
    private let github: BrokerGitHubAPI
    private let now: Clock
    private let random: @Sendable (Int) -> [UInt8]
    private let sleep: Sleeper
    private let emitAudit: @Sendable (AuditEvent) -> Void
    private var devices: [String: DeviceRecord]
    private var challenges: [String: (deviceId: String, challenge: String, expiresAt: Date)] = [:]
    private var sessions: [String: (deviceId: String, expiresAt: Date)] = [:]
    private(set) var allocations: [String: AllocationRecord] = [:]
    private var idempotency: [String: IdempotencyRecord] = [:]
    private var allocationTimes: [String: [Date]] = [:]
    private var denials: [String: [Date]] = [:]
    private var circuitOpenUntil: [String: Date] = [:]
    private(set) var cleanupQueue: [CleanupEntry] = []
    private var repository: GitHubRepositoryInfo?

    init(
        config: MockBrokerConfig,
        devices: [DeviceRecord],
        github: BrokerGitHubAPI,
        now: @escaping Clock = Date.init,
        random: @escaping @Sendable (Int) -> [UInt8] = BrokerRandom.bytes,
        sleep: @escaping Sleeper = { try await Task.sleep(nanoseconds: UInt64(max(0, $0) * 1_000_000_000)) },
        audit: @escaping @Sendable (AuditEvent) -> Void = { _ in }
    ) {
        self.config = config
        self.devices = Dictionary(uniqueKeysWithValues: devices.map { ($0.id, $0) })
        self.github = github
        self.now = now
        self.random = random
        self.sleep = sleep
        self.emitAudit = audit
    }

    var policy: AdmissionPolicy { config.policy }

    func revoke(deviceId: String) {
        devices[deviceId]?.revoked = true
        sessions = sessions.filter { $0.value.deviceId != deviceId }
    }

    func record(_ id: String) -> AllocationRecord? { allocations[id] }

    // MARK: - Sessions

    func createChallenge(deviceId: String) throws -> BrokerChallenge {
        guard let device = devices[deviceId], !device.revoked else {
            // Unknown devices are refused like revoked ones.
            throw BrokerAPIError(status: 403, code: "device_revoked", message: "device not enrolled or revoked")
        }
        let id = BrokerID.make("chl", random: random)
        let challenge = Base64URL.encode(Data(random(32)))
        let expiresAt = now().addingTimeInterval(Self.challengeTTL)
        challenges[id] = (deviceId, challenge, expiresAt)
        return BrokerChallenge(challengeId: id, challenge: challenge, expiresAt: expiresAt)
    }

    func createSession(_ request: SessionRequest) throws -> BrokerSession {
        // Single use: removed before any check, so a failed attempt also spends it.
        guard let challenge = challenges.removeValue(forKey: request.challengeId),
              challenge.deviceId == request.deviceId, challenge.expiresAt > now() else {
            audit("device.session.denied", level: .warning, deviceId: request.deviceId, fields: ["reason": "challenge_invalid"])
            throw BrokerAPIError(status: 401, code: "challenge_invalid", message: "challenge unknown, expired or used")
        }
        guard let device = devices[request.deviceId], !device.revoked else {
            throw BrokerAPIError(status: 403, code: "device_revoked", message: "device revoked")
        }
        guard request.keyId == DeviceKey.keyId(for: device.publicKey),
              DeviceKey.verify(signature: request.signature, publicKey: device.publicKey, deviceId: request.deviceId, challengeId: request.challengeId, challenge: challenge.challenge) else {
            audit("device.session.denied", level: .warning, deviceId: request.deviceId, fields: ["reason": "signature_invalid"])
            throw BrokerAPIError(status: 401, code: "signature_invalid", message: "signature invalid")
        }
        let token = Base64URL.encode(Data(random(32)))
        let expiresAt = now().addingTimeInterval(Self.sessionTTL)
        sessions[token] = (device.id, expiresAt)
        audit("device.session.created", deviceId: device.id)
        return BrokerSession(sessionToken: token, expiresAt: expiresAt, deviceId: device.id, owner: device.owner, policyVersion: policy.version)
    }

    /// The device behind a bearer token.
    func authenticate(token: String) throws -> String {
        guard let session = sessions[token] else {
            throw BrokerAPIError(status: 401, code: "session_expired", message: "no such session")
        }
        guard session.expiresAt > now() else {
            sessions.removeValue(forKey: token)
            throw BrokerAPIError(status: 401, code: "session_expired", message: "session expired")
        }
        guard let device = devices[session.deviceId], !device.revoked else {
            throw BrokerAPIError(status: 403, code: "device_revoked", message: "device revoked")
        }
        return session.deviceId
    }

    // MARK: - Allocations

    /// Returns the HTTP status (201 new, 200 idempotent replay without `jit_config`).
    func allocate(deviceId: String, request: AllocationRequest, idempotencyKey: String, requestHash: String) async throws -> (Int, Allocation) {
        pruneIdempotency()
        let idemKey = "\(deviceId)/\(idempotencyKey)"
        if let previous = idempotency[idemKey] {
            guard previous.hash == requestHash else {
                throw BrokerAPIError(status: 422, code: "idempotency_mismatch", message: "idempotency key reused with a different body")
            }
            guard var allocation = allocations[previous.allocationId]?.allocation else { throw BrokerAPIError.notFound() }
            allocation.jitConfig = nil
            return (200, allocation)
        }
        guard request.repository.owner == config.github.owner, request.repository.name == config.github.repository else {
            refuse(deviceId, "repository_not_allowed")
            throw BrokerAPIError(status: 403, code: "repository_not_allowed", message: "repository not enabled in policy")
        }
        guard request.capabilities.admissionHook else {
            throw BrokerAPIError.invalid("capabilities.admission_hook must be true")
        }
        if allocations.values.contains(where: { $0.deviceId == deviceId && $0.state.isOutstanding }) {
            refuse(deviceId, "allocation_outstanding")
            throw BrokerAPIError(status: 409, code: "allocation_outstanding", message: "another allocation is outstanding")
        }
        let hourAgo = now().addingTimeInterval(-3600)
        allocationTimes[deviceId] = (allocationTimes[deviceId] ?? []).filter { $0 > hourAgo }
        if (allocationTimes[deviceId]?.count ?? 0) >= config.limits.allocationsLimit {
            refuse(deviceId, "rate_limited")
            throw BrokerAPIError(status: 429, code: "rate_limited", message: "allocation rate limit", retryAfterSeconds: 60)
        }
        if let until = circuitOpen(deviceId) {
            refuse(deviceId, "circuit_open")
            throw BrokerAPIError(status: 429, code: "circuit_open", message: "too many denials", retryAfterSeconds: max(1, Int(until.timeIntervalSince(now()).rounded(.up))))
        }
        let repository = try await resolveRepository()
        if policy.requiresQueuedJob {
            let queued: [GitHubRun]
            do {
                queued = try await github.runs(status: "queued")
            } catch {
                throw BrokerAPIError(status: 502, code: "github_error", message: "GitHub unavailable")
            }
            let owner = devices[deviceId]?.owner.githubUserId ?? -1
            let eligible = queued.contains { AdmissionEvaluator.runReasons(run: $0, policy: policy, ownerId: owner, repositoryId: repository.id).isEmpty }
            guard eligible else {
                throw BrokerAPIError(status: 409, code: "no_eligible_demand", message: "no queued run passes the admission policy", retryAfterSeconds: 30)
            }
        }
        // Re-check after the awaits: a concurrent request may have allocated meanwhile.
        if allocations.values.contains(where: { $0.deviceId == deviceId && $0.state.isOutstanding }) {
            throw BrokerAPIError(status: 409, code: "allocation_outstanding", message: "another allocation is outstanding")
        }
        let suffix = random(4).map { String(format: "%02x", $0) }.joined()
        let name = "sand-\(deviceId)-\(suffix)"
        let jit: GitHubJITConfig
        do {
            jit = try await github.generateJITConfig(name: name, labels: policy.labels, runnerGroupId: 1, workFolder: "_work")
        } catch {
            throw BrokerAPIError(status: 502, code: "github_error", message: "JIT config request failed")
        }
        let labels = jit.runner.labels?.map(\.name) ?? policy.labels
        // JIT runners are single-use; refuse one GitHub reports as non-ephemeral.
        if jit.runner.ephemeral == false {
            _ = try? await github.deleteRunner(id: jit.runner.id)
            throw BrokerAPIError(status: 502, code: "github_error", message: "runner is not ephemeral")
        }
        let createdAt = now()
        let allocation = Allocation(
            allocationId: BrokerID.make("alc", random: random),
            state: .registered,
            nonce: Base64URL.encode(Data(random(32))),
            createdAt: createdAt,
            expiresAt: createdAt.addingTimeInterval(TimeInterval(policy.idleTTL)),
            repository: BrokerRepository(id: repository.id, owner: config.github.owner, name: config.github.repository),
            runner: BrokerRunner(id: jit.runner.id, name: jit.runner.name, labels: labels, runnerGroupId: jit.runner.runnerGroupId ?? 1, ephemeral: true),
            jitConfig: nil,
            admission: AdmissionSettings(deadlineSeconds: policy.deadlineSeconds, requireOidc: policy.requiresOIDC, oidcAudience: "sand-broker"),
            policyVersion: policy.version
        )
        allocations[allocation.allocationId] = AllocationRecord(allocation: allocation, deviceId: deviceId, state: .registered)
        idempotency[idemKey] = IdempotencyRecord(hash: requestHash, allocationId: allocation.allocationId, storedAt: now())
        allocationTimes[deviceId, default: []].append(now())
        audit("allocation.created", deviceId: deviceId, allocation: allocation, fields: [
            "runner_name": jit.runner.name, "runner_labels": labels.joined(separator: ","),
            "ephemeral": jit.runner.ephemeral.map(String.init) ?? "unreported"
        ])
        var first = allocation
        first.jitConfig = jit.encodedJitConfig
        return (201, first)
    }

    func status(deviceId: String, allocationId: String) async throws -> AllocationStatus {
        guard let record = allocations[allocationId], record.deviceId == deviceId else { throw BrokerAPIError.notFound() }
        if record.state == .registered || record.state == .assigned || record.state == .admitted {
            await refreshObserved(allocationId)
        }
        guard let current = allocations[allocationId] else { throw BrokerAPIError.notFound() }
        return AllocationStatus(
            allocationId: allocationId, state: current.state, expiresAt: current.allocation.expiresAt,
            runner: BrokerRunner(id: current.allocation.runner.id, name: current.allocation.runner.name),
            observedJob: current.observedJob, admittedJob: current.admittedJob, decision: current.decision?.decision
        )
    }

    // MARK: - Admissions

    func admit(deviceId: String, allocationId: String, request: AdmissionRequest) async throws -> AdmissionDecision {
        guard var record = allocations[allocationId], record.deviceId == deviceId else { throw BrokerAPIError.notFound() }
        let key = [request.hints.runId, request.hints.runAttempt]
        if let decided = record.decision {
            if record.decidedKey == key, constantTimeEquals(request.nonce, record.allocation.nonce) {
                return decided
            }
            return makeDecision(.deny, [.alreadyAdmitted], job: nil)
        }
        if record.admissionInFlight {
            return makeDecision(.deny, [.alreadyAdmitted], job: nil)
        }
        var reasons: [DenyReason] = []
        if record.state != .registered && record.state != .assigned { reasons.append(.allocationState) }
        if record.state == .registered && now() > record.allocation.expiresAt { reasons.append(.allocationExpired) }
        if !constantTimeEquals(request.nonce, record.allocation.nonce) { reasons.append(.nonceMismatch) }
        if !request.hints.isWellFormed { reasons.append(.hintInvalid) }
        if request.hints.repositoryId != record.allocation.repository.id { reasons.append(.repositoryMismatch) }
        if circuitOpen(deviceId) != nil { reasons.append(.circuitOpen) }
        if policy.requiresOIDC { reasons.append(.oidcUnsupported) }
        if !reasons.isEmpty {
            return finalize(allocationId, key: key, .deny, reasons, job: nil)
        }
        record.admissionInFlight = true
        allocations[allocationId] = record
        let facts = AllocationFacts(
            repositoryId: record.allocation.repository.id, runnerId: record.allocation.runner.id,
            runnerName: record.allocation.runner.name, runnerLabels: record.allocation.runner.labels ?? policy.labels
        )
        let result: AdmissionEvaluator.Result
        do {
            var jobs = try await github.attemptJobs(runId: request.hints.runId, attempt: request.hints.runAttempt)
            var waited = 0
            while AdmissionEvaluator.selectJob(jobs, allocation: facts).1 == .jobNotFoundForRunner, waited < policy.waitSeconds {
                try await sleep(1)
                waited += 1
                jobs = try await github.attemptJobs(runId: request.hints.runId, attempt: request.hints.runAttempt)
            }
            let run = try await github.runAttempt(runId: request.hints.runId, attempt: request.hints.runAttempt)
            let owner = devices[deviceId]?.owner.githubUserId ?? -1
            result = AdmissionEvaluator.evaluate(allocation: facts, hints: request.hints, run: run, jobs: jobs, policy: policy, ownerId: owner)
        } catch is CancellationError {
            allocations[allocationId]?.admissionInFlight = false
            throw CancellationError()
        } catch {
            result = .init(decision: .deny, reasons: [.githubUnavailable], job: nil)
        }
        allocations[allocationId]?.admissionInFlight = false
        // The allocation may have expired or been released while GitHub answered.
        if let state = allocations[allocationId]?.state, state != .registered && state != .assigned {
            return finalize(allocationId, key: key, .deny, [.allocationState], job: result.job)
        }
        return finalize(allocationId, key: key, result.decision, result.reasons, job: result.job)
    }

    private func finalize(_ allocationId: String, key: [Int], _ verdict: AdmissionVerdict, _ reasons: [DenyReason], job: AdmissionJob?) -> AdmissionDecision {
        let decision = makeDecision(verdict, reasons, job: job)
        guard var record = allocations[allocationId] else { return decision }
        record.decision = decision
        record.decidedKey = key
        let jobRef = job.map { JobRef(id: $0.id, runId: $0.runId, runAttempt: $0.runAttempt, status: "in_progress", observedAt: now()) }
        if verdict == .allow {
            record.state = .admitted
            record.admittedJob = jobRef
        } else {
            if record.state.isOutstanding { record.state = .denied }
        }
        allocations[allocationId] = record
        audit(verdict == .allow ? "admission.allowed" : "admission.denied", level: verdict == .allow ? .info : .warning,
              deviceId: record.deviceId, allocation: record.allocation, job: job, decision: verdict, reasons: reasons,
              fields: ["workflow_path": job?.workflowPath ?? "", "head_branch": job?.headBranch ?? "", "event": job?.event ?? ""])
        if verdict == .deny {
            recordDenial(record.deviceId)
            enqueueCleanup(allocationId, cancelRunId: policy.cancelsDeniedRuns ? job?.runId : nil)
        }
        return decision
    }

    private func makeDecision(_ verdict: AdmissionVerdict, _ reasons: [DenyReason], job: AdmissionJob?) -> AdmissionDecision {
        AdmissionDecision(admissionId: BrokerID.make("adm", random: random), decision: verdict, reasons: reasons, job: job, policyVersion: policy.version, decidedAt: now())
    }

    // MARK: - Release and cleanup

    func release(deviceId: String, allocationId: String, request: ReleaseRequest) async throws -> ReleaseResult {
        guard var record = allocations[allocationId], record.deviceId == deviceId else { throw BrokerAPIError.notFound() }
        if record.state != .closed && record.state != .cleaning {
            record.state = .cleaning
            allocations[allocationId] = record
            enqueueCleanup(allocationId, cancelRunId: nil)
        }
        if allocations[allocationId]?.runnerDeleted == true {
            closeIfReleased(allocationId)
        } else {
            await processCleanup(only: allocationId, force: true)
        }
        guard let current = allocations[allocationId] else { throw BrokerAPIError.notFound() }
        return ReleaseResult(state: current.state == .closed ? .closed : .cleaning, runnerDeleted: current.runnerDeleted, nextAttemptAt: current.nextCleanupAt)
    }

    private func enqueueCleanup(_ allocationId: String, cancelRunId: Int?) {
        guard let record = allocations[allocationId], !record.runnerDeleted else { return }
        if let index = cleanupQueue.firstIndex(where: { $0.allocationId == allocationId }) {
            if cancelRunId != nil { cleanupQueue[index].cancelRunId = cancelRunId }
            return
        }
        cleanupQueue.append(CleanupEntry(
            allocationId: allocationId, runnerId: record.allocation.runner.id, cancelRunId: cancelRunId,
            nextAttemptAt: now(), delay: Self.cleanupInitialDelay, deadline: now().addingTimeInterval(Self.cleanupDeadline)
        ))
    }

    /// Runs due runner deletions. 422 (still assigned) backs off 30 s doubling to 5 min, for up to 6 h.
    func processCleanup(only: String? = nil, force: Bool = false) async {
        for entry in cleanupQueue where only == nil || entry.allocationId == only {
            guard force || entry.nextAttemptAt <= now() else { continue }
            var updated = entry
            if let runId = entry.cancelRunId {
                do {
                    try await github.cancelRun(id: runId)
                    audit("run.cancelled", deviceId: allocations[entry.allocationId]?.deviceId, allocation: allocations[entry.allocationId]?.allocation, fields: ["run_id": String(runId)])
                } catch {
                    // Needs actions: write; logged, never fatal.
                    audit("run.cancelled", level: .warning, deviceId: allocations[entry.allocationId]?.deviceId, allocation: allocations[entry.allocationId]?.allocation, fields: ["result": "failed", "run_id": String(runId)])
                }
                updated.cancelRunId = nil
            }
            let result = try? await github.deleteRunner(id: entry.runnerId)
            let deviceId = allocations[entry.allocationId]?.deviceId
            let allocation = allocations[entry.allocationId]?.allocation
            switch result {
            case .deleted?, .notFound?:
                cleanupQueue.removeAll { $0.allocationId == entry.allocationId }
                allocations[entry.allocationId]?.runnerDeleted = true
                allocations[entry.allocationId]?.nextCleanupAt = nil
                closeIfReleased(entry.allocationId)
                audit("runner.deregistered", deviceId: deviceId, allocation: allocation, fields: ["result": result == .deleted ? "deleted" : "not_found"])
            default:
                if now() >= entry.deadline {
                    cleanupQueue.removeAll { $0.allocationId == entry.allocationId }
                    audit("runner.deregister_failed", level: .error, deviceId: deviceId, allocation: allocation)
                    continue
                }
                updated.nextAttemptAt = now().addingTimeInterval(updated.delay)
                allocations[entry.allocationId]?.nextCleanupAt = updated.nextAttemptAt
                updated.delay = min(updated.delay * 2, Self.cleanupMaxDelay)
                if let index = cleanupQueue.firstIndex(where: { $0.allocationId == entry.allocationId }) {
                    cleanupQueue[index] = updated
                }
                audit("runner.deregister_retry", level: .warning, deviceId: deviceId, allocation: allocation, fields: [
                    "result": result == .busy ? "busy" : "error", "next_in_s": String(Int(updated.nextAttemptAt.timeIntervalSince(now())))
                ])
            }
        }
    }

    /// An allocation whose runner is gone is closed once the device released it.
    private func closeIfReleased(_ allocationId: String) {
        if allocations[allocationId]?.state == .cleaning {
            allocations[allocationId]?.state = .closed
        }
    }

    // MARK: - Background work

    /// Idle expiry, admission deadlines and due cleanups. Called every few seconds.
    func tick() async {
        for (id, record) in allocations {
            switch record.state {
            case .registered where now() > record.allocation.expiresAt:
                allocations[id]?.state = .expired
                audit("allocation.expired", level: .warning, deviceId: record.deviceId, allocation: record.allocation)
                enqueueCleanup(id, cancelRunId: nil)
            case .assigned:
                if record.decision == nil, !record.admissionInFlight, let first = record.firstObservedAt,
                   now().timeIntervalSince(first) > TimeInterval(policy.deadlineSeconds) {
                    let job = record.observedJob
                    _ = finalize(id, key: [job?.runId ?? 0, job?.runAttempt ?? 0], .deny, [.admissionTimeout],
                                 job: job.map { AdmissionJob(id: $0.id, runId: $0.runId, runAttempt: $0.runAttempt) })
                }
            default:
                break
            }
        }
        await processCleanup()
    }

    /// Deletes `sand-<device>-` runners that no live allocation owns.
    func collectGarbage() async {
        guard let runners = try? await github.listRunners() else { return }
        let prefixes = devices.keys.map { "sand-\($0)-" }
        let owned = Set(allocations.values.filter { !$0.runnerDeleted }.map(\.allocation.runner.id))
        for runner in runners where prefixes.contains(where: { runner.name.hasPrefix($0) }) && !owned.contains(runner.id) {
            if let result = try? await github.deleteRunner(id: runner.id), result != .busy {
                audit("gc.runner_deleted", fields: ["runner_name": runner.name, "runner_id": String(runner.id)])
            }
        }
    }

    /// The broker's own REST view of the job our runner holds (cached for 5 s).
    private func refreshObserved(_ allocationId: String) async {
        guard let record = allocations[allocationId] else { return }
        if let at = record.observedAt, now().timeIntervalSince(at) < Self.observedCacheSeconds { return }
        allocations[allocationId]?.observedAt = now()
        guard let runs = try? await github.runs(status: "in_progress") else { return }
        var found: JobRef?
        for run in runs {
            guard let jobs = try? await github.attemptJobs(runId: run.id, attempt: run.runAttempt ?? 1) else { continue }
            if let job = jobs.first(where: { $0.runnerId == record.allocation.runner.id }) {
                found = JobRef(id: job.id, runId: job.runId, runAttempt: job.runAttempt ?? run.runAttempt ?? 1, status: job.status, observedAt: now())
                break
            }
        }
        guard let found, var current = allocations[allocationId] else { return }
        if current.observedJob?.id != found.id {
            current.firstObservedAt = now()
        }
        current.observedJob = found
        if current.state == .registered {
            current.state = .assigned
            audit("allocation.assigned", deviceId: current.deviceId, allocation: current.allocation,
                  job: AdmissionJob(id: found.id, runId: found.runId, runAttempt: found.runAttempt))
        }
        allocations[allocationId] = current
    }

    // MARK: - Device-sent audit

    func acceptAudit(deviceId: String, events: [AuditEvent]) throws -> Int {
        guard events.count <= 100 else { throw BrokerAPIError.invalid("at most 100 events per batch") }
        for var event in events {
            event.deviceId = deviceId
            event.fields = AuditEvent.sanitize(event.fields)
            emitAudit(event)
        }
        return events.count
    }

    // MARK: - Helpers

    private func resolveRepository() async throws -> GitHubRepositoryInfo {
        if let repository { return repository }
        do {
            let info = try await github.repositoryInfo()
            repository = info
            return info
        } catch {
            throw BrokerAPIError(status: 502, code: "github_error", message: "repository lookup failed")
        }
    }

    private func circuitOpen(_ deviceId: String) -> Date? {
        guard let until = circuitOpenUntil[deviceId] else { return nil }
        if until > now() { return until }
        circuitOpenUntil.removeValue(forKey: deviceId)
        return nil
    }

    private func recordDenial(_ deviceId: String) {
        let hourAgo = now().addingTimeInterval(-3600)
        var window = (denials[deviceId] ?? []).filter { $0 > hourAgo }
        window.append(now())
        denials[deviceId] = window
        if window.count >= config.limits.denialLimit, circuitOpen(deviceId) == nil {
            circuitOpenUntil[deviceId] = now().addingTimeInterval(TimeInterval(config.limits.circuitSeconds))
            audit("allocation.refused", level: .warning, deviceId: deviceId, fields: ["reason": "circuit_open", "denials_last_hour": String(window.count)])
        }
    }

    private func refuse(_ deviceId: String, _ reason: String) {
        audit("allocation.refused", level: .warning, deviceId: deviceId, fields: ["reason": reason])
    }

    private func pruneIdempotency() {
        let cutoff = now().addingTimeInterval(-86_400)
        idempotency = idempotency.filter { $0.value.storedAt > cutoff }
    }

    private func audit(_ type: String, level: AuditEvent.Level = .info, deviceId: String? = nil, allocation: Allocation? = nil,
                       job: AdmissionJob? = nil, decision: AdmissionVerdict? = nil, reasons: [DenyReason]? = nil, fields: [String: String] = [:]) {
        emitAudit(AuditEvent.make(
            type: type, source: .broker, level: level, now: now(), deviceId: deviceId,
            allocationId: allocation?.allocationId, repositoryId: allocation?.repository.id, runnerId: allocation?.runner.id,
            runId: job?.runId, runAttempt: job?.runAttempt, jobId: job?.id, decision: decision, reasons: reasons,
            policyVersion: policy.version, fields: fields.filter { !$0.value.isEmpty },
            secrets: [allocation?.nonce ?? ""]
        ))
    }
}
