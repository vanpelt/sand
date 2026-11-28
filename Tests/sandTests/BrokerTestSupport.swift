import CryptoKit
import Foundation
@testable import sand

/// A URLSession stand-in answering from a closure, recording every request.
final class ScriptedSession: URLSessionProtocol, @unchecked Sendable {
    struct Reply {
        var status: Int
        var body: Data
        var headers: [String: String] = [:]
        init(_ status: Int, _ body: String = "{}", headers: [String: String] = [:]) {
            self.status = status
            self.body = Data(body.utf8)
            self.headers = headers
        }
    }

    private let lock = NSLock()
    private var recorded: [URLRequest] = []
    var handler: @Sendable (URLRequest) throws -> Reply

    init(_ handler: @escaping @Sendable (URLRequest) throws -> Reply) {
        self.handler = handler
    }

    var requests: [URLRequest] { lock.withLock { recorded } }

    func data(for request: URLRequest) async throws -> (Data, URLResponse) {
        lock.withLock { recorded.append(request) }
        let reply = try handler(request)
        let response = HTTPURLResponse(url: request.url!, statusCode: reply.status, httpVersion: nil, headerFields: reply.headers)!
        return (reply.body, response)
    }
}

/// A mutable clock for injected time.
final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var current: Date
    init(_ start: Date = Date(timeIntervalSince1970: 1_800_000_000)) { current = start }
    var now: Date { lock.withLock { current } }
    func advance(_ seconds: TimeInterval) { lock.withLock { current = current.addingTimeInterval(seconds) } }
    var clock: @Sendable () -> Date { { [self] in now } }
}

/// Deterministic "random" bytes: a counter, so ids and nonces are unique.
final class CountingRandom: @unchecked Sendable {
    private let lock = NSLock()
    private var counter: UInt8 = 0
    var bytes: @Sendable (Int) -> [UInt8] {
        { [self] count in
            lock.withLock {
                counter &+= 1
                return (0..<count).map { UInt8(truncatingIfNeeded: Int(counter) &* 31 &+ $0) }
            }
        }
    }
}

enum Spike {
    static let repositoryId = 1_473_742_157
    static let ownerId = 17
    static let runId = 46_107_413_025
    static let jobId = 140_863_154_515
    static let runnerId = 34
    static let runnerName = "sand-dev-laptop-3f9a1c2e"
    static let labels = ["self-hosted", "macOS", "ARM64", "sand"]

    static let policy = AdmissionPolicy(
        version: "pilot-1",
        labels: labels,
        events: ["push", "workflow_dispatch"],
        workflows: [".github/workflows/self-hosted-smoke.yml"],
        branches: ["main", "feature/*"]
    )

    static let facts = AllocationFacts(repositoryId: repositoryId, runnerId: runnerId, runnerName: runnerName, runnerLabels: labels)

    static func run(
        id: Int = runId, attempt: Int = 1, event: String = "push",
        path: String = ".github/workflows/self-hosted-smoke.yml", branch: String? = "feature/job-admission",
        actor: GitHubActor? = GitHubActor(id: ownerId, login: "owner", type: "User"),
        triggeringActor: GitHubActor? = GitHubActor(id: ownerId, login: "owner", type: "User"),
        headRepositoryId: Int? = repositoryId, referenced: [String] = [], status: String = "in_progress"
    ) -> GitHubRun {
        GitHubRun(
            id: id, runAttempt: attempt, event: event, status: status, path: path, headBranch: branch, headSha: "c905f1da",
            repository: GitHubRepoRef(id: repositoryId), headRepository: headRepositoryId.map(GitHubRepoRef.init(id:)),
            actor: actor, triggeringActor: triggeringActor,
            referencedWorkflows: referenced.map(GitHubRun.ReferencedWorkflow.init(path:))
        )
    }

    static func job(id: Int = jobId, runId: Int = runId, attempt: Int = 1, status: String = "in_progress",
                    runnerId: Int? = runnerId, runnerName: String? = runnerName, labels: [String] = ["self-hosted", "macOS", "ARM64", "sand"]) -> GitHubJob {
        GitHubJob(id: id, runId: runId, runAttempt: attempt, status: status, name: "smoke", runnerId: runnerId, runnerName: runnerName, labels: labels, headSha: "c905f1da")
    }

    static func hints(runId: Int = runId, attempt: Int = 1, repositoryId: Int = repositoryId, runnerName: String = runnerName, jobKey: String = "smoke") -> AdmissionHints {
        AdmissionHints(repositoryId: repositoryId, runId: runId, runAttempt: attempt, runnerName: runnerName, jobKey: jobKey)
    }

    static func allocation(id: String = "alc_01JDQ7Z6S8V4N3K2M1P0R9T8W7", nonce: String = String(repeating: "n", count: 43), deadline: Int = 30) -> Allocation {
        Allocation(
            allocationId: id, state: .registered, nonce: nonce,
            createdAt: Date(timeIntervalSince1970: 1_800_000_000), expiresAt: Date(timeIntervalSince1970: 1_800_000_900),
            repository: BrokerRepository(id: repositoryId, owner: "example-org", name: "example-repo"),
            runner: BrokerRunner(id: runnerId, name: runnerName, labels: labels, runnerGroupId: 1, ephemeral: true),
            jitConfig: nil,
            admission: AdmissionSettings(deadlineSeconds: deadline, requireOidc: false, oidcAudience: "sand-broker"),
            policyVersion: "pilot-1"
        )
    }
}

/// In-memory GitHub for the mock broker store.
final class FakeBrokerGitHub: BrokerGitHubAPI, @unchecked Sendable {
    private let lock = NSLock()
    var queuedRuns: [GitHubRun] = []
    var inProgressRuns: [GitHubRun] = []
    var attempts: [String: GitHubRun] = [:]
    /// Successive answers for one attempt's jobs; the last one repeats.
    var jobs: [String: [[GitHubJob]]] = [:]
    var runners: [GitHubService.RunnersResponse.Runner] = []
    var ephemeral: Bool? = true
    var deleteResults: [DeleteRunnerResult] = []
    var cancelFails = false
    var failRuns = false
    private(set) var deleted: [Int] = []
    private(set) var cancelled: [Int] = []
    private(set) var jitRequests: [(name: String, labels: [String], group: Int, folder: String)] = []
    private var nextRunnerId = 100

    func set<T>(_ body: (FakeBrokerGitHub) -> T) -> T { lock.withLock { body(self) } }

    func repositoryInfo() async throws -> GitHubRepositoryInfo {
        GitHubRepositoryInfo(id: Spike.repositoryId, name: "example-repo", owner: .init(login: "example-org", id: 99))
    }

    func generateJITConfig(name: String, labels: [String], runnerGroupId: Int, workFolder: String) async throws -> GitHubJITConfig {
        let json: String = lock.withLock {
            jitRequests.append((name, labels, runnerGroupId, workFolder))
            nextRunnerId += 1
            let eph = ephemeral.map { ",\"ephemeral\":\($0)" } ?? ""
            let labelJSON = labels.map { "{\"name\":\"\($0)\"}" }.joined(separator: ",")
            return "{\"runner\":{\"id\":\(nextRunnerId),\"name\":\"\(name)\",\"labels\":[\(labelJSON)]\(eph)},\"encoded_jit_config\":\"SECRET-JIT-\(nextRunnerId)\"}"
        }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(GitHubJITConfig.self, from: Data(json.utf8))
    }

    func runs(status: String) async throws -> [GitHubRun] {
        try lock.withLock {
            if failRuns { throw GitHubServiceError.httpError(status: 503, body: "") }
            return status == "queued" ? queuedRuns : inProgressRuns
        }
    }

    func runAttempt(runId: Int, attempt: Int) async throws -> GitHubRun {
        try lock.withLock {
            guard let run = attempts["\(runId)/\(attempt)"] else { throw GitHubServiceError.httpError(status: 404, body: "") }
            return run
        }
    }

    func attemptJobs(runId: Int, attempt: Int) async throws -> [GitHubJob] {
        try lock.withLock {
            let key = "\(runId)/\(attempt)"
            guard var answers = jobs[key], !answers.isEmpty else {
                if failRuns { throw GitHubServiceError.httpError(status: 503, body: "") }
                return []
            }
            let first = answers[0]
            if answers.count > 1 { answers.removeFirst(); jobs[key] = answers }
            return first
        }
    }

    func deleteRunner(id: Int) async throws -> DeleteRunnerResult {
        lock.withLock {
            deleted.append(id)
            if deleteResults.isEmpty { return .deleted }
            return deleteResults.removeFirst()
        }
    }

    func listRunners() async throws -> [GitHubService.RunnersResponse.Runner] { lock.withLock { runners } }

    func cancelRun(id: Int) async throws {
        try lock.withLock {
            cancelled.append(id)
            if cancelFails { throw GitHubServiceError.httpError(status: 403, body: "") }
        }
    }
}

/// Programmable broker client for relay, verifier and runner tests.
final class FakeBrokerClient: BrokerClienting, @unchecked Sendable {
    private let lock = NSLock()
    var admitResult: Result<AdmissionDecision, Error> = .failure(BrokerClientError.transport("unset"))
    var admitDelay: TimeInterval = 0
    var statuses: [Result<AllocationStatus, Error>] = []
    var allocateResults: [Result<Allocation, Error>] = []
    private(set) var admitCalls: [AdmissionRequest] = []
    private(set) var releases: [ReleaseRequest] = []
    private(set) var statusCalls = 0
    private(set) var allocateCalls = 0

    func set(_ body: (FakeBrokerClient) -> Void) { lock.withLock { body(self) } }

    func allocate(_ request: AllocationRequest) async throws -> Allocation {
        let next: Result<Allocation, Error> = lock.withLock {
            allocateCalls += 1
            return allocateResults.isEmpty ? .failure(BrokerClientError.transport("none")) : allocateResults.removeFirst()
        }
        return try next.get()
    }

    func status(allocationId: String) async throws -> AllocationStatus {
        let next: Result<AllocationStatus, Error> = lock.withLock {
            statusCalls += 1
            if statuses.count > 1 { return statuses.removeFirst() }
            return statuses.first ?? .failure(BrokerClientError.transport("none"))
        }
        return try next.get()
    }

    func admit(allocationId: String, _ request: AdmissionRequest) async throws -> AdmissionDecision {
        let (result, delay) = lock.withLock { () -> (Result<AdmissionDecision, Error>, TimeInterval) in
            admitCalls.append(request)
            return (admitResult, admitDelay)
        }
        if delay > 0 { try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000)) }
        return try result.get()
    }

    func release(allocationId: String, _ request: ReleaseRequest) async throws -> ReleaseResult {
        lock.withLock { releases.append(request) }
        return ReleaseResult(state: .closed, runnerDeleted: true)
    }

    func audit(_ events: [AuditEvent]) async throws {}
}

final class AuditCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [AuditEvent] = []
    var events: [AuditEvent] { lock.withLock { storage } }
    var types: [String] { events.map(\.type) }
    var audit: AdmissionAudit { AdmissionAudit { [self] event in lock.withLock { storage.append(event) } } }
    var sink: @Sendable (AuditEvent) -> Void { { [self] event in lock.withLock { storage.append(event) } } }
}

func decision(_ verdict: AdmissionVerdict, _ reasons: [DenyReason] = [], jobId: Int = Spike.jobId) -> AdmissionDecision {
    AdmissionDecision(
        admissionId: "adm_00000000000000000000000000", decision: verdict, reasons: reasons,
        job: AdmissionJob(id: jobId, runId: Spike.runId, runAttempt: 1, workflowPath: ".github/workflows/self-hosted-smoke.yml", headBranch: "main", event: "push"),
        policyVersion: "pilot-1", decidedAt: Date()
    )
}
