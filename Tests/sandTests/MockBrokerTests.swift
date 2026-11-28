import Foundation
import Testing
@testable import sand

/// A mock broker store wired to a fake GitHub, fake clock and instant sleeps.
struct BrokerHarness {
    let key = DeviceKey.generate()
    let clock = TestClock()
    let github = FakeBrokerGitHub()
    let audit = AuditCollector()
    let store: MockBrokerStore
    let sleeps = SleepRecorder()

    final class SleepRecorder: @unchecked Sendable {
        private let lock = NSLock()
        private var values: [TimeInterval] = []
        var onSleep: (@Sendable () -> Void)?
        var recorded: [TimeInterval] { lock.withLock { values } }
        func record(_ value: TimeInterval) {
            let hook = lock.withLock { () -> (@Sendable () -> Void)? in
                values.append(value)
                return onSleep
            }
            hook?()
        }
    }

    init(policy: AdmissionPolicy = Spike.policy, limits: MockBrokerConfig.Limits = .init(), revoked: Bool = false) {
        let config = MockBrokerConfig(
            github: .init(appId: 1, privateKeyPath: nil, privateKeyKeychainLabel: "label", owner: "example-org", repository: "example-repo"),
            devices: [], policy: policy, limits: limits
        )
        let device = MockBrokerStore.DeviceRecord(id: "dev-laptop", publicKey: key.publicKey, owner: BrokerOwner(githubUserId: Spike.ownerId, githubLogin: "owner"), revoked: revoked)
        let sleeps = self.sleeps
        let clock = self.clock
        store = MockBrokerStore(
            config: config, devices: [device], github: github, now: clock.clock, random: CountingRandom().bytes,
            sleep: { seconds in
                sleeps.record(seconds)
                clock.advance(seconds)
            },
            audit: audit.sink
        )
        github.set { $0.queuedRuns = [Spike.run(status: "queued")] }
    }

    func session() async throws -> String {
        let challenge = try await store.createChallenge(deviceId: "dev-laptop")
        let signature = try key.sign(deviceId: "dev-laptop", challengeId: challenge.challengeId, challenge: challenge.challenge)
        return try await store.createSession(.init(deviceId: "dev-laptop", keyId: key.keyId, challengeId: challenge.challengeId, signature: signature)).sessionToken
    }

    static let request = AllocationRequest(
        repository: .init(owner: "example-org", name: "example-repo"), runnerNamePrefix: "laptop-runner",
        sand: .init(version: "test", networkPolicyHash: nil, vmName: "laptop-runner")
    )

    func allocate(key: String = UUID().uuidString, hash: String = "h") async throws -> (Int, Allocation) {
        try await store.allocate(deviceId: "dev-laptop", request: Self.request, idempotencyKey: key, requestHash: hash)
    }

    /// An allocation whose runner holds the spike job, with REST data prepared.
    func assigned(run: GitHubRun = Spike.run(), jobs: [[GitHubJob]]? = nil) async throws -> Allocation {
        let (_, allocation) = try await allocate()
        let job = Spike.job(runnerId: allocation.runner.id, runnerName: allocation.runner.name)
        github.set {
            $0.attempts["\(run.id)/\(run.runAttempt ?? 1)"] = run
            $0.jobs["\(run.id)/\(run.runAttempt ?? 1)"] = jobs ?? [[job]]
            $0.inProgressRuns = [run]
        }
        return allocation
    }

    func admission(_ allocation: Allocation, nonce: String? = nil, hints: AdmissionHints? = nil) -> AdmissionRequest {
        AdmissionRequest(nonce: nonce ?? allocation.nonce, hints: hints ?? Spike.hints(runnerName: allocation.runner.name))
    }
}

@Suite struct MockBrokerSessionTests {
    @Test func challengeIsSingleUse() async throws {
        let h = BrokerHarness()
        let challenge = try await h.store.createChallenge(deviceId: "dev-laptop")
        let signature = try h.key.sign(deviceId: "dev-laptop", challengeId: challenge.challengeId, challenge: challenge.challenge)
        let request = SessionRequest(deviceId: "dev-laptop", keyId: h.key.keyId, challengeId: challenge.challengeId, signature: signature)
        _ = try await h.store.createSession(request)
        await #expect(throws: BrokerAPIError(status: 401, code: "challenge_invalid", message: "challenge unknown, expired or used")) {
            _ = try await h.store.createSession(request)
        }
    }

    @Test func expiredChallengeFails() async throws {
        let h = BrokerHarness()
        let challenge = try await h.store.createChallenge(deviceId: "dev-laptop")
        h.clock.advance(61)
        let signature = try h.key.sign(deviceId: "dev-laptop", challengeId: challenge.challengeId, challenge: challenge.challenge)
        do {
            _ = try await h.store.createSession(.init(deviceId: "dev-laptop", keyId: h.key.keyId, challengeId: challenge.challengeId, signature: signature))
            Issue.record("expected challenge_invalid")
        } catch let error as BrokerAPIError {
            #expect(error.code == "challenge_invalid")
        }
    }

    @Test func wrongKeySignatureFails() async throws {
        let h = BrokerHarness()
        let challenge = try await h.store.createChallenge(deviceId: "dev-laptop")
        let other = DeviceKey.generate()
        let signature = try other.sign(deviceId: "dev-laptop", challengeId: challenge.challengeId, challenge: challenge.challenge)
        do {
            _ = try await h.store.createSession(.init(deviceId: "dev-laptop", keyId: h.key.keyId, challengeId: challenge.challengeId, signature: signature))
            Issue.record("expected signature_invalid")
        } catch let error as BrokerAPIError {
            #expect(error.code == "signature_invalid")
        }
    }

    @Test func unknownAndRevokedDevicesAreRejected() async throws {
        let h = BrokerHarness()
        await #expect(throws: BrokerAPIError.self) { _ = try await h.store.createChallenge(deviceId: "stranger") }
        let token = try await h.session()
        await h.store.revoke(deviceId: "dev-laptop")
        await #expect(throws: BrokerAPIError.self) { _ = try await h.store.authenticate(token: token) }
        await #expect(throws: BrokerAPIError.self) { _ = try await h.store.createChallenge(deviceId: "dev-laptop") }
    }

    @Test func expiredSessionIs401SessionExpired() async throws {
        let h = BrokerHarness()
        let token = try await h.session()
        #expect(try await h.store.authenticate(token: token) == "dev-laptop")
        h.clock.advance(901)
        do {
            _ = try await h.store.authenticate(token: token)
            Issue.record("expected session_expired")
        } catch let error as BrokerAPIError {
            #expect(error.status == 401)
            #expect(error.code == "session_expired")
        }
    }
}

@Suite struct MockBrokerAllocationTests {
    @Test func firstResponseCarriesJITConfigAndReplayDoesNot() async throws {
        let h = BrokerHarness()
        let (status, allocation) = try await h.allocate(key: "k1")
        #expect(status == 201)
        #expect(allocation.jitConfig?.hasPrefix("SECRET-JIT-") == true)
        #expect(allocation.runner.name.hasPrefix("sand-dev-laptop-"))
        #expect(allocation.runner.name.count == "sand-dev-laptop-".count + 8)
        #expect(Base64URL.isToken32(allocation.nonce))
        #expect(BrokerID.matches(allocation.allocationId, prefix: "alc"))
        let (replayStatus, replay) = try await h.allocate(key: "k1")
        #expect(replayStatus == 200)
        #expect(replay.jitConfig == nil)
        #expect(replay.allocationId == allocation.allocationId)
        let request = h.github.set { $0.jitRequests.first }
        #expect(request?.labels == Spike.labels)
        #expect(request?.group == 1)
        #expect(request?.folder == "_work")
        #expect(!h.audit.events.contains { $0.jsonLine().contains("SECRET-JIT") || $0.jsonLine().contains(allocation.nonce) })
    }

    @Test func sameKeyDifferentBodyIs422() async throws {
        let h = BrokerHarness()
        _ = try await h.allocate(key: "k1", hash: "a")
        await #expect(throws: BrokerAPIError(status: 422, code: "idempotency_mismatch", message: "idempotency key reused with a different body")) {
            _ = try await h.allocate(key: "k1", hash: "b")
        }
    }

    @Test func secondOutstandingAllocationIs409() async throws {
        let h = BrokerHarness()
        _ = try await h.allocate()
        do {
            _ = try await h.allocate()
            Issue.record("expected 409")
        } catch let error as BrokerAPIError {
            #expect(error.status == 409)
            #expect(error.code == "allocation_outstanding")
        }
    }

    @Test func noEligibleDemandIs409WithRetryAfter() async throws {
        let h = BrokerHarness()
        h.github.set { $0.queuedRuns = [Spike.run(event: "pull_request", status: "queued"), Spike.run(path: ".github/workflows/spike-decoy.yml", status: "queued")] }
        do {
            _ = try await h.allocate()
            Issue.record("expected no_eligible_demand")
        } catch let error as BrokerAPIError {
            #expect(error.status == 409)
            #expect(error.code == "no_eligible_demand")
            #expect(error.retryAfterSeconds == 30)
        }
        #expect(h.github.set { $0.jitRequests.isEmpty }, "no runner registered without demand")
    }

    @Test func nonEphemeralRunnerIsDeletedAnd502() async throws {
        let h = BrokerHarness()
        h.github.set { $0.ephemeral = false }
        do {
            _ = try await h.allocate()
            Issue.record("expected 502")
        } catch let error as BrokerAPIError {
            #expect(error.status == 502)
        }
        #expect(h.github.set { $0.deleted } == [101])
    }

    @Test func idleExpiryDeletesTheRunner() async throws {
        let h = BrokerHarness()
        let (_, allocation) = try await h.allocate()
        h.clock.advance(901)
        await h.store.tick()
        #expect(await h.store.record(allocation.allocationId)?.state == .expired)
        #expect(h.github.set { $0.deleted } == [allocation.runner.id])
        #expect(h.audit.types.contains("allocation.expired"))
    }

    @Test func circuitOpensAfterSixDenials() async throws {
        let h = BrokerHarness()
        for _ in 0..<6 {
            let allocation = try await h.assigned(run: Spike.run(path: ".github/workflows/spike-decoy.yml"))
            let result = try await h.store.admit(deviceId: "dev-laptop", allocationId: allocation.allocationId, request: h.admission(allocation))
            #expect(result.decision == .deny)
            _ = try await h.store.release(deviceId: "dev-laptop", allocationId: allocation.allocationId, request: .init(reason: .denied))
        }
        do {
            _ = try await h.allocate()
            Issue.record("expected circuit_open")
        } catch let error as BrokerAPIError {
            #expect(error.status == 429)
            #expect(error.code == "circuit_open")
            #expect((error.retryAfterSeconds ?? 0) > 3000)
        }
    }

    @Test func otherRepositoryIs403() async throws {
        let h = BrokerHarness()
        let request = AllocationRequest(repository: .init(owner: "evil", name: "repo"), runnerNamePrefix: "x", sand: .init(version: "t", networkPolicyHash: nil, vmName: "x"))
        await #expect(throws: BrokerAPIError.self) {
            _ = try await h.store.allocate(deviceId: "dev-laptop", request: request, idempotencyKey: "k", requestHash: "h")
        }
    }

    @Test func statusReportsTheObservedJob() async throws {
        let h = BrokerHarness()
        let allocation = try await h.assigned()
        let status = try await h.store.status(deviceId: "dev-laptop", allocationId: allocation.allocationId)
        #expect(status.state == .assigned)
        #expect(status.observedJob?.id == Spike.jobId)
        #expect(status.admittedJob == nil)
        await #expect(throws: BrokerAPIError.self) { _ = try await h.store.status(deviceId: "other", allocationId: allocation.allocationId) }
        #expect(status.observedOkAt == h.clock.now)
    }

    /// Finding 1: a failing or rate-limited GitHub must read as stale, not as
    /// "nothing running": observed_ok_at does not advance.
    @Test(arguments: ["runs", "jobs"])
    func failedObservationDoesNotAdvanceObservedOkAt(_ failing: String) async throws {
        let h = BrokerHarness()
        let allocation = try await h.assigned()
        h.github.set { if failing == "runs" { $0.failInProgress = true } else { $0.failJobs = true } }
        let status = try await h.store.status(deviceId: "dev-laptop", allocationId: allocation.allocationId)
        #expect(status.observedJob == nil)
        #expect(status.observedOkAt == nil)
        #expect(status.state == .registered)
    }

    /// Finding 1: the mock observes and times out undecided allocations on
    /// its own tick, even when the device stops polling status.
    @Test func tickAssignsAndTimesOutWithoutDevicePolls() async throws {
        let h = BrokerHarness()
        let allocation = try await h.assigned()
        await h.store.tick()
        #expect(await h.store.record(allocation.allocationId)?.state == .assigned)
        h.clock.advance(61)
        await h.store.tick()
        let record = await h.store.record(allocation.allocationId)
        #expect(record?.state == .denied)
        #expect(record?.decision?.reasons == [.admissionTimeout])
    }

    // MARK: - Tier A preconditions (finding 4)

    @Test func failingPreconditionRefusesAllocationWhenEnforced() async throws {
        let h = BrokerHarness()
        h.github.set { $0.tierA.repositorySecrets = 1; $0.tierA.forkPullRequestApproval = "first_time_contributors" }
        do {
            _ = try await h.allocate()
            Issue.record("expected tier_precondition_failed")
        } catch let error as BrokerAPIError {
            #expect(error.status == 403)
            #expect(error.code == "tier_precondition_failed")
            #expect(error.message.contains("repository_secrets=1"))
            #expect(error.message.contains("fork_pr_approval=first_time_contributors"))
        }
        #expect(h.github.set { $0.jitRequests.isEmpty }, "no runner is registered")
    }

    @Test(arguments: [
        TierAFacts(repositorySecrets: 0, organizationSecrets: 2, environments: 0, defaultWorkflowPermissions: "read", forkPullRequestApproval: "all_external_contributors"),
        TierAFacts(repositorySecrets: 0, organizationSecrets: 0, environments: 1, defaultWorkflowPermissions: "read", forkPullRequestApproval: "all_external_contributors"),
        TierAFacts(repositorySecrets: 0, organizationSecrets: 0, environments: 0, defaultWorkflowPermissions: "write", forkPullRequestApproval: "all_external_contributors")
    ])
    func eachPreconditionIsChecked(_ facts: TierAFacts) {
        #expect(facts.failures.count == 1)
    }

    @Test func uncheckablePreconditionFailsClosed() async throws {
        let h = BrokerHarness()
        h.github.set { $0.tierAError = true }
        await #expect(throws: BrokerAPIError(status: 403, code: "tier_precondition_failed", message: "Tier A preconditions not met: check_failed")) {
            _ = try await h.allocate()
        }
    }

    @Test func warnModeAllocatesAndAudits() async throws {
        var policy = Spike.policy
        policy.tierAPreconditions = "warn"
        let h = BrokerHarness(policy: policy)
        h.github.set { $0.tierA.forkPullRequestApproval = "first_time_contributors" }
        let (status, _) = try await h.allocate()
        #expect(status == 201)
        let event = h.audit.events.first { $0.type == "allocation.precondition" }
        #expect(event?.fields["mode"] == "warn")
        #expect(event?.fields["failures"] == "fork_pr_approval=first_time_contributors")
    }

    @Test func preconditionsAreCachedForFiveMinutes() async throws {
        let h = BrokerHarness()
        _ = try await h.allocate()
        let first = h.github.set { $0.tierAChecks }
        _ = await h.store.checkPreconditions()
        #expect(h.github.set { $0.tierAChecks } == first)
        h.clock.advance(301)
        _ = await h.store.checkPreconditions()
        #expect(h.github.set { $0.tierAChecks } == first + 1)
    }
}

@Suite struct MockBrokerAdmissionTests {
    @Test func allowsTheOwnersJob() async throws {
        let h = BrokerHarness()
        let allocation = try await h.assigned()
        let result = try await h.store.admit(deviceId: "dev-laptop", allocationId: allocation.allocationId, request: h.admission(allocation))
        #expect(result.decision == .allow)
        #expect(result.job?.id == Spike.jobId)
        #expect(await h.store.record(allocation.allocationId)?.state == .admitted)
        #expect(h.audit.types.contains("admission.allowed"))
    }

    @Test func nonceMismatchDenies() async throws {
        let h = BrokerHarness()
        let allocation = try await h.assigned()
        let result = try await h.store.admit(deviceId: "dev-laptop", allocationId: allocation.allocationId, request: h.admission(allocation, nonce: String(repeating: "x", count: 43)))
        #expect(result.decision == .deny)
        #expect(result.reasons.contains(.nonceMismatch))
    }

    @Test func expiredAllocationDenies() async throws {
        let h = BrokerHarness()
        let allocation = try await h.assigned()
        h.clock.advance(901)
        let result = try await h.store.admit(deviceId: "dev-laptop", allocationId: allocation.allocationId, request: h.admission(allocation))
        #expect(result.reasons.contains(.allocationExpired))
    }

    @Test func replayReturnsTheStoredDecisionAndOtherRunIsAlreadyAdmitted() async throws {
        let h = BrokerHarness()
        let allocation = try await h.assigned()
        let first = try await h.store.admit(deviceId: "dev-laptop", allocationId: allocation.allocationId, request: h.admission(allocation))
        let replay = try await h.store.admit(deviceId: "dev-laptop", allocationId: allocation.allocationId, request: h.admission(allocation))
        #expect(replay == first)
        let other = try await h.store.admit(deviceId: "dev-laptop", allocationId: allocation.allocationId,
                                            request: h.admission(allocation, hints: Spike.hints(runId: 1, runnerName: allocation.runner.name)))
        #expect(other.decision == .deny)
        #expect(other.reasons == [.alreadyAdmitted])
    }

    @Test func jobAppearsOnTheSecondPoll() async throws {
        let h = BrokerHarness()
        let (_, allocation) = try await h.allocate()
        let run = Spike.run()
        h.github.set {
            $0.attempts["\(run.id)/1"] = run
            $0.jobs["\(run.id)/1"] = [[], [Spike.job(runnerId: allocation.runner.id, runnerName: allocation.runner.name)]]
        }
        let result = try await h.store.admit(deviceId: "dev-laptop", allocationId: allocation.allocationId, request: h.admission(allocation))
        #expect(result.decision == .allow)
        #expect(h.sleeps.recorded == [1])
    }

    @Test func noJobAfterTheWaitIsJobNotFound() async throws {
        let h = BrokerHarness()
        let (_, allocation) = try await h.allocate()
        h.github.set { $0.attempts["\(Spike.runId)/1"] = Spike.run() }
        let result = try await h.store.admit(deviceId: "dev-laptop", allocationId: allocation.allocationId, request: h.admission(allocation))
        #expect(result.reasons.contains(.jobNotFoundForRunner))
        #expect(h.sleeps.recorded.count == 15)
        #expect(await h.store.record(allocation.allocationId)?.state == .denied)
    }

    @Test func requireOIDCAnswersOIDCUnsupported() async throws {
        var policy = Spike.policy
        policy.requireOIDC = true
        let h = BrokerHarness(policy: policy)
        let allocation = try await h.assigned()
        let result = try await h.store.admit(deviceId: "dev-laptop", allocationId: allocation.allocationId, request: h.admission(allocation))
        #expect(result.reasons.contains(.oidcUnsupported))
    }

    @Test func githubFailureIsGitHubUnavailable() async throws {
        let h = BrokerHarness()
        let (_, allocation) = try await h.allocate()
        h.github.set { $0.failRuns = true }
        let result = try await h.store.admit(deviceId: "dev-laptop", allocationId: allocation.allocationId, request: h.admission(allocation))
        #expect(result.decision == .deny)
        #expect(result.reasons == [.githubUnavailable])
    }

    @Test func decoyWorkflowIsDeniedAndCleanupStarts() async throws {
        let h = BrokerHarness()
        let allocation = try await h.assigned(run: Spike.run(path: ".github/workflows/spike-decoy.yml"))
        let result = try await h.store.admit(deviceId: "dev-laptop", allocationId: allocation.allocationId, request: h.admission(allocation))
        #expect(result.reasons == [.workflowNotAllowed])
        #expect(await h.store.cleanupQueue.map(\.runnerId) == [allocation.runner.id], "cleanup is queued at deny time")
        await h.store.tick()
        #expect(h.github.set { $0.deleted } == [allocation.runner.id])
        let denied = h.audit.events.first { $0.type == "admission.denied" }
        #expect(denied?.jobId == Spike.jobId)
        #expect(denied?.reasons == [.workflowNotAllowed])
    }

    @Test func unadmittedObservedJobTimesOut() async throws {
        let h = BrokerHarness()
        let allocation = try await h.assigned()
        _ = try await h.store.status(deviceId: "dev-laptop", allocationId: allocation.allocationId)
        h.clock.advance(61)
        await h.store.tick()
        let record = await h.store.record(allocation.allocationId)
        #expect(record?.state == .denied)
        #expect(record?.decision?.reasons == [.admissionTimeout])
    }
}

@Suite struct MockBrokerReleaseTests {
    @Test func busyRunnerRetriesWithBackoff() async throws {
        let h = BrokerHarness()
        let allocation = try await h.assigned()
        _ = try await h.store.admit(deviceId: "dev-laptop", allocationId: allocation.allocationId, request: h.admission(allocation))
        h.github.set { $0.deleteResults = [.busy, .busy, .deleted] }
        let first = try await h.store.release(deviceId: "dev-laptop", allocationId: allocation.allocationId, request: .init(reason: .completed, jobId: Spike.jobId))
        #expect(first.state == .cleaning)
        #expect(first.runnerDeleted == false)
        #expect(first.nextAttemptAt == h.clock.now.addingTimeInterval(30))
        h.clock.advance(29)
        await h.store.tick()
        #expect(h.github.set { $0.deleted.count } == 1, "not due yet")
        h.clock.advance(1)
        await h.store.tick()
        #expect(await h.store.record(allocation.allocationId)?.nextCleanupAt == h.clock.now.addingTimeInterval(60), "30 s doubles to 60 s")
        h.clock.advance(60)
        await h.store.tick()
        #expect(await h.store.record(allocation.allocationId)?.state == .closed)
        let again = try await h.store.release(deviceId: "dev-laptop", allocationId: allocation.allocationId, request: .init(reason: .completed))
        #expect(again.state == .closed, "release is idempotent")
    }

    @Test func notFoundClosesTheAllocation() async throws {
        let h = BrokerHarness()
        let (_, allocation) = try await h.allocate()
        h.github.set { $0.deleteResults = [.notFound] }
        let result = try await h.store.release(deviceId: "dev-laptop", allocationId: allocation.allocationId, request: .init(reason: .unused))
        #expect(result.state == .closed)
        #expect(result.runnerDeleted)
    }

    @Test func cancelOnlyWhenPolicyAsksAndA403IsTolerated() async throws {
        let off = BrokerHarness()
        let a = try await off.assigned(run: Spike.run(path: ".github/workflows/spike-decoy.yml"))
        _ = try await off.store.admit(deviceId: "dev-laptop", allocationId: a.allocationId, request: off.admission(a))
        _ = try await off.store.release(deviceId: "dev-laptop", allocationId: a.allocationId, request: .init(reason: .denied, jobId: Spike.jobId))
        #expect(off.github.set { $0.cancelled }.isEmpty)

        var policy = Spike.policy
        policy.cancelDeniedRuns = true
        let on = BrokerHarness(policy: policy)
        on.github.set { $0.cancelFails = true }
        let b = try await on.assigned(run: Spike.run(path: ".github/workflows/spike-decoy.yml"))
        _ = try await on.store.admit(deviceId: "dev-laptop", allocationId: b.allocationId, request: on.admission(b))
        let result = try await on.store.release(deviceId: "dev-laptop", allocationId: b.allocationId, request: .init(reason: .denied, jobId: Spike.jobId))
        #expect(on.github.set { $0.cancelled } == [Spike.runId])
        #expect(result.state == .closed)
    }

    @Test func gcDeletesOnlyUnownedDeviceRunners() async throws {
        let h = BrokerHarness()
        let (_, allocation) = try await h.allocate()
        h.github.set {
            $0.runners = [
                .init(id: allocation.runner.id, name: allocation.runner.name),
                .init(id: 500, name: "sand-dev-laptop-deadbeef"),
                .init(id: 501, name: "laptop-runner-1a2b3"),
                .init(id: 502, name: "sand-other-device-00000000"),
            ]
        }
        await h.store.collectGarbage()
        #expect(h.github.set { $0.deleted } == [500])
    }
}

@Suite struct MockBrokerRoutesTests {
    @Test func mockRefusesANonLoopbackListenAddress() {
        var config = MockBrokerConfig(
            github: .init(appId: 1, privateKeyPath: nil, privateKeyKeychainLabel: "l", owner: "o", repository: "r"),
            devices: [.init(id: "dev", publicKeyPath: "/x", owner: .init(login: "u", id: 1), revoked: nil)],
            policy: Spike.policy
        )
        #expect(config.validationErrors().isEmpty)
        config.listen.host = "0.0.0.0"
        #expect(config.validationErrors().contains { $0.contains("listen.host") })
    }

    /// Finding 10: timeouts must nest (broker wait < relay < hook < verifier).
    @Test func timeoutOrderingIsValidated() {
        func errors(wait: Int?, deadline: Int?) -> [String] {
            var policy = Spike.policy
            policy.admissionWaitSeconds = wait
            policy.admissionDeadlineSeconds = deadline
            return MockBrokerConfig(
                github: .init(appId: 1, privateKeyPath: nil, privateKeyKeychainLabel: "l", owner: "o", repository: "r"),
                devices: [.init(id: "dev", publicKeyPath: "/x", owner: .init(login: "u", id: 1), revoked: nil)],
                policy: policy
            ).validationErrors()
        }
        #expect(errors(wait: nil, deadline: nil).isEmpty)
        #expect(errors(wait: 31, deadline: 60).contains { $0.contains("admissionWaitSeconds") })
        #expect(errors(wait: 15, deadline: 30).contains { $0.contains("admissionDeadlineSeconds") })
        #expect(Double(AdmissionTimeouts.maxBrokerWaitSeconds) < AdmissionTimeouts.relaySeconds)
        #expect(AdmissionTimeouts.relaySeconds < Double(AdmissionTimeouts.hookCurlSeconds))
        #expect(Double(AdmissionTimeouts.hookCurlSeconds) < AdmissionTimeouts.minimumVerifierDeadline)
    }

    @Test func fixtureLoadsAndValidates() throws {
        let path = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("fixtures/broker_mock.yml").path
        let config = try MockBrokerConfig.load(path: path)
        #expect(config.validationErrors().isEmpty)
        #expect(config.policy.labels == Spike.labels)
        #expect(config.policy.deadlineSeconds == 60)
        #expect(config.policy.enforcesTierAPreconditions)
    }

    @Test func endToEndOverHTTPWithBrokerClient() async throws {
        let h = BrokerHarness()
        let allocationSeed = try await h.assigned()
        // Release the seeded allocation so the client can allocate its own.
        _ = try await h.store.release(deviceId: "dev-laptop", allocationId: allocationSeed.allocationId, request: .init(reason: .unused))
        let routes = MockBrokerRoutes(store: h.store)
        let server = LoopbackHTTPServer(maxBodyBytes: 16_384) { await routes.handle($0) }
        let port = try await server.start()
        defer { server.stop() }
        let client = BrokerClient(baseURL: URL(string: "http://127.0.0.1:\(port)")!, deviceId: "dev-laptop", key: h.key, session: URLSession(configuration: .ephemeral), now: h.clock.clock)
        let allocation = try await client.allocate(BrokerHarness.request)
        #expect(allocation.jitConfig != nil)
        let job = Spike.job(runnerId: allocation.runner.id, runnerName: allocation.runner.name)
        h.github.set { $0.jobs["\(Spike.runId)/1"] = [[job]] }
        let status = try await client.status(allocationId: allocation.allocationId)
        #expect(status.observedJob?.id == Spike.jobId)
        let result = try await client.admit(allocationId: allocation.allocationId, .init(nonce: allocation.nonce, hints: Spike.hints(runnerName: allocation.runner.name)))
        #expect(result.decision == .allow)
        let release = try await client.release(allocationId: allocation.allocationId, .init(reason: .completed, jobId: Spike.jobId))
        #expect(release.state == .closed)
        do {
            _ = try await client.allocate(AllocationRequest(repository: .init(owner: "evil", name: "r"), runnerNamePrefix: "x", sand: .init(version: "t", networkPolicyHash: nil, vmName: "x")))
            Issue.record("expected 403")
        } catch let error as BrokerClientError {
            #expect(error == .http(status: 403, code: "repository_not_allowed", retryAfterSeconds: nil))
        }
    }
}
