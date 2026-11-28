import Foundation
import Testing
@testable import sand

@Suite struct AssignmentVerifierTests {
    struct Fixture {
        let broker = FakeBrokerClient()
        let clock = TestClock()
        let audit = AuditCollector()
        let kills = AdmissionRelayTests.KillLog()
        let warnings = AdmissionRelayTests.KillLog()
        let controller: AdmissionController

        init() {
            let kills = self.kills
            controller = AdmissionController(allocation: Spike.allocation(deadline: 30), deviceId: "dev-laptop", audit: audit.audit) { kills.add($0) }
        }

        var workerProbe: AssignmentVerifier.WorkerProbe?

        func verifier() -> AssignmentVerifier {
            let clock = self.clock
            let warnings = self.warnings
            return AssignmentVerifier(
                controller: controller, broker: broker, deadlineSeconds: 30, workerProbe: workerProbe,
                now: clock.clock, sleep: { clock.advance($0); await Task.yield() }, warn: { warnings.add($0) }
            )
        }

        /// `fresh`: the broker's observation succeeded just now (`observed_ok_at` = now).
        func status(_ state: AllocationState = .assigned, observed: Int? = nil, admitted: Int? = nil, fresh: Bool = true) -> Result<AllocationStatus, Error> {
            .success(AllocationStatus(
                allocationId: Spike.allocation().allocationId, state: state, expiresAt: Date(),
                runner: BrokerRunner(id: Spike.runnerId, name: Spike.runnerName),
                observedJob: observed.map { JobRef(id: $0, runId: Spike.runId, runAttempt: 1) },
                admittedJob: admitted.map { JobRef(id: $0, runId: Spike.runId, runAttempt: 1) },
                observedOkAt: fresh ? clock.now : nil
            ))
        }

        /// Answers every poll with `status(...)` computed at poll time.
        func serve(_ state: AllocationState = .assigned, observed: Int? = nil, admitted: Int? = nil, fresh: Bool = true) {
            let f = self
            broker.set { $0.statusProvider = { f.status(state, observed: observed, admitted: admitted, fresh: fresh) } }
        }

        func run(maxPolls: Int = 50) async {
            let task = Task { await verifier().run() }
            for _ in 0..<500 where broker.statusCalls < maxPolls && kills.reasons.isEmpty {
                try? await Task.sleep(nanoseconds: 2_000_000)
            }
            task.cancel()
            await task.value
        }
    }

    @Test func observedJobWithoutAdmissionPastTheDeadlineKills() async {
        let f = Fixture()
        f.serve(observed: Spike.jobId)
        await f.run()
        #expect(f.kills.reasons.count == 1)
        #expect(await f.controller.kill?.type == "assignment.unadmitted")
        #expect(await f.controller.kill?.reasons == ["admission_timeout"])
        #expect(f.audit.types.contains("assignment.unadmitted"))
        // 5 s polls; the 30 s broker deadline is raised to 60 s (above the
        // relay and hook timeouts): killed on the first poll past 60 s.
        #expect(f.broker.statusCalls == 14)
    }

    /// Finding 1: a broker whose GitHub calls fail returns 200 with a null
    /// observed_job. Null must not read as "nothing running" forever.
    @Test func staleObservationBeforeAdmissionKills() async {
        let f = Fixture()
        f.serve(.registered, fresh: false)
        await f.run()
        #expect(await f.controller.kill?.reasons == ["observation_stale"])
        #expect(f.clock.now.timeIntervalSince(TestClock().now) > 60)
        #expect(f.clock.now.timeIntervalSince(TestClock().now) <= 65)
    }

    @Test func freshEmptyObservationIsLeftAlone() async {
        let f = Fixture()
        f.serve(.registered)
        await f.run(maxPolls: 40)
        #expect(f.kills.reasons.isEmpty)
    }

    @Test func observationThatStopsAdvancingKills() async {
        let f = Fixture()
        let frozen = f.clock.now
        f.broker.set {
            $0.statusProvider = {
                .success(AllocationStatus(allocationId: Spike.allocation().allocationId, state: .registered, expiresAt: Date(),
                                          runner: BrokerRunner(id: Spike.runnerId, name: Spike.runnerName), observedOkAt: frozen))
            }
        }
        await f.run()
        #expect(await f.controller.kill?.reasons == ["observation_stale"])
    }

    @Test func staleObservationAfterAdmissionDoesNotKill() async {
        let f = Fixture()
        await f.controller.recordAllow(decision(.allow))
        f.serve(.admitted, admitted: Spike.jobId, fresh: false)
        await f.run(maxPolls: 10)
        #expect(f.kills.reasons.isEmpty)
    }

    /// Finding 1, GitHub-independent: a Runner.Worker without an admission
    /// past the deadline kills even while the broker sees nothing.
    @Test func guestWorkerWithoutAdmissionKills() async {
        var f = Fixture()
        f.workerProbe = { true }
        f.serve(.registered)
        await f.run()
        #expect(await f.controller.kill?.reasons == ["worker_unadmitted"])
    }

    @Test func guestWorkerAfterAdmissionIsFine() async {
        var f = Fixture()
        f.workerProbe = { true }
        await f.controller.recordAllow(decision(.allow))
        f.serve(.admitted, observed: Spike.jobId, admitted: Spike.jobId)
        await f.run(maxPolls: 10)
        #expect(f.kills.reasons.isEmpty)
    }

    @Test func failingWorkerProbeOnlyWarns() async {
        var f = Fixture()
        f.workerProbe = { throw BrokerClientError.invalidResponse }
        f.serve(.registered)
        await f.run(maxPolls: 30)
        #expect(f.kills.reasons.isEmpty)
        #expect(f.warnings.reasons.contains { $0.contains("worker probe failed") })
    }

    @Test func workerProbeParsing() throws {
        #expect(try AssignmentVerifier.parseWorkerProbe("SAND_WORKER_UP\n"))
        #expect(try !AssignmentVerifier.parseWorkerProbe("SAND_WORKER_DOWN\n"))
        #expect(throws: BrokerClientError.self) { try AssignmentVerifier.parseWorkerProbe("") }
        #expect(!AssignmentVerifier.workerProbeCommand.contains("Runner.Worker"), "the probe must not match its own command line")
    }

    @Test func mismatchKills() async {
        let f = Fixture()
        await f.controller.recordAllow(decision(.allow, jobId: Spike.jobId))
        f.serve(.admitted, observed: 999, admitted: Spike.jobId)
        await f.run()
        #expect(await f.controller.kill?.type == "assignment.mismatch")
        #expect(await f.controller.kill?.jobId == 999)
    }

    @Test(arguments: [AllocationState.denied, .expired])
    func deniedOrExpiredStateKills(_ state: AllocationState) async {
        let f = Fixture()
        f.broker.set { $0.statuses = [f.status(state)] }
        await f.run()
        #expect(f.kills.reasons.count == 1)
        #expect(f.broker.statusCalls == 1)
    }

    @Test func unreachableBrokerBeforeAdmissionKillsAfterTheDeadline() async {
        let f = Fixture()
        f.broker.set { $0.statuses = [.failure(BrokerClientError.transport("down"))] }
        await f.run()
        #expect(await f.controller.kill?.reasons == ["broker_unreachable"])
        #expect(f.clock.now.timeIntervalSince(TestClock().now) > 60)
    }

    @Test func unreachableBrokerAfterAdmissionOnlyWarns() async {
        let f = Fixture()
        await f.controller.recordAllow(decision(.allow))
        f.broker.set { $0.statuses = [.failure(BrokerClientError.transport("down"))] }
        await f.run(maxPolls: 10)
        #expect(f.kills.reasons.isEmpty)
        #expect(!f.warnings.reasons.isEmpty)
        // 30 s polls after admission.
        #expect(f.clock.now.timeIntervalSince(TestClock().now) >= 30 * 9)
    }

    @Test func matchingAdmittedJobIsLeftAlone() async {
        let f = Fixture()
        await f.controller.recordAllow(decision(.allow))
        f.serve(.admitted, observed: Spike.jobId, admitted: Spike.jobId)
        await f.run(maxPolls: 10)
        #expect(f.kills.reasons.isEmpty)
    }

    @Test func cancellationStopsPolling() async throws {
        let f = Fixture()
        f.broker.set { $0.statuses = [f.status()] }
        let verifier = AssignmentVerifier(controller: f.controller, broker: f.broker, deadlineSeconds: 30, sleep: { try await Task.sleep(nanoseconds: UInt64($0 * 1_000_000)) })
        let task = Task { await verifier.run() }
        try await Task.sleep(nanoseconds: 30_000_000)
        task.cancel()
        await task.value
        let calls = f.broker.statusCalls
        try await Task.sleep(nanoseconds: 50_000_000)
        #expect(f.broker.statusCalls == calls)
        #expect(f.kills.reasons.isEmpty)
    }
}
