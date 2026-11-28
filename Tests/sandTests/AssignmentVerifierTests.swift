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

        func verifier() -> AssignmentVerifier {
            let clock = self.clock
            let warnings = self.warnings
            return AssignmentVerifier(
                controller: controller, broker: broker, deadlineSeconds: 30,
                now: clock.clock, sleep: { clock.advance($0); await Task.yield() }, warn: { warnings.add($0) }
            )
        }

        func status(_ state: AllocationState = .assigned, observed: Int? = nil, admitted: Int? = nil) -> Result<AllocationStatus, Error> {
            .success(AllocationStatus(
                allocationId: Spike.allocation().allocationId, state: state, expiresAt: Date(),
                runner: BrokerRunner(id: Spike.runnerId, name: Spike.runnerName),
                observedJob: observed.map { JobRef(id: $0, runId: Spike.runId, runAttempt: 1) },
                admittedJob: admitted.map { JobRef(id: $0, runId: Spike.runId, runAttempt: 1) }
            ))
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
        f.broker.set { $0.statuses = [f.status(observed: Spike.jobId)] }
        await f.run()
        #expect(f.kills.reasons.count == 1)
        #expect(await f.controller.kill?.type == "assignment.unadmitted")
        #expect(f.audit.types.contains("assignment.unadmitted"))
        // 5 s polls: killed on the first poll past 30 s.
        #expect(f.broker.statusCalls == 8)
    }

    @Test func mismatchKills() async {
        let f = Fixture()
        await f.controller.recordAllow(decision(.allow, jobId: Spike.jobId))
        f.broker.set { $0.statuses = [f.status(.admitted, observed: 999, admitted: Spike.jobId)] }
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
        #expect(f.clock.now.timeIntervalSince(TestClock().now) > 30)
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
        f.broker.set { $0.statuses = [f.status(.admitted, observed: Spike.jobId, admitted: Spike.jobId)] }
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
