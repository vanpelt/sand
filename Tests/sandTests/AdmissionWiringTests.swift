import Foundation
import Testing
@testable import sand

/// The broker-mode kill path and release, wired like `Runner` wires them.
@Suite struct AdmissionWiringTests {
    final class EventLog: ProcessRunning, @unchecked Sendable {
        private let lock = NSLock()
        private var storage: [String] = []
        var events: [String] { lock.withLock { storage } }
        func add(_ event: String) { lock.withLock { storage.append(event) } }

        func run(executable: String, arguments: [String], wait: Bool) async throws -> ProcessResult? {
            add("tart \(arguments.first ?? "")")
            return ProcessResult(stdout: "", stderr: "", exitCode: 0)
        }

        func start(executable: String, arguments: [String]) throws -> ProcessHandle {
            ProcessHandle(waitAsync: { ProcessResult(stdout: "", stderr: "", exitCode: 0) }, terminate: {})
        }
    }

    /// Records releases into the shared event log.
    final class ReleasingBroker: BrokerClienting, @unchecked Sendable {
        let log: EventLog
        init(log: EventLog) { self.log = log }
        private let lock = NSLock()
        private var storage: [ReleaseRequest] = []
        var releases: [ReleaseRequest] { lock.withLock { storage } }
        func allocate(_ request: AllocationRequest) async throws -> Allocation { throw BrokerClientError.invalidResponse }
        func status(allocationId: String) async throws -> AllocationStatus { throw BrokerClientError.invalidResponse }
        func admit(allocationId: String, _ request: AdmissionRequest) async throws -> AdmissionDecision { throw BrokerClientError.invalidResponse }
        func release(allocationId: String, _ request: ReleaseRequest) async throws -> ReleaseResult {
            lock.withLock { storage.append(request) }
            log.add("release \(request.reason.rawValue) \(request.jobId.map(String.init) ?? "-")")
            return ReleaseResult(state: .closed, runnerDeleted: true)
        }
        func audit(_ events: [AuditEvent]) async throws {}
    }

    struct Wiring {
        let log = EventLog()
        let control = RunnerControl()
        let coordinator: VMShutdownCoordinator
        let broker: ReleasingBroker
        let controller: AdmissionController
        let audit = AuditCollector()

        init() async {
            let logger = Logger(label: "test", minimumLevel: .critical)
            let log = self.log
            coordinator = VMShutdownCoordinator(destroyer: VMDestroyer(tart: Tart(processRunner: log, logger: logger), logger: logger), logger: logger)
            broker = ReleasingBroker(log: log)
            await coordinator.activate(name: "slot")
            await control.setProvisioningHandle(ProcessHandle(waitAsync: { ProcessResult(stdout: "", stderr: "", exitCode: 0) }, terminate: { log.add("terminate provisioning") }))
            controller = AdmissionController(
                allocation: Spike.allocation(), deviceId: "dev-laptop", audit: audit.audit,
                kill: Runner.admissionKillAction(control: control, shutdownCoordinator: coordinator, logger: logger) { _ in log.add("health check failed") }
            )
            let controller = self.controller
            let broker = self.broker
            await coordinator.setDeregistration(withReason: { reason in
                guard let release = await controller.takeRelease(cleanupReason: reason) else { return }
                _ = try? await broker.release(allocationId: Spike.allocation().allocationId, release)
            })
        }
    }

    @Test func denyTerminatesThenCleansUpThenReleasesOnce() async {
        let w = await Wiring()
        let kill = AdmissionController.Kill(type: "admission.denied", reasons: ["workflow_not_allowed"], jobId: Spike.jobId, runId: Spike.runId, runAttempt: 1, byVerifier: false)
        async let first: Void = w.controller.kill(kill)
        async let second: Void = w.controller.kill(.init(type: "assignment.unadmitted", reasons: ["admission_timeout"], jobId: nil, runId: nil, runAttempt: nil, byVerifier: true))
        _ = await (first, second)
        await w.coordinator.cleanup(reason: "admission denied")
        #expect(w.log.events == ["health check failed", "terminate provisioning", "tart stop", "tart delete", "release denied \(Spike.jobId)"])
        #expect(w.broker.releases.count == 1)
        #expect(w.audit.types == ["admission.denied", "vm.killed"])
    }

    @Test func verifierKillReleasesAsVerifierKill() async {
        let w = await Wiring()
        await w.controller.kill(.init(type: "assignment.unadmitted", reasons: ["admission_timeout"], jobId: 5, runId: nil, runAttempt: nil, byVerifier: true))
        #expect(w.broker.releases.map(\.reason) == [.verifierKill])
    }

    @Test func completedRunReleasesWithCompletedAndTheAdmittedJob() async {
        let w = await Wiring()
        await w.controller.recordAllow(decision(.allow))
        await w.controller.markCompleted()
        await w.coordinator.cleanup(reason: "provisioner exited")
        #expect(w.broker.releases == [ReleaseRequest(reason: .completed, jobId: Spike.jobId, detail: "provisioner exited")])
    }

    @Test func signalShutdownReleasesWithShutdown() async {
        let w = await Wiring()
        await w.coordinator.cleanup(reason: "signal shutdown")
        #expect(w.broker.releases.map(\.reason) == [.shutdown])
    }

    @Test func otherFailuresReleaseAsVMFailed() async {
        let w = await Wiring()
        await w.coordinator.cleanup(reason: "admission relay setup failed")
        #expect(w.broker.releases.map(\.reason) == [.vmFailed])
    }

    @Test func secretsNeverReachAuditEvents() async {
        var allocation = Spike.allocation()
        allocation.jitConfig = "JIT-SECRET"
        let audit = AuditCollector()
        let controller = AdmissionController(allocation: allocation, deviceId: "dev", audit: audit.audit) { _ in }
        await controller.kill(.init(type: "admission.denied", reasons: ["nonce_mismatch"], jobId: nil, runId: nil, runAttempt: nil, byVerifier: false))
        for event in audit.events {
            #expect(!event.jsonLine().contains(allocation.nonce))
            #expect(!event.jsonLine().contains("JIT-SECRET"))
        }
    }

    @Test func runnerRedactsTheJITConfigAndNonceFromCommandLogs() throws {
        let allocation = Spike.allocation(nonce: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123456")
        let commands = try GitHubProvisioner().brokerScript(allocation: allocation, jitConfig: "JIT-SECRET-XYZ", egress: .standard)
        let logged = commands.map { Runner.redact($0.command + ($0.stdin ?? ""), secrets: ["JIT-SECRET-XYZ", allocation.nonce]) }.joined(separator: "\n")
        #expect(!logged.contains("JIT-SECRET-XYZ"))
        #expect(!logged.contains(allocation.nonce))
        #expect(logged.contains("[REDACTED]"))
    }

    @Test func admissionTunnelUsesTheGuestAdmissionPortWithoutEgress() {
        let ssh = SSHClient(processRunner: EventLog(), host: "192.168.64.5", config: .standard)
        let arguments = ssh.reverseTunnelArguments(remotePort: NetworkPolicy.guestAdmissionPort, localPort: 50123)
        #expect(arguments.contains("127.0.0.1:3129:127.0.0.1:50123"))
        #expect(NetworkPolicy.guestAdmissionPort != NetworkPolicy.guestProxyPort)
    }
}
