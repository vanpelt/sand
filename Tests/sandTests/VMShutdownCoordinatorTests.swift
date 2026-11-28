import XCTest
@testable import sand

private actor StopGate {
    private var stopStarted = false
    private var startedWaiters: [CheckedContinuation<Void, Never>] = []
    private var releaseWaiter: CheckedContinuation<Void, Never>?
    private(set) var deleted = false

    func enterStop() async {
        stopStarted = true
        startedWaiters.forEach { $0.resume() }
        startedWaiters = []
        await withCheckedContinuation { releaseWaiter = $0 }
    }

    func waitUntilStopStarted() async {
        if stopStarted {
            return
        }
        await withCheckedContinuation { startedWaiters.append($0) }
    }

    func release() {
        releaseWaiter?.resume()
        releaseWaiter = nil
    }

    func markDeleted() {
        deleted = true
    }
}

private struct GatedStopRunner: ProcessRunning {
    let gate: StopGate

    func run(executable: String, arguments: [String], wait: Bool) async throws -> ProcessResult? {
        switch arguments.first {
        case "stop":
            await gate.enterStop()
        case "delete":
            await gate.markDeleted()
        default:
            break
        }
        return ProcessResult(stdout: "", stderr: "", exitCode: 0)
    }

    func start(executable: String, arguments: [String]) throws -> ProcessHandle {
        ProcessHandle(waitAsync: { ProcessResult(stdout: "", stderr: "", exitCode: 0) }, terminate: {})
    }
}

final class VMShutdownCoordinatorTests: XCTestCase {
    func testConcurrentCleanupWaitsForInFlightDestroy() async throws {
        let gate = StopGate()
        let logger = Logger(label: "shutdown.test", minimumLevel: .critical)
        let coordinator = VMShutdownCoordinator(
            destroyer: VMDestroyer(tart: makeTart(GatedStopRunner(gate: gate)), logger: logger),
            logger: logger
        )
        await coordinator.activate(name: "vm")
        let first = Task { await coordinator.cleanup(reason: "runner") }
        await gate.waitUntilStopStarted()
        let second = Task {
            await coordinator.cleanup(reason: "signal")
            return await gate.deleted
        }
        try await Task.sleep(nanoseconds: 50_000_000)
        await gate.release()
        let deletedBeforeSecondReturned = await second.value
        await first.value
        XCTAssertTrue(deletedBeforeSecondReturned)
    }

    func testCleanupWithoutActiveVMIsNoop() async {
        let gate = StopGate()
        let logger = Logger(label: "shutdown.test", minimumLevel: .critical)
        let coordinator = VMShutdownCoordinator(
            destroyer: VMDestroyer(tart: makeTart(GatedStopRunner(gate: gate)), logger: logger),
            logger: logger
        )
        await coordinator.cleanup(reason: "signal")
        let deleted = await gate.deleted
        XCTAssertFalse(deleted)
    }

    func testCleanupDeregistersAfterDestroyingVM() async {
        let gate = StopGate()
        let logger = Logger(label: "shutdown.test", minimumLevel: .critical)
        let coordinator = VMShutdownCoordinator(
            destroyer: VMDestroyer(tart: makeTart(GatedStopRunner(gate: gate)), logger: logger),
            logger: logger
        )
        let deletedAtDeregistration = DeregistrationProbe()
        await coordinator.activate(name: "vm")
        await coordinator.setDeregistration {
            await deletedAtDeregistration.record(await gate.deleted)
        }
        let cleanup = Task { await coordinator.cleanup(reason: "runner") }
        await gate.waitUntilStopStarted()
        await gate.release()
        await cleanup.value
        let observed = await deletedAtDeregistration.values
        XCTAssertEqual(observed, [true])
    }
}

/// `tart delete` fails a given number of times; `tart list` reports the VM present.
private final class FlakyDeleteRunner: ProcessRunning, @unchecked Sendable {
    private let lock = NSLock()
    private var failuresLeft: Int
    private(set) var deletes = 0
    init(failures: Int) { failuresLeft = failures }

    func run(executable: String, arguments: [String], wait: Bool) async throws -> ProcessResult? {
        switch arguments.first {
        case "delete":
            let fail = lock.withLock { () -> Bool in
                deletes += 1
                if failuresLeft > 0 { failuresLeft -= 1; return true }
                return false
            }
            if fail { throw ProcessRunnerError.failed(exitCode: 1, stdout: "", stderr: "busy", command: ["tart"] + arguments) }
        case "list":
            return ProcessResult(stdout: #"[{"Name":"vm","State":"stopped","Source":"local"}]"#, stderr: "", exitCode: 0)
        default:
            break
        }
        return ProcessResult(stdout: "", stderr: "", exitCode: 0)
    }

    func start(executable: String, arguments: [String]) throws -> ProcessHandle {
        ProcessHandle(waitAsync: { ProcessResult(stdout: "", stderr: "", exitCode: 0) }, terminate: {})
    }
}

final class VMDestroyerRetryTests: XCTestCase {
    func testDeleteIsRetried() async throws {
        let runner = FlakyDeleteRunner(failures: 2)
        var destroyer = VMDestroyer(tart: makeTart(runner), logger: Logger(label: "t", minimumLevel: .critical))
        destroyer.deleteRetryDelays = [0, 0]
        try await destroyer.destroy(name: "vm")
        XCTAssertEqual(runner.deletes, 3)
    }

    /// Finding 6: a VM that cannot be deleted is reported, not ignored.
    func testPersistentDeleteFailureIsRecordedAndStillDeregisters() async {
        let runner = FlakyDeleteRunner(failures: 10)
        let logger = Logger(label: "t", minimumLevel: .critical)
        var destroyer = VMDestroyer(tart: makeTart(runner), logger: logger)
        destroyer.deleteRetryDelays = [0, 0]
        let coordinator = VMShutdownCoordinator(destroyer: destroyer, logger: logger)
        let probe = DeregistrationProbe()
        await coordinator.activate(name: "vm")
        await coordinator.setDeregistration { await probe.record(true) }
        await coordinator.cleanup(reason: "admission denied")
        let failures = await coordinator.destroyFailures
        XCTAssertEqual(failures, ["vm"])
        XCTAssertEqual(runner.deletes, 3)
        let released = await probe.values
        XCTAssertEqual(released, [true])
    }
}

private actor DeregistrationProbe {
    private(set) var values: [Bool] = []

    func record(_ value: Bool) {
        values.append(value)
    }
}
