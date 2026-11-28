import Foundation
import Testing
@testable import sand

/// A process handle that runs until `finish()` (or a terminate), like `tart run`.
final class LiveHandleState: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    var finished: Bool { lock.withLock { done } }
    func finish() { lock.withLock { done = true } }

    func handle(pid: Int32? = nil) -> ProcessHandle {
        ProcessHandle(
            waitAsync: { [self] in
                while !self.finished {
                    try await Task.sleep(nanoseconds: 20_000_000)
                }
                return ProcessResult(stdout: "", stderr: "", exitCode: 0)
            },
            terminate: { [self] in self.finish() },
            hasExited: { [self] in self.finished },
            processIdentifier: pid
        )
    }
}

/// Fake host: tart + sshpass behave like a VM that boots, answers SSH and runs probes.
final class FakeVMHost: ProcessRunning, @unchecked Sendable {
    let lock = NSLock()
    var clones = 0
    var deletes = 0
    var stops = 0
    var executed: [String] = []
    var started: [String] = []
    var tunnelExitsImmediately = false
    var tunnelReady = true
    var probeOverrides: [String: String] = [:]
    var booted = false
    var tartRunState = LiveHandleState()
    var tartRun: LiveHandleState { lock.withLock { tartRunState } }
    private var tunnelState = LiveHandleState()
    var tunnel: LiveHandleState { lock.withLock { tunnelState } }
    /// When set, every `tart run` exits at once with this stderr (a dead network backend).
    var tartExitStderr: String?
    var tartRunArguments: [[String]] = []
    /// When set, the inspection-CA install prints this instead of the OK marker.
    var inspectionInstallOutput: String?

    func run(executable: String, arguments: [String], wait: Bool) async throws -> ProcessResult? {
        let ok = ProcessResult(stdout: "", stderr: "", exitCode: 0)
        if executable == "tart" {
            switch arguments.first {
            case "clone":
                lock.withLock { clones += 1 }
            case "delete":
                lock.withLock { deletes += 1 }
            case "stop":
                lock.withLock { stops += 1 }
                tartRun.finish()
            case "list":
                let running = lock.withLock { booted } && !tartRun.finished
                return ProcessResult(stdout: running ? #"[{"Name":"slot","Running":true}]"# : "[]", stderr: "", exitCode: 0)
            case "ip":
                if lock.withLock({ tartExitStderr }) != nil {
                    // No lease ever appears: the VM's network never came up.
                    try await Task.sleep(nanoseconds: 5_000_000_000)
                }
                return ProcessResult(stdout: "192.168.64.5\n", stderr: "", exitCode: 0)
            default:
                break
            }
            return ok
        }
        if executable == "sshpass" {
            let command = arguments.last ?? ""
            lock.withLock { executed.append(command) }
            if command.contains(GuestInspectionTrust.okMarker) {
                let output = lock.withLock { inspectionInstallOutput } ?? "\(GuestInspectionTrust.okMarker)\n"
                return ProcessResult(stdout: output, stderr: "", exitCode: 0)
            }
            if command.contains("SAND_TUNNEL_OK") {
                return ProcessResult(stdout: tunnelReady ? "SAND_TUNNEL_OK\n" : "", stderr: "", exitCode: 0)
            }
            if command.contains("SANDPROBE") {
                let overrides = lock.withLock { probeOverrides }
                // Answer every probe line the verifier script asked for.
                let verbs: Set<String> = ["tcp", "dnsq", "v6", "proxied", "denied", "routed", "routed6"]
                var ids: [String] = []
                for line in command.split(separator: "\n") {
                    let fields = line.split(separator: " ")
                    guard fields.count >= 2, verbs.contains(String(fields[0])), fields[1].first?.isUppercase == true else { continue }
                    ids.append(String(fields[1]))
                }
                let lines = ids.map { id in "SANDPROBE \(id) \(overrides[id] ?? (id == "P1" ? "OK http=200" : "CLOSED x"))" }
                return ProcessResult(stdout: lines.joined(separator: "\n"), stderr: "", exitCode: 0)
            }
        }
        return ok
    }

    func start(executable: String, arguments: [String]) throws -> ProcessHandle {
        // Under softnet, tart run is started by absolute path.
        if executable == "tart" || executable.hasSuffix("/tart") {
            lock.withLock { tartRunArguments.append(arguments) }
            if let stderr = lock.withLock({ tartExitStderr }) {
                lock.withLock { booted = true }
                let error = ProcessRunnerError.failed(exitCode: 1, stdout: "", stderr: stderr, command: ["tart"] + arguments)
                return ProcessHandle(waitAsync: { throw error }, terminate: {}, hasExited: { true })
            }
            // A fresh tart run per boot (recreated VMs get a new process).
            let state = LiveHandleState()
            lock.withLock {
                tartRunState = state
                booted = true
            }
            return state.handle()
        }
        if arguments.contains("-N") {
            // A fresh ssh -R per VM, like the real tunnel.
            let state = LiveHandleState()
            lock.withLock {
                started.append("tunnel")
                tunnelState = state
            }
            if tunnelExitsImmediately { state.finish() }
            return state.handle()
        }
        lock.withLock { started.append(arguments.last ?? "") }
        return ProcessHandle(waitAsync: { ProcessResult(stdout: "", stderr: "", exitCode: 0) }, terminate: {})
    }
}

/// Wraps FakeVMHost so one provisioner command blocks until released.
final class BlockingProvisioner: ProcessRunning, @unchecked Sendable {
    let inner: FakeVMHost
    let blocking: LiveHandleState

    init(inner: FakeVMHost, blocking: LiveHandleState) {
        self.inner = inner
        self.blocking = blocking
    }

    func run(executable: String, arguments: [String], wait: Bool) async throws -> ProcessResult? {
        try await inner.run(executable: executable, arguments: arguments, wait: wait)
    }

    func start(executable: String, arguments: [String]) throws -> ProcessHandle {
        if arguments.last?.contains("sleep-forever-marker") == true {
            return blocking.handle()
        }
        return try inner.start(executable: executable, arguments: arguments)
    }
}

final class FakeProxy: EgressProxying, @unchecked Sendable {
    private let lock = NSLock()
    private var failed = false
    var stopped = false
    func start(port: UInt16) async throws -> UInt16 { 40_123 }
    func stop() { lock.withLock { stopped = true } }
    var hasFailed: Bool { lock.withLock { failed || stopped } }
    func fail() { lock.withLock { failed = true } }
}

func dependencies(
    host: FakeVMHost,
    proxy: FakeProxy,
    routes: RouteInspector = RouteInspector(routes: []),
    fileSystem: FakeFileSystem = FakeFileSystem(),
    recorder: AuditRecorder
) -> RunnerNetworkDependencies {
    var deps = RunnerNetworkDependencies(
        preflight: NetworkPreflight(
            processRunner: ScriptedProcessRunner(responder: currentToolHelp),
            fileSystem: fileSystem,
            resolver: StaticHostResolver(table: ["github.com": [IPAddress("140.82.112.3")!]]),
            hostProbe: FakeHostProbe(),
            proxySelfTest: nil
        ),
        resolver: StaticHostResolver(table: ["github.com": [IPAddress("140.82.112.3")!]]),
        hostFacts: { HostFacts() },
        routes: { routes },
        makeProxy: { _, _, _ in proxy },
        audit: recorder.audit
    )
    deps.watchdogInterval = 0.05
    deps.tunnelReadyTimeout = 1
    deps.ipForwarding = { IPForwardingState(ipv4: 0, ipv6: 0) }
    deps.bridgeAddresses = { _ in [IPAddress("192.168.64.1")!] }
    return deps
}

func makeRunner(host: ProcessRunning, network: RunnerNetworkDependencies, run: String = "echo provisioned-marker", policy: NetworkConfig = NetworkConfig(selection: .profile(.github), backend: .hostOnly), stopAfter: Int? = 1) -> Runner {
    let logger = Logger(label: "test", minimumLevel: .critical)
    let tart = Tart(processRunner: host, logger: logger, isExecutable: { $0.hasSuffix("/tart") })
    let vm = Config.VM(source: .init(type: .local, image: nil, name: "golden"), hardware: nil, mounts: [], cache: nil, run: .init(noGraphics: true, noClipboard: true, nested: false, network: policy), diskSizeGb: nil, ssh: .standard)
    let config = Config.RunnerConfig(name: "slot", vm: vm, provisioner: .init(type: .script, script: .init(run: run), github: nil), preRun: nil, postRun: nil, stopAfter: stopAfter, healthCheck: Config.HealthCheck(command: "true", interval: 30, delay: 600))
    return Runner(
        tart: tart, github: nil, provisioner: GitHubProvisioner(), runnerVersionResolver: GitHubRunnerVersionResolver(),
        runnerCache: RunnerCache(), config: config,
        shutdownCoordinator: VMShutdownCoordinator(destroyer: VMDestroyer(tart: tart, logger: logger), logger: logger),
        control: RunnerControl(), vmName: "slot", logLabel: "slot", logLevel: .critical, logSink: nil,
        network: network
    )
}

@Suite(.serialized) struct RunnerNetworkTests {
    @Test func failedPreflightNeverClones() async {
        let host = FakeVMHost()
        var fileSystem = FakeFileSystem()
        fileSystem.paths["softnet"] = nil
        let recorder = AuditRecorder()
        let runner = makeRunner(host: host, network: dependencies(host: host, proxy: FakeProxy(), fileSystem: fileSystem, recorder: recorder), policy: NetworkConfig(selection: .profile(.github), backend: .softnet))
        await #expect(throws: NetworkEnforcementError.self) { try await runner.run() }
        #expect(host.clones == 0)
        #expect(recorder.events.contains { $0.name == "network.preflight.failed" })
    }

    @Test func verifiedVMProvisionsWithGuestProxySettings() async throws {
        let host = FakeVMHost()
        let proxy = FakeProxy()
        let recorder = AuditRecorder()
        let runner = makeRunner(host: host, network: dependencies(host: host, proxy: proxy, recorder: recorder))
        try await runner.run()
        let executed = host.lock.withLock { host.executed }
        let started = host.lock.withLock { host.started }
        #expect(started.first == "tunnel")
        let setupIndex = executed.firstIndex { $0.contains("networksetup") }
        #expect(setupIndex != nil)
        #expect(started.contains { $0.contains("provisioned-marker") })
        #expect(recorder.events.contains { $0.name == "network.guest.verified" })
        #expect(proxy.stopped)
        #expect(host.deletes >= 2, "leftover delete plus teardown delete")
        #expect(!recorder.events.contains { $0.name == "network.enforcement.lost" })
    }

    @Test func tunnelExitStopsAndDeletesWithoutProvisioning() async {
        let host = FakeVMHost()
        host.tunnelExitsImmediately = true
        let recorder = AuditRecorder()
        let runner = makeRunner(host: host, network: dependencies(host: host, proxy: FakeProxy(), recorder: recorder))
        await #expect(throws: NetworkEnforcementError.self) { try await runner.run() }
        #expect(host.stops >= 1)
        #expect(host.deletes >= 2)
        #expect(!host.lock.withLock { host.started }.contains { $0.contains("provisioned-marker") })
    }

    @Test func verifierFailureMeansNoRegistration() async {
        let host = FakeVMHost()
        host.probeOverrides = ["N2": "OPEN 140.82.112.3:443"]
        let recorder = AuditRecorder()
        let runner = makeRunner(host: host, network: dependencies(host: host, proxy: FakeProxy(), recorder: recorder))
        await #expect(throws: NetworkEnforcementError.self) { try await runner.run() }
        #expect(!host.lock.withLock { host.started }.contains { $0.contains("provisioned-marker") })
        #expect(recorder.events.contains { $0.name == "network.guest.verify" && $0.fields["failed"] == "N2:OPEN" })
        #expect(host.stops >= 1)
    }

    @Test func subnetOverlapRecreatesThenGivesUp() async {
        let host = FakeVMHost()
        let routes = RouteInspector(netstatOutput: "192.168.64/24      link#31            UCS                 utun9")
        let recorder = AuditRecorder()
        let runner = makeRunner(host: host, network: dependencies(host: host, proxy: FakeProxy(), routes: routes, recorder: recorder), policy: NetworkConfig(selection: .profile(.github), maxEnforcementFailures: 2))
        await #expect(throws: NetworkEnforcementError.self) { try await runner.run() }
        // Three recreations per attempt, and the repeated overlap counts toward the limit (exit 78), not forever.
        #expect(host.clones == 6)
        let failed = recorder.events.filter { $0.name == "network.enforcement.failed" }
        #expect(failed.map { $0.fields["reason"] } == ["subnet-overlap", "subnet-overlap"])
        #expect(failed.last?.fields["final"] == "true")
        #expect(host.lock.withLock { host.started }.filter { $0 == "tunnel" }.isEmpty)
    }

    @Test func proxyFailureMidJobStopsTheVM() async throws {
        let host = FakeVMHost()
        let proxy = FakeProxy()
        let recorder = AuditRecorder()
        // The provisioner command never finishes on its own; only enforcement loss ends it.
        let blocking = LiveHandleState()
        let real = makeRunner(host: BlockingProvisioner(inner: host, blocking: blocking), network: dependencies(host: host, proxy: proxy, recorder: recorder), run: "sleep-forever-marker")
        let task = Task { try await real.run() }
        for _ in 0..<100 where !host.lock.withLock({ host.executed }).contains(where: { $0.contains("networksetup") }) {
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        try await Task.sleep(nanoseconds: 200_000_000)
        proxy.fail()
        _ = try? await task.value
        blocking.finish()
        #expect(recorder.events.contains { $0.name == "network.enforcement.lost" && $0.fields["component"] == "proxy" })
        #expect(host.stops >= 1)
    }
}
