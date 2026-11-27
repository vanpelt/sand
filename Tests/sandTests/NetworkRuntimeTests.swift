import Foundation
import Testing
@testable import sand

/// Scriptable process runner: answers by executable + first argument.
final class ScriptedProcessRunner: ProcessRunning, @unchecked Sendable {
    struct Call: Equatable {
        let executable: String
        let arguments: [String]
        let environment: [String: String]?
    }

    private let lock = NSLock()
    private var storage: [Call] = []
    var responder: @Sendable (String, [String]) throws -> ProcessResult

    init(responder: @escaping @Sendable (String, [String]) throws -> ProcessResult = { _, _ in ProcessResult(stdout: "", stderr: "", exitCode: 0) }) {
        self.responder = responder
    }

    var calls: [Call] { lock.withLock { storage } }

    func run(executable: String, arguments: [String], wait: Bool) async throws -> ProcessResult? {
        try await run(executable: executable, arguments: arguments, wait: wait, environment: nil)
    }

    func start(executable: String, arguments: [String]) throws -> ProcessHandle {
        try start(executable: executable, arguments: arguments, environment: nil)
    }

    func run(executable: String, arguments: [String], wait: Bool, environment: [String: String]?) async throws -> ProcessResult? {
        lock.withLock { storage.append(Call(executable: executable, arguments: arguments, environment: environment)) }
        return try responder(executable, arguments)
    }

    func start(executable: String, arguments: [String], environment: [String: String]?) throws -> ProcessHandle {
        lock.withLock { storage.append(Call(executable: executable, arguments: arguments, environment: environment)) }
        return ProcessHandle(waitAsync: { ProcessResult(stdout: "", stderr: "", exitCode: 0) }, terminate: {}, hasExited: { false })
    }
}

func failure(_ executable: String, _ arguments: [String], code: Int32 = 1) -> ProcessRunnerError {
    .failed(exitCode: code, stdout: "", stderr: "", command: [executable] + arguments)
}

struct FakeFileSystem: PreflightFileSystem {
    var paths: [String: String] = ["tart": "/opt/homebrew/bin/tart", "softnet": "/opt/homebrew/bin/softnet", "ssh": "/usr/bin/ssh", "sshpass": "/opt/homebrew/bin/sshpass"]
    var owner: (uid: UInt32, mode: UInt16)? = (0, UInt16(S_ISUID) | 0o755)
    var free: Int64? = 100_000_000_000

    func which(_ command: String) -> String? { paths[command] }
    func realpath(_ path: String) -> String { path.replacingOccurrences(of: "/opt/homebrew/bin", with: "/opt/homebrew/Cellar/softnet/0.26.0/bin") }
    func ownerAndMode(_ path: String) -> (uid: UInt32, mode: UInt16)? { owner }
    func freeBytes(atPath path: String) -> Int64? { free }
}

struct FakeHostProbe: HostEgressProbing {
    var succeed = true
    func tlsHandshake(host: String, port: UInt16, timeout: TimeInterval) async -> Result<Void, Error> {
        succeed ? .success(()) : .failure(HostEgressProbeError.timeout)
    }
}

let currentToolHelp: @Sendable (String, [String]) throws -> ProcessResult = { executable, arguments in
    if executable == "tart", arguments == ["run", "--help"] {
        return ProcessResult(stdout: "--net-softnet-allow <comma-separated CIDRs>", stderr: "", exitCode: 0)
    }
    if executable == "tart", arguments == ["--version"] {
        return ProcessResult(stdout: "2.42.0\n", stderr: "", exitCode: 0)
    }
    if executable.hasSuffix("softnet"), arguments == ["--help"] {
        return ProcessResult(stdout: "out [proto PROTO] [TARGET] [port PORT] ... @host", stderr: "", exitCode: 0)
    }
    if executable == "sudo" {
        throw failure(executable, arguments)
    }
    return ProcessResult(stdout: "", stderr: "", exitCode: 0)
}

func makePreflight(runner: ScriptedProcessRunner, fileSystem: FakeFileSystem = FakeFileSystem(), resolver: HostResolving = StaticHostResolver(table: ["github.com": [IPAddress("172.16.7.60")!], "api.github.com": [IPAddress("172.16.0.150")!]]), probe: FakeHostProbe = FakeHostProbe()) -> NetworkPreflight {
    NetworkPreflight(processRunner: runner, fileSystem: fileSystem, resolver: resolver, hostProbe: probe, proxySelfTest: nil)
}

@Suite struct NetworkPreflightTests {
    let github = try! NetworkConfig.secureDefault.compile()

    @Test func preparedHostPasses() async {
        let checks = await makePreflight(runner: ScriptedProcessRunner(responder: currentToolHelp)).run(policy: github)
        #expect(NetworkPreflight.failures(checks).isEmpty, "\(checks.map(\.line))")
        #expect(checks.contains { $0.name == "P4 GitHub egress" && $0.detail.contains("VPN-steered") })
    }

    @Test func missingSoftnetFails() async {
        var fileSystem = FakeFileSystem()
        fileSystem.paths["softnet"] = nil
        let failures = NetworkPreflight.failures(await makePreflight(runner: ScriptedProcessRunner(responder: currentToolHelp), fileSystem: fileSystem).run(policy: github))
        #expect(failures.contains { $0.name == "P2 softnet" })
    }

    @Test func softnetWithoutPrivilegeFailsWithRemediation() async {
        var fileSystem = FakeFileSystem()
        fileSystem.owner = (501, 0o755)
        let runner = ScriptedProcessRunner(responder: currentToolHelp)
        let failures = NetworkPreflight.failures(await makePreflight(runner: runner, fileSystem: fileSystem).run(policy: github))
        let privilege = failures.first { $0.name == "P3 softnet privilege" }
        #expect(privilege?.remediation?.contains("chmod u+s") == true)
        // Only ever non-interactive sudo.
        #expect(runner.calls.filter { $0.executable == "sudo" }.allSatisfy { $0.arguments.first == "-n" })
        #expect(!runner.calls.filter { $0.executable == "sudo" }.isEmpty)
    }

    @Test func passwordlessSudoIsAccepted() async {
        var fileSystem = FakeFileSystem()
        fileSystem.owner = (501, 0o755)
        let runner = ScriptedProcessRunner { executable, arguments in
            if executable == "sudo" { return ProcessResult(stdout: "", stderr: "", exitCode: 0) }
            return try currentToolHelp(executable, arguments)
        }
        let check = await makePreflight(runner: runner, fileSystem: fileSystem).checkSoftnetPrivilege()
        #expect(check.status == .ok)
    }

    @Test func oldTartOrSoftnetFails() async {
        let runner = ScriptedProcessRunner { _, _ in ProcessResult(stdout: "--net-softnet", stderr: "", exitCode: 0) }
        let failures = NetworkPreflight.failures(await makePreflight(runner: runner).run(policy: github))
        #expect(failures.contains { $0.name == "P1 tart" })
        #expect(failures.contains { $0.name == "P2 softnet" && $0.detail.contains("too old") })
    }

    @Test func hostWithoutGitHubEgressFails() async {
        let failures = NetworkPreflight.failures(await makePreflight(runner: ScriptedProcessRunner(responder: currentToolHelp), probe: FakeHostProbe(succeed: false)).run(policy: github))
        #expect(failures.contains { $0.name == "P4 GitHub egress" })
    }

    @Test func sharedPolicyOnlyWarns() async {
        let runner = ScriptedProcessRunner(responder: currentToolHelp)
        let checks = await makePreflight(runner: runner).run(policy: .shared)
        #expect(checks.allSatisfy { $0.status == .warning })
        #expect(runner.calls.isEmpty)
    }

    @Test func perVMRecheckCoversPrivilegeAndResolution() async {
        var fileSystem = FakeFileSystem()
        fileSystem.owner = (501, 0o755)
        let failures = NetworkPreflight.failures(await makePreflight(runner: ScriptedProcessRunner(responder: currentToolHelp), fileSystem: fileSystem, resolver: StaticHostResolver(table: [:])).perVM(policy: github))
        #expect(failures.map(\.name) == ["P3 softnet privilege", "P4 resolve github.com"])
    }
}

@Suite struct GuestEgressVerifierTests {
    let verifier = GuestEgressVerifier(level: .basic, directGitHubAddress: "172.16.7.60")

    private func transcript(_ overrides: [String: String] = [:]) -> String {
        verifier.probes.map { probe in
            let outcome = overrides[probe.id] ?? (probe.expectation == .proxyWorks ? "OK http=200" : "CLOSED x")
            return "SANDPROBE \(probe.id) \(outcome)"
        }.joined(separator: "\n")
    }

    @Test func allClosedPlusProxyPasses() {
        let results = verifier.evaluate("noise\n" + transcript())
        #expect(results.allSatisfy { $0.passed })
        #expect(results.map(\.id) == ["N1", "N2", "N3a", "N3b", "N3c", "N4a", "N4b", "N5", "P1"])
    }

    @Test func anyOpenNegativeFails() {
        let results = verifier.evaluate(transcript(["N2": "OPEN 172.16.7.60:443"]))
        #expect(results.first { $0.id == "N2" }?.passed == false)
    }

    @Test func missingProbeFails() {
        let output = transcript().split(separator: "\n").filter { !$0.contains(" N5 ") }.joined(separator: "\n")
        #expect(verifier.evaluate(output).first { $0.id == "N5" }?.outcome == "MISSING")
    }

    @Test func proxyFailureFailsAndInconclusiveDNSPasses() {
        let results = verifier.evaluate(transcript(["P1": "FAIL http=000", "N4b": "INCONCLUSIVE no-dig", "N1": "INCONCLUSIVE no-nc"]))
        #expect(results.first { $0.id == "P1" }?.passed == false)
        #expect(results.first { $0.id == "N4b" }?.passed == true)
        #expect(results.first { $0.id == "N1" }?.passed == false)
    }

    @Test func duplicateLinesKeepTheWorstOutcome() {
        #expect(GuestEgressVerifier.parse("SANDPROBE N1 OPEN a\nSANDPROBE N1 CLOSED b")["N1"]?.0 == "OPEN")
        #expect(GuestEgressVerifier.parse("SANDPROBE N1 CLOSED a\nSANDPROBE N1 OPEN b")["N1"]?.0 == "OPEN")
    }

    @Test func strictAddsHostDerivedTargets() {
        let strict = GuestEgressVerifier(level: .strict, directGitHubAddress: "140.82.112.3", strictTargets: .init(lanGateway: "10.0.0.1", hostLANAddress: "10.0.0.152", tunnelTargets: ["172.16.0.1"]))
        let ids = strict.probes.map(\.id)
        #expect(ids.contains("S1") && ids.contains("S5") && ids.contains("S7") && ids.contains("T1"))
        #expect(strict.script.contains("unset https_proxy http_proxy"))
        #expect(GuestEgressVerifier(level: .off, directGitHubAddress: "x").probes.isEmpty)
    }
}

@Suite struct StrictTargetTests {
    @Test func derivesLANAndVPNTargetsWithoutMulticast() {
        let routes = RouteInspector(netstatOutput: """
        default            10.0.0.1           UGScg                en12
        172.16             link#29            UCS                 utun8
        224.0.0/4          link#29            UmCSI               utun8
        100.64/10          link#25            UCS                 utun4
        """)
        let facts = HostFacts(interfaceAddresses: [IPAddress("10.0.0.152")!], onLinkSubnets: [IPNetwork("10.0.0.0/24")!])
        let targets = GuestEgressVerifier.StrictTargets.derive(facts: facts, routes: routes)
        #expect(targets.lanGateway == "10.0.0.1")
        #expect(targets.hostLANAddress == "10.0.0.152")
        #expect(targets.tunnelTargets == ["172.16.0.1", "100.64.0.1"])
    }
}

@Suite struct NetworkWatchdogTests {
    final class Flag: @unchecked Sendable {
        private let lock = NSLock()
        private var value = false
        func set() { lock.withLock { value = true } }
        var isSet: Bool { lock.withLock { value } }
    }

    final class Box: @unchecked Sendable {
        private let lock = NSLock()
        private var value: String?
        func set(_ v: String) { lock.withLock { value = v } }
        var current: String? { lock.withLock { value } }
    }

    func handle(_ exited: Flag) -> ProcessHandle {
        ProcessHandle(waitAsync: { ProcessResult(stdout: "", stderr: "", exitCode: 0) }, terminate: {}, hasExited: { exited.isSet }, processIdentifier: 4242)
    }

    @Test func tunnelExitFiresOnceWithinAPoll() async throws {
        let tartExited = Flag()
        let tunnelExited = Flag()
        let lost = Box()
        let runner = ScriptedProcessRunner()
        let watchdog = NetworkWatchdog(
            components: .init(tartRun: handle(tartExited), tunnel: handle(tunnelExited), proxy: nil, checkSoftnet: true, routeOverlap: nil),
            interval: 0.05,
            processRunner: runner
        ) { component in lost.set(component) }
        await watchdog.start()
        try await Task.sleep(nanoseconds: 150_000_000)
        #expect(lost.current == nil)
        tunnelExited.set()
        for _ in 0..<40 where lost.current == nil {
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        #expect(lost.current == "tunnel")
        #expect(runner.calls.contains { $0.executable == "pgrep" && $0.arguments == ["-f", "-P", "4242", "softnet"] })
        await watchdog.stop()
    }

    @Test func missingSoftnetChildIsDetected() async {
        let runner = ScriptedProcessRunner { executable, arguments in
            if executable == "pgrep" { throw failure(executable, arguments) }
            return ProcessResult(stdout: "", stderr: "", exitCode: 0)
        }
        let watchdog = NetworkWatchdog(components: .init(tartRun: handle(Flag()), tunnel: nil, proxy: nil, checkSoftnet: true, routeOverlap: nil), processRunner: runner) { _ in }
        #expect(await watchdog.firstFailure() == "softnet")
    }

    @Test func tartExitAndRouteOverlapAreDetected() async {
        let exited = Flag()
        exited.set()
        let tart = NetworkWatchdog(components: .init(tartRun: handle(exited), tunnel: nil, proxy: nil, checkSoftnet: false, routeOverlap: nil), processRunner: ScriptedProcessRunner()) { _ in }
        #expect(await tart.firstFailure() == "tart")
        let route = NetworkWatchdog(components: .init(tartRun: handle(Flag()), tunnel: nil, proxy: nil, checkSoftnet: false, routeOverlap: { "172.16.0.0/16@utun8" }), processRunner: ScriptedProcessRunner()) { _ in }
        #expect(await route.firstFailure() == "route-overlap(172.16.0.0/16@utun8)")
    }
}

@Suite struct TartEnvironmentTests {
    @Test func tartNeverReceivesSentryVariables() async throws {
        let runner = ScriptedProcessRunner()
        let tart = Tart(processRunner: runner, logger: Logger(label: "test", minimumLevel: .critical))
        _ = try tart.run(name: "vm", options: .init(directoryMounts: [], noAudio: true, noGraphics: true, noClipboard: true, nested: false, network: try NetworkConfig.secureDefault.compile()))
        try await tart.clone(source: "a", name: "b")
        let scrubbed = Tart.scrubbedEnvironment(["SENTRY_DSN": "x", "CIRRUS_SENTRY_TAGS": "y", "PATH": "/bin"])
        #expect(scrubbed == ["PATH": "/bin"])
        #expect(runner.calls.count == 2)
        for call in runner.calls {
            let environment = try #require(call.environment)
            #expect(environment["SENTRY_DSN"] == nil && environment["CIRRUS_SENTRY_TAGS"] == nil)
        }
        #expect(runner.calls.first?.arguments.prefix(5) == ["run", "vm", "--net-softnet", "--net-softnet-block=0.0.0.0/0", "--net-softnet-allow=in proto tcp @host port 22"])
    }

    @Test func reverseTunnelBindsGuestLoopbackAndFailsOnForwardFailure() {
        let ssh = SSHClient(processRunner: ScriptedProcessRunner(), host: "192.168.64.3", config: .standard)
        let arguments = ssh.reverseTunnelArguments(remotePort: 3128, localPort: 50123)
        #expect(arguments.contains("-N"))
        #expect(arguments.contains("ExitOnForwardFailure=yes"))
        let reverse = arguments.firstIndex(of: "-R")
        #expect(reverse.map { arguments[$0 + 1] } == "127.0.0.1:3128:127.0.0.1:50123")
        // ssh keeps the first value for an option: the tunnel's keepalive must win.
        let first = arguments.firstIndex(of: "ServerAliveInterval=15")
        let shared = arguments.firstIndex(of: "ServerAliveInterval=30")
        #expect(first != nil && shared != nil && first! < shared!)
        #expect(arguments.last == "admin@192.168.64.3")
    }
}
