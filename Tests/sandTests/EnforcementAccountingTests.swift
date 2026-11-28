import Foundation
import Testing
@testable import sand

/// Every provisioner command containing the marker blocks until terminated, with
/// a fresh handle per VM (so each recreated VM's job blocks again).
private final class FreshBlockingProvisioner: ProcessRunning, @unchecked Sendable {
    let inner: FakeVMHost
    init(inner: FakeVMHost) { self.inner = inner }

    func run(executable: String, arguments: [String], wait: Bool) async throws -> ProcessResult? {
        try await inner.run(executable: executable, arguments: arguments, wait: wait)
    }

    func start(executable: String, arguments: [String]) throws -> ProcessHandle {
        if arguments.last?.contains("sleep-forever-marker") == true {
            return LiveHandleState().handle()
        }
        return try inner.start(executable: executable, arguments: arguments)
    }
}

/// A proxy that dies shortly after it starts: enforcement is lost during every job.
private final class DyingProxy: EgressProxying, @unchecked Sendable {
    private let lock = NSLock()
    private var startedAt: Date?
    func start(port: UInt16) async throws -> UInt16 {
        lock.withLock { startedAt = Date() }
        return 40_124
    }
    func stop() {}
    var hasFailed: Bool {
        lock.withLock { startedAt.map { Date().timeIntervalSince($0) > 0.4 } ?? false }
    }
}

private func waitUntil(_ condition: () -> Bool) async throws {
    for _ in 0..<250 where !condition() {
        try await Task.sleep(nanoseconds: 20_000_000)
    }
}

@Suite(.serialized) struct EnforcementAccountingTests {
    @Test func stopAfterEarlyBackendExitRetriesThenExits78() async throws {
        let host = FakeVMHost()
        host.tartExitStderr = "Error: Softnet process terminated prematurely"
        let recorder = AuditRecorder()
        let runner = makeRunner(
            host: host, network: dependencies(host: host, proxy: FakeProxy(), recorder: recorder),
            policy: NetworkConfig(selection: .profile(.github), backend: .softnet, maxEnforcementFailures: 2), stopAfter: 1
        )
        var thrown: Error?
        do { try await runner.run() } catch { thrown = error }
        // Not a finished iteration: before the fix this returned normally (exit 0).
        let error = try #require(thrown as? NetworkEnforcementError)
        guard case .gaveUp = error else { Issue.record("expected gaveUp, got \(error)"); return }
        let failed = recorder.events.filter { $0.name == "network.enforcement.failed" }
        #expect(failed.map { $0.fields["final"] } == ["false", "true"])
        #expect(host.clones == 2)
    }

    @Test func inspectionCAInstallFailureIsCountedAndReachesTheLimit() async throws {
        let host = FakeVMHost()
        host.inspectionInstallOutput = "ERROR: no default CA bundle found in the guest\n"
        let recorder = AuditRecorder()
        var deps = dependencies(host: host, proxy: FakeProxy(), recorder: recorder)
        deps.makeProxy = { _, _, _ in FakeProxy() }
        deps.inspectionCAs = [InspectionCA(sha256: "AA77", subject: "Inspection Root", pem: "x", isRoot: true)]
        let runner = makeRunner(
            host: host, network: deps,
            policy: NetworkConfig(selection: .profile(.github), backend: .hostOnly, tlsInspection: .trustHostCA, maxEnforcementFailures: 2), stopAfter: nil
        )
        await #expect(throws: NetworkEnforcementError.self) { try await runner.run() }
        let failed = recorder.events.filter { $0.name == "network.enforcement.failed" }
        #expect(failed.map { $0.fields["reason"] } == ["inspection-ca", "inspection-ca"])
        #expect(failed.map { $0.fields["stage"] } == ["inspection-ca", "inspection-ca"])
        #expect(failed.last?.fields["final"] == "true")
        #expect(!host.lock.withLock { host.started }.contains { $0.contains("provisioned-marker") })
        #expect(host.clones == 2)
    }

    @Test func perVMPreflightFailureIsCountedAndReachesTheLimit() async throws {
        let host = FakeVMHost()
        let recorder = AuditRecorder()
        var deps = dependencies(host: host, proxy: FakeProxy(), recorder: recorder)
        var fileSystem = FakeFileSystem()
        fileSystem.sysctls[IPForwardingState.ipv4Name] = 1
        deps.preflight = NetworkPreflight(
            processRunner: ScriptedProcessRunner(responder: currentToolHelp), fileSystem: fileSystem,
            resolver: StaticHostResolver(table: ["github.com": [IPAddress("140.82.112.3")!]]), hostProbe: FakeHostProbe(), proxySelfTest: nil
        )
        let runner = makeRunner(host: host, network: deps, policy: NetworkConfig(selection: .profile(.github), backend: .hostOnly, maxEnforcementFailures: 2), stopAfter: nil)
        await #expect(throws: NetworkEnforcementError.self) { try await runner.run() }
        let failed = recorder.events.filter { $0.name == "network.enforcement.failed" }
        #expect(failed.map { $0.fields["stage"] } == ["per-vm-preflight", "per-vm-preflight"])
        #expect(failed.first?.fields["detail"]?.contains("P11 host IP forwarding") == true)
        #expect(host.clones == 0)
    }

    @Test func lossDuringAJobUnderStopAfterExits78() async throws {
        let host = FakeVMHost()
        let proxy = FakeProxy()
        let recorder = AuditRecorder()
        let runner = makeRunner(host: FreshBlockingProvisioner(inner: host), network: dependencies(host: host, proxy: proxy, recorder: recorder), run: "sleep-forever-marker", stopAfter: 1)
        let task = Task { try await runner.run() }
        try await waitUntil { host.lock.withLock { host.executed }.contains { $0.contains("networksetup") } }
        try await Task.sleep(nanoseconds: 200_000_000)
        proxy.fail()
        var thrown: Error?
        do { try await task.value } catch { thrown = error }
        let error = try #require(thrown as? NetworkEnforcementError)
        #expect(error.isFatal)
        guard case .enforcementLost(component: "proxy") = error else { Issue.record("expected enforcementLost(proxy), got \(error)"); return }
        #expect(recorder.events.contains { $0.name == "network.enforcement.lost" && $0.fields["component"] == "proxy" })
        #expect(recorder.events.contains { $0.name == "network.enforcement.failed" && $0.fields["stage"] == "job" && $0.fields["final"] == "true" })
        #expect(host.clones == 1)
    }

    @Test func repeatedLossDuringJobsReachesTheLimitWithoutStopAfter() async throws {
        let host = FakeVMHost()
        let recorder = AuditRecorder()
        var deps = dependencies(host: host, proxy: FakeProxy(), recorder: recorder)
        deps.makeProxy = { _, _, _ in DyingProxy() }
        let runner = makeRunner(
            host: FreshBlockingProvisioner(inner: host), network: deps, run: "sleep-forever-marker",
            policy: NetworkConfig(selection: .profile(.github), backend: .hostOnly, maxEnforcementFailures: 2), stopAfter: nil
        )
        var thrown: Error?
        do { try await runner.run() } catch { thrown = error }
        let error = try #require(thrown as? NetworkEnforcementError)
        guard case .gaveUp = error else { Issue.record("expected gaveUp, got \(error)"); return }
        let failed = recorder.events.filter { $0.name == "network.enforcement.failed" }
        #expect(failed.map { $0.fields["reason"] } == ["lost-proxy", "lost-proxy"])
        #expect(host.clones == 2)
    }

    @Test func aCompletedJobResetsTheCount() async throws {
        let host = FakeVMHost()
        let recorder = AuditRecorder()
        var deps = dependencies(host: host, proxy: FakeProxy(), recorder: recorder)
        deps.makeProxy = { _, _, _ in FakeProxy() }
        let runner = makeRunner(host: host, network: deps, stopAfter: 2)
        try await runner.run()
        #expect(!recorder.events.contains { $0.name == "network.enforcement.failed" })
        #expect(host.clones == 2)
    }
}

@Suite struct BackendPinningTests {
    @Test func autoStaysOnTheStartupBackendAndFailsClosedWhenItsPrivilegeIsGone() async throws {
        var unprivileged = FakeFileSystem()
        unprivileged.owner = (501, 0o755)
        let preflight = NetworkPreflight(
            processRunner: ScriptedProcessRunner(responder: currentToolHelp), fileSystem: unprivileged,
            resolver: StaticHostResolver(table: ["github.com": [IPAddress("140.82.112.3")!]]), hostProbe: FakeHostProbe(), proxySelfTest: nil
        )
        let auto = NetworkConfig(selection: .profile(.github), backend: .auto)
        // Unpinned, auto would now silently pick hostOnly (no host-service or peer isolation).
        #expect(try await preflight.compile(auto, sshPort: 22).backend == .hostOnly)
        let pinned = try await preflight.compile(auto, sshPort: 22, pinnedBackend: .softnet)
        #expect(pinned.backend == .softnet)
        let failures = NetworkPreflight.failures(await preflight.perVM(policy: pinned))
        // The pinned softnet's path is now user-writable: fail closed, never run it.
        #expect(failures.map(\.name) == [NetworkPreflight.pathCheckName])
        // An explicit backend is never overridden by the pin.
        #expect(try await preflight.compile(NetworkConfig(selection: .profile(.github), backend: .hostOnly), sshPort: 22, pinnedBackend: .softnet).backend == .hostOnly)
        // The default is auto, so it follows the pin.
        #expect(try await preflight.compile(.secureDefault, sshPort: 22, pinnedBackend: .softnet).backend == .softnet)
    }
}

@Suite struct IPForwardingTests {
    private func preflight(ipv4: Int?, ipv6: Int?) -> NetworkPreflight {
        var fileSystem = FakeFileSystem()
        fileSystem.sysctls = [:]
        if let ipv4 { fileSystem.sysctls[IPForwardingState.ipv4Name] = ipv4 }
        if let ipv6 { fileSystem.sysctls[IPForwardingState.ipv6Name] = ipv6 }
        return NetworkPreflight(
            processRunner: ScriptedProcessRunner(responder: currentToolHelp), fileSystem: fileSystem,
            resolver: StaticHostResolver(table: ["github.com": [IPAddress("140.82.112.3")!], "api.github.com": [IPAddress("140.82.112.5")!]]),
            hostProbe: FakeHostProbe(), proxySelfTest: nil
        )
    }

    @Test func hostOnlyFailsClosedWhileForwardingIsOnOrUnreadable() async throws {
        let hostOnly = try NetworkConfig.secureDefault.compile()
        for (v4, v6) in [(1, 0), (0, 1), (nil, 0)] as [(Int?, Int?)] {
            let failures = NetworkPreflight.failures(await preflight(ipv4: v4, ipv6: v6).run(policy: hostOnly))
            #expect(failures.map(\.name) == ["P11 host IP forwarding"])
            #expect(failures.first?.remediation?.contains("ipForwarding: accept") == true)
            #expect(NetworkPreflight.failures(await preflight(ipv4: v4, ipv6: v6).perVM(policy: hostOnly)).map(\.name) == ["P11 host IP forwarding"])
        }
        let clean = await preflight(ipv4: 0, ipv6: 0).run(policy: hostOnly)
        #expect(clean.contains { $0.name == "P11 host IP forwarding" && $0.status == .ok })
    }

    @Test func acceptWarnsAndSoftnetIsUnaffected() async throws {
        let accepted = try NetworkConfig(selection: .profile(.github), ipForwarding: .accept).compile()
        let checks = await preflight(ipv4: 1, ipv6: 1).run(policy: accepted)
        #expect(NetworkPreflight.failures(checks).isEmpty)
        #expect(checks.contains { $0.name == "P11 host IP forwarding" && $0.status == .warning })
        let softnet = try NetworkConfig(selection: .profile(.github), backend: .softnet).compile()
        #expect(!(await preflight(ipv4: 1, ipv6: 1).run(policy: softnet)).contains { $0.name.hasPrefix("P11") })
    }

    @Test func configParsingHashAndValidation() throws {
        let accepted = try NetworkConfig(selection: .profile(.github), ipForwarding: .accept).compile()
        let denied = try NetworkConfig.secureDefault.compile()
        #expect(denied.options.ipForwarding == .deny)
        #expect(accepted.policyHash != denied.policyHash)
        #expect(accepted.explain().contains { $0.contains("host IP forwarding: accept") })
        let vm = { (network: NetworkConfig) in
            Config.VM(source: .init(type: .local, image: nil, name: "golden"), hardware: nil, mounts: [], cache: nil,
                      run: .init(noGraphics: true, noClipboard: true, nested: false, network: network), diskSizeGb: nil, ssh: .standard)
        }
        func issues(_ network: NetworkConfig) -> [ConfigValidationIssue] {
            let runner = Config.RunnerConfig(name: "n", vm: vm(network), provisioner: .init(type: .script, script: .init(run: "true"), github: nil), preRun: nil, postRun: nil, stopAfter: nil, healthCheck: nil)
            return ConfigValidator().validate(Config(runners: [runner]))
        }
        #expect(issues(NetworkConfig(selection: .profile(.github), ipForwarding: .accept)).contains { $0.severity == .warning && $0.message.contains("ipForwarding: accept") })
        #expect(issues(NetworkConfig(selection: .mode(.softnet), ipForwarding: .accept)).contains { $0.severity == .error && $0.message.contains("ipForwarding") })
        let yaml = """
        runners:
          - name: fwd
            vm:
              source:
                type: local
                name: golden
              run:
                network:
                  profile: github
                  ipForwarding: accept
            provisioner:
              type: script
              config:
                run: echo ok
        """
        let config = try Config.load(path: writeTempFile(contents: yaml).path)
        #expect(config.runners.first?.vm.run.network.ipForwarding == .accept)
        let bad = yaml.replacingOccurrences(of: "ipForwarding: accept", with: "ipForwarding: maybe")
        #expect(throws: (any Error).self) { try Config.load(path: writeTempFile(contents: bad).path) }
    }

    @Test func watchdogStopsTheVMWhenForwardingTurnsOn() async {
        let state = LiveHandleState()
        let forwarding = LiveHandleState()
        let watchdog = NetworkWatchdog(
            components: .init(tartRun: state.handle(), checkSoftnet: false, ipForwarding: { forwarding.finished ? "net.inet.ip.forwarding=1" : nil }),
            processRunner: ScriptedProcessRunner { _, _ in ProcessResult(stdout: "", stderr: "", exitCode: 0) }
        ) { _ in }
        #expect(await watchdog.firstFailure() == nil)
        forwarding.finish()
        #expect(await watchdog.firstFailure() == "ip-forwarding(net.inet.ip.forwarding=1)")
    }

    @Test func forwardingTurnedOnAfterPreflightRefusesTheVM() async throws {
        let host = FakeVMHost()
        let recorder = AuditRecorder()
        var deps = dependencies(host: host, proxy: FakeProxy(), recorder: recorder)
        deps.ipForwarding = { IPForwardingState(ipv4: 1, ipv6: 0) }
        let runner = makeRunner(host: host, network: deps, policy: NetworkConfig(selection: .profile(.github), backend: .hostOnly, maxEnforcementFailures: 1))
        await #expect(throws: NetworkEnforcementError.self) { try await runner.run() }
        #expect(recorder.events.contains { $0.name == "network.host.forwarding" && $0.fields["result"] == "denied" })
        #expect(!host.lock.withLock { host.started }.contains { $0.contains("provisioned-marker") })
    }

    @Test func acceptedForwardingIsAuditedPerVMAndRoutedReachIsReported() async throws {
        let host = FakeVMHost()
        host.probeOverrides = ["R4": "OPEN 100.100.100.100"]
        let recorder = AuditRecorder()
        var deps = dependencies(host: host, proxy: FakeProxy(), recorder: recorder)
        deps.ipForwarding = { IPForwardingState(ipv4: 1, ipv6: 1) }
        try await makeRunner(host: host, network: deps, policy: NetworkConfig(selection: .profile(.github), backend: .hostOnly, ipForwarding: .accept)).run()
        #expect(recorder.events.contains { $0.name == "network.host.forwarding" && $0.fields["result"] == "accepted" })
        let verified = try #require(recorder.events.first { $0.name == "network.guest.verified" })
        #expect(verified.fields["routed_reachable"]?.contains("100.100.100.100") == true)
        #expect(host.lock.withLock { host.started }.contains { $0.contains("provisioned-marker") })
    }

    @Test func routedReachUnderDenyFailsVerification() async throws {
        let host = FakeVMHost()
        host.probeOverrides = ["R4": "OPEN 100.100.100.100"]
        let recorder = AuditRecorder()
        let runner = makeRunner(host: host, network: dependencies(host: host, proxy: FakeProxy(), recorder: recorder), policy: NetworkConfig(selection: .profile(.github), backend: .hostOnly, maxEnforcementFailures: 1))
        await #expect(throws: NetworkEnforcementError.self) { try await runner.run() }
        #expect(recorder.events.contains { $0.name == "network.guest.verify" && $0.fields["failed"] == "R4:OPEN" })
    }
}

@Suite struct RoutedVerifierTests {
    private func transcript(_ verifier: GuestEgressVerifier, _ overrides: [String: String]) -> String {
        verifier.probes.map { probe in
            "SANDPROBE \(probe.id) \(overrides[probe.id] ?? (probe.expectation == .proxyWorks ? "OK http=200" : "CLOSED x"))"
        }.joined(separator: "\n")
    }

    private let routed = GuestEgressVerifier.RoutedTargets(hostGatewayV6: "fe80::1", resolvers: ["10.0.0.1", "100.100.100.100", "fd7a:115c:a1e0::53", "x;id"], tunnelTargets: ["100.64.0.1", "172.16.0.1"])

    @Test func hostOnlyRoutesEachTargetViaTheHostBridgeAddress() {
        let verifier = GuestEgressVerifier(level: .basic, directGitHubAddress: "172.16.7.60", backend: .hostOnly, hostGateway: "192.168.128.1", routed: routed)
        let ids = verifier.probes.filter { $0.expectation == .routedClosed }.map(\.id)
        #expect(ids == ["R1", "R2", "R3", "R4", "R5", "RD1", "RT1", "RT2", "R6"], "IPv4 resolvers only, tailnet resolver not duplicated")
        let script = verifier.script
        #expect(script.contains("HGW='192.168.128.1'"))
        #expect(script.contains(#"sudo -n /sbin/route -n add -host "$1" "$HGW""#))
        #expect(script.contains("sudo -n ip route replace"))
        #expect(script.contains("routed R4 dnsq 100.100.100.100"))
        #expect(script.contains("routed RD1 dnsq '10.0.0.1'"))
        #expect(script.contains("routed6 R6 'fe80::1'"))
        #expect(script.contains("trap sand_unroute EXIT"))
        #expect(!script.contains("x;id"))
        #expect(!script.contains("route add default") && !script.contains("route delete default"), "never touches the default route")
    }

    @Test func routedReachFailsUnlessForwardingIsAccepted() {
        let deny = GuestEgressVerifier(level: .basic, directGitHubAddress: "172.16.7.60", backend: .hostOnly, hostGateway: "192.168.128.1", routed: routed)
        #expect(deny.evaluate(transcript(deny, ["R4": "OPEN 100.100.100.100"])).filter { !$0.passed }.map(\.id) == ["R4"])
        #expect(deny.evaluate(transcript(deny, ["R1": "INCONCLUSIVE no-guest-root"])).allSatisfy { $0.passed })
        #expect(deny.evaluate(transcript(deny, ["R1": "NOTARGET empty-target"])).contains { $0.id == "R1" && !$0.passed })
        var accepted = routed
        accepted.forwardingAccepted = true
        let accept = GuestEgressVerifier(level: .basic, directGitHubAddress: "172.16.7.60", backend: .hostOnly, hostGateway: "192.168.128.1", routed: accepted)
        let results = accept.evaluate(transcript(accept, ["R4": "OPEN 100.100.100.100"]))
        #expect(results.allSatisfy { $0.passed })
        #expect(accept.routedReachable(results) == ["R4"])
    }

    @Test func softnetHasNoRoutedProbes() {
        let verifier = GuestEgressVerifier(level: .strict, directGitHubAddress: "172.16.7.60", backend: .softnet, routed: routed)
        #expect(!verifier.probes.contains { $0.expectation == .routedClosed })
        #expect(!verifier.script.contains("sand_unroute"))
    }

    @Test func parsesHostDNSServers() {
        let output = """
        resolver #1
          nameserver[0] : 10.0.0.1
          nameserver[1] : 127.0.0.1
        resolver #2
          nameserver[0] : 100.100.100.100
          nameserver[1] : fd7a:115c:a1e0::53
          nameserver[2] : 10.0.0.1
          nameserver[3] : not-an-ip
        """
        #expect(HostDNSServers.parse(scutil: output) == ["10.0.0.1", "100.100.100.100", "fd7a:115c:a1e0::53"])
    }
}

@Suite struct ReachableHostAddressTests {
    @Test func everyNonLoopbackHostAddressCountsAsReachable() throws {
        // getifaddrs-style link-local with the KAME embedded scope (fe80:7::1).
        var scoped = try #require(IPAddress("fe80::1")).withoutEmbeddedScope
        if case var .v6(bytes) = scoped { bytes[3] = 7; scoped = .v6(bytes) }
        let bridge = [IPAddress("192.168.128.1")!, scoped]
        let host = [IPAddress("10.0.0.152")!, IPAddress("100.101.102.103")!, IPAddress("127.0.0.1")!, IPAddress("fe80::99")!, IPAddress("2001:db8::5")!, IPAddress("192.168.128.1")!]
        let reachable = HostListenerInspector.reachableAddresses(bridge: bridge, host: host).map(\.description)
        #expect(reachable == ["192.168.128.1", "fe80::1", "10.0.0.152", "100.101.102.103", "2001:db8::5"])
    }

    @Test func listenersBoundToTheLANOrVPNAddressAreReported() {
        let addresses = HostListenerInspector.reachableAddresses(bridge: [IPAddress("192.168.128.1")!], host: [IPAddress("10.0.0.152")!])
        let tcp = HostListenerInspector.parse(netstat: HostListenerTests.netstatTCP, bridgeAddresses: addresses).map(\.description)
        #expect(tcp.contains("tcp/9000@10.0.0.152"), "a dev server on the LAN address answers on the bridge (weak host)")
        #expect(!tcp.contains { $0.contains("631") || $0.contains("50123") }, "loopback stays unreported")
        let lsof = "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\ndevsrv 4300 user 7u IPv4 0x3 0t0 TCP 10.0.0.152:8080 (LISTEN)"
        #expect(HostListenerInspector.parse(lsof: lsof, bridgeAddresses: addresses).map(\.description) == ["tcp/8080@10.0.0.152 (devsrv:4300)"])
    }

    @Test func netstatWithOnlyUDPSocketsStillCounts() {
        #expect(HostListenerInspector.netstatSeesInternetSockets("udp4       0      0  *.5353                 *.*"))
    }

    @Test func bridgeInterfaceWinsOverAWideUtunNetmask() {
        #expect(HostListenerInspector.pickBridge(["utun4", "bridge100"]) == "bridge100")
        #expect(HostListenerInspector.pickBridge(["bridge100", "utun4"]) == "bridge100")
        #expect(HostListenerInspector.pickBridge(["utun4"]) == "utun4")
        #expect(HostListenerInspector.pickBridge([]) == nil)
    }
}
