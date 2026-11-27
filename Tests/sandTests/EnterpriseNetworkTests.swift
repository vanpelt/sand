import Foundation
import Testing
@testable import sand

private func loadNetwork(_ body: String) throws -> NetworkConfig {
    let yaml = """
    runners:
      - name: net-test
        vm:
          source:
            type: local
            name: golden
          run:
            network:
    \(body)
        provisioner:
          type: script
          config:
            run: echo ok
    """
    let config = try Config.load(path: writeTempFile(contents: yaml).path)
    return try #require(config.runners.first?.vm.run.network)
}

private func errors(_ network: NetworkConfig) -> [String] {
    issues(network).filter { $0.severity == .error }.map(\.message)
}

private func issues(_ network: NetworkConfig) -> [ConfigValidationIssue] {
    let vm = Config.VM(
        source: .init(type: .local, image: nil, name: "golden"), hardware: nil, mounts: [], cache: nil,
        run: .init(noGraphics: true, noClipboard: true, nested: false, network: network),
        diskSizeGb: nil, ssh: .standard
    )
    let runner = Config.RunnerConfig(name: "net-test", vm: vm, provisioner: .init(type: .script, script: .init(run: "true"), github: nil), preRun: nil, postRun: nil, stopAfter: nil, healthCheck: nil)
    return ConfigValidator().validate(Config(runners: [runner]))
}

@Suite struct EnforcementBackendConfigTests {
    @Test func defaultIsHostOnlyWithoutSoftnet() throws {
        let policy = try NetworkConfig.secureDefault.compile()
        #expect(policy.backend == .hostOnly)
        #expect(policy.tartArguments == ["--net-host"])
        #expect(policy.softnet == nil)
        #expect(!policy.usesSoftnet)
        #expect(policy.egress != nil)
        let offline = try NetworkConfig(selection: .profile(.offline)).compile()
        #expect(offline.tartArguments == ["--net-host"])
    }

    @Test func explicitSoftnetAndLegacyModesUseSoftnet() throws {
        let softnet = try loadNetwork("          profile: github\n          backend: softnet")
        #expect(try softnet.compile().tartArguments.first == "--net-softnet")
        #expect(try softnet.compile().usesSoftnet)
        #expect(try NetworkConfig(mode: .restricted, allowCIDRs: ["10.0.0.0/24"]).compile().backend == .softnet)
        #expect(try NetworkConfig(mode: .softnet).compile().backend == .softnet)
        #expect(try NetworkConfig(mode: .shared).compile().backend == nil)
    }

    @Test func autoCompilesToWhatTheHostResolved() throws {
        let auto = try loadNetwork("          profile: github\n          backend: auto")
        #expect(auto.backendChoice == .auto)
        #expect(try auto.compile().backend == .hostOnly)
        #expect(try auto.compile(autoBackend: .softnet).backend == .softnet)
    }

    @Test func unknownBackendIsAnError() {
        #expect(throws: (any Error).self) { try loadNetwork("          profile: github\n          backend: bridged") }
        #expect(throws: (any Error).self) { try loadNetwork("          profile: github\n          tlsInspection: yes-please") }
        #expect(throws: (any Error).self) { try loadNetwork("          profile: github\n          hostListeners: allow") }
    }

    @Test func policyHashDependsOnBackendAndInspectionMode() throws {
        let hostOnly = try NetworkConfig.secureDefault.compile()
        let softnet = try NetworkConfig(selection: .profile(.github), backend: .softnet).compile()
        let trust = try NetworkConfig(selection: .profile(.github), tlsInspection: .trustHostCA).compile()
        let deny = try NetworkConfig(selection: .profile(.github), hostListeners: .deny).compile()
        #expect(Set([hostOnly.policyHash, softnet.policyHash, trust.policyHash, deny.policyHash]).count == 4)
        #expect(hostOnly.explain().contains { $0.contains("no peer-VM isolation") })
    }

    @Test func allowedCIDRsNeedExplicitSoftnet() {
        let allow = [DirectCIDRAllow(cidr: "203.0.113.10/32", port: 443)]
        #expect(throws: DirectCIDRError.requiresSoftnet) { try NetworkConfig(selection: .profile(.github), allowedCIDRs: allow).compile() }
        #expect(errors(NetworkConfig(selection: .profile(.github), allowedCIDRs: allow)).contains { $0.contains("requires backend: softnet") })
        #expect(errors(NetworkConfig(selection: .profile(.github), allowedCIDRs: allow, backend: .auto)).contains { $0.contains("may resolve to hostOnly") })
        #expect(errors(NetworkConfig(selection: .profile(.github), allowedCIDRs: allow, backend: .softnet)).isEmpty)
    }

    @Test func modeRejectsBackendAndProfileOptions() {
        #expect(errors(NetworkConfig(selection: .mode(.softnet), backend: .hostOnly)).contains { $0.contains("backend applies to profiles only") })
        #expect(errors(NetworkConfig(selection: .mode(.softnet), tlsInspection: .trustHostCA)).contains { $0.contains("require a profile") })
        #expect(errors(NetworkConfig(selection: .mode(.shared), maxEnforcementFailures: 2)).contains { $0.contains("does not apply to mode: shared") })
        #expect(errors(NetworkConfig(selection: .profile(.offline), tlsInspection: .trustHostCA)).contains { $0.contains("profile: github only") })
    }

    @Test func hostListenerOptionsValidate() throws {
        let config = try loadNetwork("          profile: github\n          hostListeners: deny\n          acceptedHostListeners: [tcp/7000, udp/*]")
        let policy = try config.compile()
        #expect(policy.options.hostListeners == .deny)
        #expect(policy.options.acceptedHostListeners.map(\.description) == ["tcp/7000", "udp/*"])
        #expect(errors(config).isEmpty)
        #expect(errors(NetworkConfig(selection: .profile(.github), hostListeners: .deny, acceptedHostListeners: ["tcp/0"])).contains { $0.contains("acceptedHostListeners entry 'tcp/0'") })
        #expect(throws: HostListenerPatternError.self) { try HostListenerPattern.parse("sctp/9") }
        #expect(issues(NetworkConfig(selection: .profile(.github), backend: .softnet, hostListeners: .deny)).contains { $0.severity == .warning && $0.message.contains("only apply to the hostOnly backend") })
    }

    @Test func maxEnforcementFailuresIsBoundedAndDefaultsToThree() throws {
        #expect(try NetworkConfig.secureDefault.compile().options.maxEnforcementFailures == 3)
        #expect(try loadNetwork("          profile: github\n          maxEnforcementFailures: 5").compile().options.maxEnforcementFailures == 5)
        #expect(errors(NetworkConfig(selection: .profile(.github), maxEnforcementFailures: 0)).contains { $0.contains("between 1 and 100") })
    }

    @Test func trustHostCAWarns() throws {
        let config = try loadNetwork("          profile: github\n          tlsInspection: trustHostCA")
        #expect(try config.compile().options.tlsInspection == .trustHostCA)
        #expect(issues(config).contains { $0.severity == .warning && $0.message.contains("trustHostCA") })
        #expect(try NetworkConfig.secureDefault.compile().options.tlsInspection == .fail)
    }

    @Test func peerIsolationWarningOnlyForConcurrentHostOnly() throws {
        let hostOnly = try NetworkConfig.secureDefault.compile()
        let softnet = try NetworkConfig(selection: .profile(.github), backend: .softnet).compile()
        #expect(NetworkStartup.peerIsolationWarning([("a", hostOnly)]) == nil)
        #expect(NetworkStartup.peerIsolationWarning([("a", hostOnly), ("b", softnet)]) == nil)
        #expect(NetworkStartup.peerIsolationWarning([("a", hostOnly), ("b", hostOnly)])?.contains("backend: softnet") == true)
    }
}

@Suite struct HostOnlyPreflightTests {
    let hostOnly = try! NetworkConfig.secureDefault.compile()

    @Test func hostOnlyNeedsNoSoftnetAndNeverRunsSudo() async {
        var fileSystem = FakeFileSystem()
        fileSystem.paths["softnet"] = nil
        let runner = ScriptedProcessRunner(responder: currentToolHelp)
        let checks = await makePreflight(runner: runner, fileSystem: fileSystem).run(policy: hostOnly)
        #expect(NetworkPreflight.failures(checks).isEmpty, "\(checks.map(\.line))")
        #expect(checks.contains { $0.name == "P1 tart" && $0.detail.contains("--net-host") })
        #expect(runner.calls.allSatisfy { $0.executable != "sudo" })
        #expect(await makePreflight(runner: runner, fileSystem: fileSystem).perVM(policy: hostOnly).allSatisfy { $0.name != "P3 softnet privilege" })
    }

    @Test func tartWithoutNetHostFails() async {
        let runner = ScriptedProcessRunner { executable, arguments in
            if executable == "tart", arguments == ["run", "--help"] {
                return ProcessResult(stdout: "--net-softnet-allow", stderr: "", exitCode: 0)
            }
            return try currentToolHelp(executable, arguments)
        }
        let failures = NetworkPreflight.failures(await makePreflight(runner: runner).run(policy: hostOnly))
        #expect(failures.map(\.name) == ["P1 tart"])
        #expect(failures.first?.detail.contains("--net-host") == true)
    }

    @Test func autoPicksSoftnetOnlyWhenPrivileged() async {
        let auto = NetworkConfig(selection: .profile(.github), backend: .auto)
        let privileged = makePreflight(runner: ScriptedProcessRunner(responder: currentToolHelp))
        #expect(await privileged.resolveBackend(auto) == .softnet)
        var unprivileged = FakeFileSystem()
        unprivileged.owner = (501, 0o755)
        #expect(await makePreflight(runner: ScriptedProcessRunner(responder: currentToolHelp), fileSystem: unprivileged).resolveBackend(auto) == .hostOnly)
        var missing = FakeFileSystem()
        missing.paths["softnet"] = nil
        #expect(await makePreflight(runner: ScriptedProcessRunner(responder: currentToolHelp), fileSystem: missing).resolveBackend(auto) == .hostOnly)
        #expect(await makePreflight(runner: ScriptedProcessRunner(responder: currentToolHelp), fileSystem: unprivileged).resolveBackend(.secureDefault) == .hostOnly)
    }

    @Test func diskCheckUsesAvailableBlocks() {
        let free = SystemPreflightFileSystem().freeBytes(atPath: NSTemporaryDirectory())
        #expect((free ?? 0) > 0)
    }
}

@Suite struct HostListenerTests {
    static let netstatTCP = """
    Active Internet connections (including servers)
    Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
    tcp4       0      0  127.0.0.1.631          *.*                    LISTEN
    tcp4       0      0  127.0.0.1.50123        *.*                    LISTEN
    tcp6       0      0  ::1.631                *.*                    LISTEN
    tcp6       0      0  fe80::74c1:afff:fe6d:8d9e%anri0.57854         *.*        LISTEN
    tcp4       0      0  *.5000                 *.*                    LISTEN
    tcp6       0      0  *.5000                 *.*                    LISTEN
    tcp46      0      0  *.853                  *.*                    LISTEN
    tcp4       0      0  192.168.128.1.8080     *.*                    LISTEN
    tcp4       0      0  10.0.0.152.9000        *.*                    LISTEN
    tcp4       0      0  10.0.0.152.56269       34.36.195.174.443      ESTABLISHED
    """

    static let netstatUDP = """
    udp4       0      0  *.*                    *.*
    udp4       0      0  10.0.0.152.61704       17.248.175.41.443
    udp4       0      0  *.5353                 *.*
    udp46      0      0  *.547                  *.*
    udp4       0      0  127.0.0.1.53           *.*
    """

    static let verbose = """
    tcp4       0      0  *.5000                 *.*                    LISTEN                 0            0  131072  131072    ControlCenter:1311   00100 00000006 0000000000003b78 00000001 00000800      1      0 000000
    tcp46      0      0  *.853                  *.*                    LISTEN                 0            0  131072  131072   srp-mdns-proxy:6648   00100 00000006 0000000000014cbc 00000000 00080800      1      0 000000
    udp4       0      0  *.5353                 *.*                                           0            0  786896    9216 Google Chrome He:5226   ffffa130 00020000 0000000000c4f4f5 00100009 842c0908      1      0 000002
    """

    let bridge = [IPAddress("192.168.128.1")!]

    @Test func reportsWildcardAndBridgeBoundOnly() {
        let tcp = HostListenerInspector.parse(netstat: Self.netstatTCP, verbose: Self.verbose, bridgeAddresses: bridge)
        let udp = HostListenerInspector.parse(netstat: Self.netstatUDP, verbose: Self.verbose, bridgeAddresses: bridge)
        let listeners = HostListenerInspector.dedupe(tcp + udp)
        #expect(listeners.map(\.description) == [
            "tcp/853 (srp-mdns-proxy:6648)",
            "tcp/5000 (ControlCenter:1311)",
            "tcp/8080@192.168.128.1",
            "udp/547",
            "udp/5353 (Google Chrome He:5226)"
        ])
        // Loopback (including Sand's own proxy), other interfaces and connected sockets are never reported.
        #expect(!listeners.contains { [631, 50123, 9000, 57854, 53, 61704].contains($0.port) })
    }

    @Test func reportPolicyAndAcceptedListeners() throws {
        let listeners = [HostListener(proto: .tcp, port: 5000, boundTo: "*"), HostListener(proto: .udp, port: 5353, boundTo: "*")]
        #expect(!HostListenerReport(reachable: listeners, policy: .warn, accepted: []).failed)
        #expect(HostListenerReport(reachable: listeners, policy: .deny, accepted: []).failed)
        let partial = HostListenerReport(reachable: listeners, policy: .deny, accepted: [try .parse("udp/*")])
        #expect(partial.failed)
        #expect(partial.reachable.map(\.key) == ["tcp/5000"])
        #expect(!HostListenerReport(reachable: listeners, policy: .deny, accepted: [try .parse("udp/*"), try .parse("tcp/5000")]).failed)
    }

    static let lsof = """
    COMMAND     PID    USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
    rapportd   1083 user   12u  IPv4 0xd433505d23772135      0t0  TCP *:57765 (LISTEN)
    ControlCe  1311 user   11u  IPv4 0x662fd22c9d9b075d      0t0  TCP *:5000 (LISTEN)
    cupsd       981 user    5u  IPv6 0x1                     0t0  TCP [::1]:631 (LISTEN)
    sand       4242 user    7u  IPv4 0x2                     0t0  TCP 127.0.0.1:50123 (LISTEN)
    devsrv     4300 user    7u  IPv4 0x3                     0t0  TCP 192.168.128.1:8080 (LISTEN)
    Google     5226 user   40u  IPv4 0x4                     0t0  UDP *:5353
    Google     5226 user   41u  IPv4 0x5                     0t0  UDP 10.0.0.152:61704->17.248.175.41:443
    """

    @Test func lsofAndSweepWhenNetstatIsBlind() async {
        #expect(!HostListenerInspector.netstatSeesInternetSockets("Active LOCAL (UNIX) domain sockets\nAddress Type"))
        #expect(HostListenerInspector.netstatSeesInternetSockets(Self.netstatTCP))
        let parsed = HostListenerInspector.parse(lsof: Self.lsof, bridgeAddresses: bridge).map(\.description)
        #expect(parsed == ["tcp/57765 (rapportd:1083)", "tcp/5000 (ControlCe:1311)", "tcp/8080@192.168.128.1 (devsrv:4300)", "udp/5353 (Google:5226)"])
        let runner = ScriptedProcessRunner { executable, _ in
            ProcessResult(stdout: executable == "lsof" ? Self.lsof : "Active LOCAL (UNIX) domain sockets", stderr: "", exitCode: 0)
        }
        var inspector = HostListenerInspector(processRunner: runner)
        inspector.sweep = { _ in [22, 5000] }
        let result = await inspector.inspect(bridgeAddresses: bridge)
        #expect(result.method == "lsof+sweep")
        #expect(result.listeners.map(\.description).contains("tcp/22"), "root sshd found by the sweep")
        #expect(result.listeners.filter { $0.key == "tcp/5000" }.count == 1)
    }

    @Test func splitsLocalAddresses() {
        #expect(HostListenerInspector.splitLocal("*.5000")! == ("*", 5000))
        #expect(HostListenerInspector.splitLocal("192.168.128.1.22")! == ("192.168.128.1", 22))
        #expect(HostListenerInspector.splitLocal("fe80::1%bridge100.5353")! == ("fe80::1%bridge100", 5353))
        #expect(HostListenerInspector.splitLocal("*.*") == nil)
    }
}

@Suite struct HostOnlyVerifierTests {
    private func transcript(_ verifier: GuestEgressVerifier, _ overrides: [String: String]) -> String {
        verifier.probes.map { probe in
            let outcome = overrides[probe.id] ?? (probe.expectation == .proxyWorks ? "OK http=200" : "CLOSED x")
            return "SANDPROBE \(probe.id) \(outcome)"
        }.joined(separator: "\n")
    }

    @Test func hostServicesOnTheBridgeAreReportedUnderWarn() {
        let verifier = GuestEgressVerifier(level: .basic, directGitHubAddress: "172.16.7.60", backend: .hostOnly, hostServicePorts: [5000, 7000])
        #expect(verifier.probes.contains { $0.id == "H1" && $0.command.hasSuffix("7000") })
        #expect(!verifier.probes.contains { $0.id == "H2" }, "5000 is already probed as N3a")
        let results = verifier.evaluate(transcript(verifier, ["N3a": "OPEN 192.168.128.1:5000", "H1": "OPEN 192.168.128.1:7000"]))
        #expect(results.allSatisfy { $0.passed })
        #expect(verifier.reachableHostServices(results) == ["tcp/5000", "tcp/7000"])
    }

    @Test func hostGatewayFallbackWhenTheGuestHasNoDefaultRoute() {
        let verifier = GuestEgressVerifier(level: .basic, directGitHubAddress: "172.16.7.60", backend: .hostOnly, hostGateway: "192.168.128.1")
        #expect(verifier.script.contains(#"[ -n "$GW" ] || GW='192.168.128.1'"#))
        let injected = GuestEgressVerifier(level: .basic, directGitHubAddress: "1.1.1.1", hostGateway: "x; rm -rf /")
        #expect(!injected.script.contains("rm -rf"))
    }

    @Test func denyFailsOnUnacceptedHostService() throws {
        let verifier = GuestEgressVerifier(level: .basic, directGitHubAddress: "172.16.7.60", backend: .hostOnly, hostListenerPolicy: .deny, acceptedHostListeners: [try .parse("tcp/22")])
        let failed = verifier.evaluate(transcript(verifier, ["N3a": "OPEN x", "N3c": "OPEN y"])).filter { !$0.passed }
        #expect(failed.map(\.id) == ["N3a"])
    }

    @Test func directEgressDNSAndIPv6MustStayClosedUnderHostOnly() {
        let verifier = GuestEgressVerifier(level: .basic, directGitHubAddress: "172.16.7.60", backend: .hostOnly)
        for id in ["N1", "N2", "N3b", "N4a", "N4b", "N5"] {
            let failed = verifier.evaluate(transcript(verifier, [id: "OPEN z"])).filter { !$0.passed }
            #expect(failed.map(\.id) == [id])
        }
    }

    @Test func softnetStillRequiresClosedGatewayPorts() {
        let verifier = GuestEgressVerifier(level: .basic, directGitHubAddress: "172.16.7.60", backend: .softnet, hostServicePorts: [7000])
        #expect(!verifier.probes.contains { $0.id.hasPrefix("H") })
        #expect(verifier.evaluate(transcript(verifier, ["N3a": "OPEN x"])).contains { $0.id == "N3a" && !$0.passed })
    }
}

/// Fake chain observer + trust store for interception tests.
struct FakeChainObserver: TLSChainObserving {
    var chains: [String: [Data]]
    var trusted = true
    func observe(host: String, port: UInt16, timeout: TimeInterval) async -> Result<TLSChainObservation, HostEgressProbeError> {
        guard let chain = chains[host] else { return .failure(.timeout) }
        return .success(TLSChainObservation(host: host, certificates: chain, trusted: trusted))
    }
}

struct FakeTrustStore: HostTrustStore {
    var roots: Set<String>
    var keychain: [String: String]
    var identities: Set<String> = []
    func systemRootFingerprints() async -> Set<String> { roots }
    func systemKeychainCertificates() async -> [String: String] { keychain }
    func identityFingerprints() async -> Set<String> { identities }
}

@Suite struct TLSInspectionTests {
    // Opaque stand-ins for DER certificates: only their hashes matter to the classifier.
    let leaf = Data("leaf".utf8)
    let publicRoot = Data("public-root".utf8)
    let inspectionIntermediate = Data("inspection-intermediate".utf8)
    let inspectionRoot = Data("inspection-root".utf8)

    func pem(_ der: Data) -> String {
        "-----BEGIN CERTIFICATE-----\n\(der.base64EncodedString())\n-----END CERTIFICATE-----\n"
    }

    var store: FakeTrustStore {
        FakeTrustStore(
            roots: [TLSInspectionDetector.sha256(publicRoot)],
            keychain: [
                TLSInspectionDetector.sha256(inspectionIntermediate): pem(inspectionIntermediate),
                TLSInspectionDetector.sha256(inspectionRoot): pem(inspectionRoot)
            ]
        )
    }

    var chains: [String: [Data]] {
        [
            "github.com": [leaf, publicRoot],
            "objects.githubusercontent.com": [leaf, inspectionIntermediate, inspectionRoot],
            "results-receiver.actions.githubusercontent.com": [leaf, inspectionIntermediate, inspectionRoot]
        ]
    }

    @Test func detectsInterceptionAndExportsOnlyTheInterceptingCAs() async {
        let detector = TLSInspectionDetector(observer: FakeChainObserver(chains: chains), store: store)
        let report = await detector.detect(hosts: ["github.com", "objects.githubusercontent.com", "results-receiver.actions.githubusercontent.com", "ghcr.io"])
        #expect(report.interceptedHosts == ["objects.githubusercontent.com", "results-receiver.actions.githubusercontent.com"])
        #expect(report.authorities.count == 2)
        #expect(report.authorities.first?.isRoot == true)
        #expect(report.authorities.first?.sha256 == TLSInspectionDetector.sha256(inspectionRoot))
        #expect(!report.authorities.contains { $0.sha256 == TLSInspectionDetector.sha256(publicRoot) })
        #expect(report.problems.isEmpty)
        #expect(report.unreachable.keys.sorted() == ["ghcr.io"])
    }

    @Test func publicChainsAreClean() async {
        let detector = TLSInspectionDetector(observer: FakeChainObserver(chains: ["github.com": [leaf, publicRoot]]), store: store)
        let report = await detector.detect(hosts: ["github.com"])
        #expect(!report.isIntercepted)
        let checks = NetworkPreflight.inspectionChecks(report, mode: .fail)
        #expect(checks.map(\.status) == [.ok])
    }

    @Test func refusesCAsMissingFromSystemKeychainOrWithAPrivateKey() async {
        var missing = store
        missing.keychain = [:]
        let notExported = await TLSInspectionDetector(observer: FakeChainObserver(chains: chains), store: missing).detect(hosts: ["objects.githubusercontent.com"])
        #expect(notExported.authorities.isEmpty)
        #expect(notExported.problems.contains { $0.contains("not in /Library/Keychains/System.keychain") })
        var signable = store
        signable.identities = [TLSInspectionDetector.sha1(inspectionRoot)]
        let withKey = await TLSInspectionDetector(observer: FakeChainObserver(chains: chains), store: signable).detect(hosts: ["objects.githubusercontent.com"])
        #expect(withKey.problems.contains { $0.contains("private key on this host") })
        #expect(NetworkPreflight.inspectionChecks(withKey, mode: .trustHostCA).contains { $0.status == .failed })
    }

    @Test func preflightFailsClosedByDefaultAndPassesWhenTrusted() async {
        let report = await TLSInspectionDetector(observer: FakeChainObserver(chains: chains), store: store).detect(hosts: ["objects.githubusercontent.com"])
        let off = NetworkPreflight.inspectionChecks(report, mode: .fail)
        let failure = off.first { $0.status == .failed }
        #expect(failure?.detail.contains("objects.githubusercontent.com") == true)
        #expect(failure?.remediation?.contains("tlsInspection: trustHostCA") == true)
        #expect(failure?.remediation?.contains("exempt these hosts") == true)
        #expect(NetworkPreflight.inspectionChecks(report, mode: .trustHostCA).allSatisfy { $0.status == .ok })
    }

    @Test func preflightRunsDetectionForEgressPolicies() async {
        let detector = TLSInspectionDetector(observer: FakeChainObserver(chains: chains), store: store)
        let preflight = NetworkPreflight(
            processRunner: ScriptedProcessRunner(responder: currentToolHelp), fileSystem: FakeFileSystem(),
            resolver: StaticHostResolver(table: ["github.com": [IPAddress("140.82.112.3")!], "api.github.com": [IPAddress("140.82.112.5")!]]),
            hostProbe: FakeHostProbe(), proxySelfTest: nil, tlsInspection: detector
        )
        let (checks, report) = await preflight.runWithInspection(policy: try! NetworkConfig.secureDefault.compile())
        #expect(report?.isIntercepted == true)
        #expect(NetworkPreflight.failures(checks).map(\.name) == ["P10 TLS inspection"])
        let trusting = await preflight.runWithInspection(policy: try! NetworkConfig(selection: .profile(.github), tlsInspection: .trustHostCA).compile())
        #expect(NetworkPreflight.failures(trusting.checks).isEmpty)
        let offline = await preflight.runWithInspection(policy: try! NetworkConfig(selection: .profile(.offline)).compile())
        #expect(offline.inspection == nil)
    }

    @Test func probeHostsAreAllowlistedRepresentatives() throws {
        let egress = try #require(try NetworkConfig(selection: .profile(.github), presets: ["npm"], allowedDomains: ["*.cdn.example.com"]).compile().egress)
        let hosts = TLSInspectionDetector.probeHosts(for: egress)
        #expect(hosts.contains("results-receiver.actions.githubusercontent.com"))
        #expect(hosts.contains("objects.githubusercontent.com"))
        #expect(hosts.contains("registry.npmjs.org"))
        #expect(hosts.allSatisfy { egress.allows(host: $0, port: 443) })
    }

    @Test func parsesSecurityOutput() {
        let dump = """
        SHA-256 hash: aa77c498
        SHA-1 hash: 1234
        keychain: "/Library/Keychains/System.keychain"
        -----BEGIN CERTIFICATE-----
        QUJD
        -----END CERTIFICATE-----
        SHA-256 hash: 81A590D6
        -----BEGIN CERTIFICATE-----
        REVG
        -----END CERTIFICATE-----
        """
        let parsed = TLSInspectionDetector.parseKeychainDump(dump)
        #expect(parsed.keys.sorted() == ["81A590D6", "AA77C498"])
        #expect(TLSInspectionDetector.derFromPEM(parsed["AA77C498"]!) == Data("ABC".utf8))
        #expect(TLSInspectionDetector.parseFingerprints(dump) == ["AA77C498", "81A590D6"])
        let identities = "  1) 0123456789ABCDEF0123456789ABCDEF01234567 \"Apple Development\"\n     1 identities found"
        #expect(TLSInspectionDetector.parseIdentities(identities) == ["0123456789ABCDEF0123456789ABCDEF01234567"])
    }

    @Test func guestInstallBuildsACombinedBundleAndTrustsOnlyRootsAsRoots() {
        let root = InspectionCA(sha256: "AA", subject: "Inspection Root", pem: pem(inspectionRoot), isRoot: true)
        let intermediate = InspectionCA(sha256: "BB", subject: "Inspection Intermediate", pem: pem(inspectionIntermediate), isRoot: false)
        let command = GuestInspectionTrust.installCommand([root, intermediate])
        #expect(command.contains("sudo -n security add-trusted-cert -d -r trustRoot -p ssl -p basic -k /Library/Keychains/System.keychain \"$d/inspection-ca-0.pem\""))
        #expect(command.contains("sudo -n security add-certificates -k /Library/Keychains/System.keychain \"$d/inspection-ca-1.pem\""))
        #expect(command.contains("cat \"$base\" \"$d/inspection-ca.pem\" > \"$d/ca-bundle.pem.tmp\""))
        #expect(command.contains("/etc/ssl/cert.pem"))
        #expect(command.hasSuffix("echo \(GuestInspectionTrust.okMarker)"))
        #expect(!command.contains("PRIVATE KEY"))
    }

    @Test func guestEnvPointsTLSClientsAtTheCombinedBundle() {
        let env = GuestEgressEnv.standard.trustingInspectionCA()
        let names = env.variables.map(\.0)
        for name in ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "NODE_EXTRA_CA_CERTS"] {
            #expect(names.contains(name))
        }
        let dotEnv = env.runnerDotEnvCommand()
        #expect(dotEnv.contains("'SSL_CERT_FILE='\"$HOME\"'/.sand/ca-bundle.pem'"))
        #expect(dotEnv.contains("'NODE_EXTRA_CA_CERTS='\"$HOME\"'/.sand/inspection-ca.pem'"))
        #expect(env.guestSetupCommand.contains("export SSL_CERT_FILE=$HOME/.sand/ca-bundle.pem"))
        #expect(!GuestEgressEnv.standard.variables.contains { $0.0 == "SSL_CERT_FILE" })
    }
}

@Suite struct NetworkBackendFailureTests {
    @Test func classifiesTartStderr() {
        #expect(NetworkBackendFailure.classify(stderr: "Error: Softnet process terminated prematurely", backend: .softnet) == "softnet-terminated")
        #expect(NetworkBackendFailure.classify(stderr: "sudo: a password is required to run softnet", backend: .softnet) == "softnet-privilege")
        #expect(NetworkBackendFailure.classify(stderr: "vmnet_start_interface failed: VMNET_FAILURE", backend: .hostOnly) == "host-network-failed")
        #expect(NetworkBackendFailure.classify(stderr: "", backend: .hostOnly) == "tart-exited-early")
        #expect(NetworkBackendFailure.summary("a\n\nb\nc\nd") == "b | c | d")
        #expect(NetworkBackendFailure.summary("exit 1: wrapper noise\nusage: x\nRuntimeFailed(why: \"Softnet process terminated prematurely\")") == "RuntimeFailed(why: \"Softnet process terminated prematurely\")")
    }

    @Test func auditLineQuotesInsteadOfMangling() {
        let event = NetworkAuditEvent(name: "network.policy.compiled", level: .info, fields: ["tart_args": "--net-softnet --net-softnet-block=0.0.0.0/0", "hash": "abc", "evil": "x\" injected=1\nnext"])
        #expect(event.line == #"network.policy.compiled evil="x\" injected=1_next" hash=abc tart_args="--net-softnet --net-softnet-block=0.0.0.0/0""#)
    }
}

@Suite(.serialized) struct RunnerEnforcementTests {
    @Test func deadNetworkBackendStopsAfterTheLimitWithAuditEvents() async throws {
        let host = FakeVMHost()
        host.tartExitStderr = "Error: Softnet process terminated prematurely"
        let recorder = AuditRecorder()
        let runner = makeRunner(
            host: host, network: dependencies(host: host, proxy: FakeProxy(), recorder: recorder),
            policy: NetworkConfig(selection: .profile(.github), backend: .softnet, maxEnforcementFailures: 2), stopAfter: nil
        )
        var thrown: Error?
        do { try await runner.run() } catch { thrown = error }
        let error = try #require(thrown as? NetworkEnforcementError)
        #expect(error.isFatal)
        let failed = recorder.events.filter { $0.name == "network.enforcement.failed" }
        #expect(failed.count == 2)
        #expect(failed.allSatisfy { $0.fields["reason"] == "softnet-terminated" && $0.fields["stage"] == "before-ip" })
        #expect(failed.last?.fields["final"] == "true")
        #expect(host.clones == 2)
        // Every retry kept the isolated backend: never shared NAT.
        #expect(host.lock.withLock { host.tartRunArguments }.allSatisfy { $0.contains("--net-softnet") })
    }

    @Test func hostOnlyBootsWithNetHostAndReportsListeners() async throws {
        let host = FakeVMHost()
        let recorder = AuditRecorder()
        var deps = dependencies(host: host, proxy: FakeProxy(), recorder: recorder)
        deps.hostListeners = { _ in .init(listeners: [HostListener(proto: .tcp, port: 5000, boundTo: "*", process: "ControlCenter:1311")], method: "netstat") }
        let runner = makeRunner(host: host, network: deps)
        try await runner.run()
        #expect(host.lock.withLock { host.tartRunArguments }.first?.contains("--net-host") == true)
        #expect(recorder.events.contains { $0.name == "network.host.listeners" && $0.fields["listeners"] == "tcp/5000 (ControlCenter:1311)" })
        #expect(host.lock.withLock { host.started }.contains { $0.contains("provisioned-marker") })
    }

    @Test func hostListenersDenyRefusesTheVM() async {
        let host = FakeVMHost()
        let recorder = AuditRecorder()
        var deps = dependencies(host: host, proxy: FakeProxy(), recorder: recorder)
        deps.hostListeners = { _ in .init(listeners: [HostListener(proto: .tcp, port: 5000, boundTo: "*")], method: "lsof+sweep") }
        let runner = makeRunner(host: host, network: deps, policy: NetworkConfig(selection: .profile(.github), hostListeners: .deny))
        await #expect(throws: NetworkEnforcementError.self) { try await runner.run() }
        #expect(!host.lock.withLock { host.started }.contains { $0.contains("provisioned-marker") })
        #expect(recorder.events.contains { $0.name == "network.host.listeners" && $0.fields["result"] == "denied" })
        #expect(recorder.events.contains { $0.name == "network.enforcement.failed" && $0.fields["reason"] == "host-listeners" })
    }

    @Test func trustedInspectionCAIsInstalledBeforeProvisioning() async throws {
        let host = FakeVMHost()
        let recorder = AuditRecorder()
        var deps = dependencies(host: host, proxy: FakeProxy(), recorder: recorder)
        deps.inspectionCAs = [InspectionCA(sha256: "AA77", subject: "Inspection Root", pem: "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n", isRoot: true)]
        let runner = makeRunner(host: host, network: deps, policy: NetworkConfig(selection: .profile(.github), tlsInspection: .trustHostCA))
        try await runner.run()
        let executed = host.lock.withLock { host.executed }
        let install = try #require(executed.firstIndex { $0.contains("add-trusted-cert") })
        #expect(executed[install].contains("QUJD"))
        #expect(executed.contains { $0.contains("networksetup") && $0.contains("SSL_CERT_FILE") })
        #expect(recorder.events.contains { $0.name == "network.tls.inspection.trusted" && $0.fields["ca_sha256"] == "AA77" })
        #expect(host.lock.withLock { host.started }.contains { $0.contains("provisioned-marker") })
    }

    @Test func inspectionCAIsIgnoredUnlessOptedIn() async throws {
        let host = FakeVMHost()
        let recorder = AuditRecorder()
        var deps = dependencies(host: host, proxy: FakeProxy(), recorder: recorder)
        deps.inspectionCAs = [InspectionCA(sha256: "AA77", subject: "Inspection Root", pem: "x", isRoot: true)]
        try await makeRunner(host: host, network: deps).run()
        #expect(!host.lock.withLock { host.executed }.contains { $0.contains("add-trusted-cert") })
    }
}

@Suite struct NetworkFixtureTests {
    @Test func everyFixtureNetworkBlockValidates() throws {
        let fixtures = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("fixtures")
        for file in try FileManager.default.contentsOfDirectory(atPath: fixtures.path) where file.hasSuffix(".yml") {
            let config = try Config.load(path: fixtures.appendingPathComponent(file).path)
            let networkErrors = ConfigValidator().validate(config).filter { $0.severity == .error && $0.message.contains("vm.run.network") }
            #expect(networkErrors.isEmpty, "\(file): \(networkErrors.map(\.message))")
            for runner in config.runners {
                _ = try runner.vm.run.network.compile(sshPort: runner.vm.ssh.port, autoBackend: .hostOnly)
            }
        }
    }

    @Test func enterpriseFixtureCompilesToHostOnlyWithOptIns() throws {
        let path = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("fixtures/network_enterprise_hostonly.yml").path
        let policy = try #require(try Config.load(path: path).runners.first).vm.run.network.compile()
        #expect(policy.tartArguments == ["--net-host"])
        #expect(policy.options.hostListeners == .deny)
        #expect(policy.options.tlsInspection == .trustHostCA)
    }
}
