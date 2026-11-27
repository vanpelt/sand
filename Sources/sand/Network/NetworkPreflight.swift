import Darwin
import Foundation
import Network

struct PreflightCheck: Sendable, Equatable {
    enum Status: String, Sendable {
        case ok
        case warning
        case failed
    }

    let name: String
    let status: Status
    let detail: String
    let remediation: String?

    init(_ name: String, _ status: Status, _ detail: String, remediation: String? = nil) {
        self.name = name
        self.status = status
        self.detail = detail
        self.remediation = remediation
    }

    var line: String {
        var text = "[\(status.rawValue)] \(name): \(detail)"
        if let remediation {
            text += "\n    fix: " + remediation.replacingOccurrences(of: "\n", with: "\n         ")
        }
        return text
    }
}

/// Host file-system facts the preflight needs; injectable for tests.
protocol PreflightFileSystem: Sendable {
    func which(_ command: String) -> String?
    func realpath(_ path: String) -> String
    /// (owner uid, mode bits) of a path.
    func ownerAndMode(_ path: String) -> (uid: UInt32, mode: UInt16)?
    func freeBytes(atPath path: String) -> Int64?
}

struct SystemPreflightFileSystem: PreflightFileSystem {
    func which(_ command: String) -> String? {
        let searchPaths = (ProcessInfo.processInfo.environment["PATH"] ?? "").split(separator: ":").map(String.init)
        for directory in searchPaths {
            let candidate = (directory as NSString).appendingPathComponent(command)
            if FileManager.default.isExecutableFile(atPath: candidate) {
                return candidate
            }
        }
        return nil
    }

    func realpath(_ path: String) -> String {
        guard let resolved = Darwin.realpath(path, nil) else { return path }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    func ownerAndMode(_ path: String) -> (uid: UInt32, mode: UInt16)? {
        var info = stat()
        guard stat(path, &info) == 0 else { return nil }
        return (info.st_uid, info.st_mode)
    }

    func freeBytes(atPath path: String) -> Int64? {
        let values = try? URL(fileURLWithPath: path).resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        return values?.volumeAvailableCapacityForImportantUsage
    }
}

/// A TLS handshake (no HTTP request, so no rate-limited API call) from the host.
protocol HostEgressProbing: Sendable {
    func tlsHandshake(host: String, port: UInt16, timeout: TimeInterval) async -> Result<Void, Error>
}

enum HostEgressProbeError: Error, CustomStringConvertible {
    case timeout
    case failed(String)

    var description: String {
        switch self {
        case .timeout: return "timed out"
        case let .failed(reason): return reason
        }
    }
}

struct SystemHostEgressProbe: HostEgressProbing {
    func tlsHandshake(host: String, port: UInt16, timeout: TimeInterval) async -> Result<Void, Error> {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return .failure(HostEgressProbeError.failed("bad port")) }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .tls)
        let queue = DispatchQueue(label: "sand.preflight.tls")
        let once = PreflightOnce()
        return await withCheckedContinuation { continuation in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if once.claim() { connection.cancel(); continuation.resume(returning: .success(())) }
                case let .failed(error), let .waiting(error):
                    if once.claim() { connection.cancel(); continuation.resume(returning: .failure(HostEgressProbeError.failed("\(error)"))) }
                default:
                    break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) {
                if once.claim() { connection.cancel(); continuation.resume(returning: .failure(HostEgressProbeError.timeout)) }
            }
        }
    }
}

private final class PreflightOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false

    func claim() -> Bool {
        lock.withLock {
            guard !done else { return false }
            done = true
            return true
        }
    }
}

/// Fail-closed host checks run by `sand doctor`, at startup and before every
/// clone. Sand never runs sudo interactively and never changes host settings;
/// remediation text is for the user to run.
struct NetworkPreflight: Sendable {
    static let softnetRemediation = """
    One-time setup, run in your own terminal (sand never does this):
      sudo chown root:wheel "$(realpath "$(which softnet)")" && sudo chmod u+s "$(realpath "$(which softnet)")"
    `brew upgrade softnet` resets this; re-run it after upgrades. Alternative: a sudoers NOPASSWD rule
    for both /opt/homebrew/bin/softnet and its Cellar path. Softnet runs its setup as root and rewrites the
    system bootpd prefs (DHCPLeaseTimeSecs=600). To opt out of isolation instead: vm.run.network: { mode: shared }.
    """

    let processRunner: ProcessRunning
    let fileSystem: PreflightFileSystem
    let resolver: HostResolving
    let hostProbe: HostEgressProbing
    /// Optional in-process proxy self-test (P5); nil skips it.
    let proxySelfTest: (@Sendable (EgressPolicy) async -> [PreflightCheck])?

    init(
        processRunner: ProcessRunning,
        fileSystem: PreflightFileSystem = SystemPreflightFileSystem(),
        resolver: HostResolving = SystemHostResolver(),
        hostProbe: HostEgressProbing = SystemHostEgressProbe(),
        proxySelfTest: (@Sendable (EgressPolicy) async -> [PreflightCheck])? = NetworkPreflight.liveProxySelfTest
    ) {
        self.processRunner = processRunner
        self.fileSystem = fileSystem
        self.resolver = resolver
        self.hostProbe = hostProbe
        self.proxySelfTest = proxySelfTest
    }

    static func failures(_ checks: [PreflightCheck]) -> [PreflightCheck] {
        checks.filter { $0.status == .failed }
    }

    /// Everything, for startup and `sand doctor`.
    func run(policy: NetworkPolicy, includeSSHTools: Bool = true) async -> [PreflightCheck] {
        guard policy.requiresSoftnet else {
            return [PreflightCheck("P8 network mode", .warning, "mode shared: VM has unrestricted host/LAN/VPN/corporate network reach")]
        }
        var checks: [PreflightCheck] = []
        checks.append(contentsOf: await checkTart())
        checks.append(contentsOf: await checkSoftnet())
        if let egress = policy.egress {
            checks.append(contentsOf: await checkHostEgress())
            if let proxySelfTest {
                checks.append(contentsOf: await proxySelfTest(egress))
            }
        }
        if includeSSHTools {
            let missing = ["ssh", "sshpass"].filter { fileSystem.which($0) == nil }
            checks.append(missing.isEmpty
                ? PreflightCheck("P6 ssh tools", .ok, "ssh and sshpass found (guest sshd TCP forwarding is verified after boot)")
                : PreflightCheck("P6 ssh tools", .failed, "missing \(missing.joined(separator: ", "))", remediation: missing.contains("sshpass") ? "brew install hudochenkov/sshpass/sshpass" : nil))
        }
        checks.append(checkDisk())
        return checks
    }

    /// Cheap re-check before every clone: privilege can be reset by `brew upgrade`.
    func perVM(policy: NetworkPolicy) async -> [PreflightCheck] {
        guard policy.requiresSoftnet else { return [] }
        var checks = [await checkSoftnetPrivilege()]
        if policy.egress != nil {
            do {
                let addresses = try await resolver.resolve("github.com")
                checks.append(PreflightCheck("P4 resolve github.com", addresses.isEmpty ? .failed : .ok, "\(addresses.count) address(es)"))
            } catch {
                checks.append(PreflightCheck("P4 resolve github.com", .failed, "\(error)", remediation: "Check the host network/VPN connection."))
            }
        }
        return checks
    }

    func checkTart() async -> [PreflightCheck] {
        guard fileSystem.which("tart") != nil else {
            return [PreflightCheck("P1 tart", .failed, "tart not found in PATH", remediation: "brew install cirruslabs/cli/tart")]
        }
        let help = (try? await processRunner.run(executable: "tart", arguments: ["run", "--help"], wait: true))?.stdout ?? ""
        let version = ((try? await processRunner.run(executable: "tart", arguments: ["--version"], wait: true))?.stdout ?? "unknown")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard help.contains("--net-softnet-allow") else {
            return [PreflightCheck("P1 tart", .failed, "tart \(version) does not support --net-softnet-allow", remediation: "brew upgrade cirruslabs/cli/tart")]
        }
        return [PreflightCheck("P1 tart", .ok, "tart \(version) supports softnet rules")]
    }

    func checkSoftnet() async -> [PreflightCheck] {
        guard let path = fileSystem.which("softnet") else {
            return [PreflightCheck("P2 softnet", .failed, "softnet not found in PATH", remediation: "brew install openai/tools/softnet\n" + Self.softnetRemediation)]
        }
        let help = (try? await processRunner.run(executable: path, arguments: ["--help"], wait: true))?.stdout ?? ""
        guard help.contains("proto"), help.contains("@host") else {
            return [PreflightCheck("P2 softnet", .failed, "softnet too old for stateful rules (needs 'proto' and '@host')", remediation: "brew upgrade openai/tools/softnet")]
        }
        return [PreflightCheck("P2 softnet", .ok, "softnet supports stateful rules"), await checkSoftnetPrivilege()]
    }

    /// Same rule tart applies: SUID root, or passwordless `sudo -n`.
    func checkSoftnetPrivilege() async -> PreflightCheck {
        guard let path = fileSystem.which("softnet") else {
            return PreflightCheck("P3 softnet privilege", .failed, "softnet not found in PATH", remediation: Self.softnetRemediation)
        }
        let real = fileSystem.realpath(path)
        if let (uid, mode) = fileSystem.ownerAndMode(real), uid == 0, mode & UInt16(S_ISUID) != 0 {
            return PreflightCheck("P3 softnet privilege", .ok, "softnet is setuid root")
        }
        // Non-interactive only: -n never prompts.
        if (try? await processRunner.run(executable: "sudo", arguments: ["-n", real, "--help"], wait: true)) != nil {
            return PreflightCheck("P3 softnet privilege", .ok, "passwordless sudo is configured for softnet")
        }
        return PreflightCheck("P3 softnet privilege", .failed, "softnet is neither setuid root nor allowed by passwordless sudo; tart would fail to boot isolated VMs", remediation: Self.softnetRemediation)
    }

    func checkHostEgress() async -> [PreflightCheck] {
        var checks: [PreflightCheck] = []
        var steered = false
        for host in ["github.com", "api.github.com"] {
            do {
                let addresses = try await resolver.resolve(host)
                let isPrivate = addresses.contains { address in DestinationGuard.steerableRanges.contains { $0.contains(address) } }
                steered = steered || isPrivate
                checks.append(PreflightCheck("P4 resolve \(host)", addresses.isEmpty ? .failed : .ok, isPrivate ? "VPN-steered private front" : "public address"))
            } catch {
                checks.append(PreflightCheck("P4 resolve \(host)", .failed, "\(error)", remediation: "Check the host network/VPN connection."))
            }
        }
        switch await hostProbe.tlsHandshake(host: "api.github.com", port: 443, timeout: 10) {
        case .success:
            checks.append(PreflightCheck("P4 GitHub egress", .ok, steered ? "via VPN-steered front (split DNS)" : "direct"))
        case let .failure(error):
            checks.append(PreflightCheck("P4 GitHub egress", .failed, "TLS handshake to api.github.com:443 failed: \(error)", remediation: "The host itself cannot reach GitHub; fix host connectivity first."))
        }
        return checks
    }

    func checkDisk() -> PreflightCheck {
        let tartHome = ProcessInfo.processInfo.environment["TART_HOME"] ?? Config.expandPath("~/.tart")
        guard let free = fileSystem.freeBytes(atPath: FileManager.default.fileExists(atPath: tartHome) ? tartHome : NSHomeDirectory()) else {
            return PreflightCheck("P7 disk", .ok, "free space unknown")
        }
        let gigabytes = free / 1_000_000_000
        return gigabytes < 20
            ? PreflightCheck("P7 disk", .warning, "only \(gigabytes) GB free for VM clones")
            : PreflightCheck("P7 disk", .ok, "\(gigabytes) GB free")
    }

    /// P5: the real proxy, in process on loopback: an allowlisted name connects,
    /// a non-allowlisted name and a corporate literal are refused.
    static let liveProxySelfTest: @Sendable (EgressPolicy) async -> [PreflightCheck] = { policy in
        let proxy = EgressProxy(
            policy: policy,
            destinationGuard: DestinationGuard(hostFacts: HostFacts.current()),
            resolver: SystemHostResolver(),
            audit: .silent
        )
        defer { proxy.stop() }
        let port: UInt16
        do {
            port = try await proxy.start(port: 0)
        } catch {
            return [PreflightCheck("P5 proxy self-test", .failed, "proxy failed to listen on loopback: \(error)")]
        }
        let results = await Task.detached { () -> [(String, Int?, Int)] in
            [
                ("github.com:443", LoopbackClient.connectStatus(port: port, target: "github.com:443"), 200),
                ("example.com:443", LoopbackClient.connectStatus(port: port, target: "example.com:443"), 403),
                ("172.16.0.1:53", LoopbackClient.connectStatus(port: port, target: "172.16.0.1:53"), 403)
            ]
        }.value
        return results.map { target, status, expected in
            let label = status.map(String.init) ?? "no response"
            return PreflightCheck("P5 proxy CONNECT \(target)", status == expected ? .ok : .failed, "got \(label), expected \(expected)")
        }
    }
}
