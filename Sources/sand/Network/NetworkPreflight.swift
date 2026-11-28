import CryptoKit
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
    /// An integer sysctl (readable without root), nil when it cannot be read.
    func sysctlInt(_ name: String) -> Int?
    /// Exists (following symlinks).
    func fileExists(_ path: String) -> Bool
    func readFile(_ path: String) -> String?
    /// Lowercase hex SHA-256 of a file's contents.
    func sha256(ofFile path: String) -> String?
    /// access(2) X_OK for this process's real user and groups.
    func isExecutable(_ path: String) -> Bool
}

/// The host's IPv4/IPv6 forwarding switches (nil: unreadable).
struct IPForwardingState: Sendable, Equatable {
    static let ipv4Name = "net.inet.ip.forwarding"
    static let ipv6Name = "net.inet6.ip6.forwarding"

    var ipv4: Int?
    var ipv6: Int?

    static func read(_ sysctl: (String) -> Int?) -> IPForwardingState {
        IPForwardingState(ipv4: sysctl(ipv4Name), ipv6: sysctl(ipv6Name))
    }

    static func current() -> IPForwardingState {
        read(SystemPreflightFileSystem.sysctlInt)
    }

    /// Fail closed: an unreadable switch counts as on.
    var isOff: Bool { ipv4 == 0 && ipv6 == 0 }

    /// `net.inet.ip.forwarding=1 net.inet6.ip6.forwarding=1`
    var summary: String {
        "\(Self.ipv4Name)=\(ipv4.map(String.init) ?? "unreadable") \(Self.ipv6Name)=\(ipv6.map(String.init) ?? "unreadable")"
    }
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

    /// Space available to an unprivileged process right now (statfs f_bavail).
    /// Not `volumeAvailableCapacityForImportantUsage`, which counts purgeable
    /// space the OS may never free for a `tart clone`.
    func freeBytes(atPath path: String) -> Int64? {
        var info = statfs()
        guard statfs(path, &info) == 0 else { return nil }
        return Int64(info.f_bavail) * Int64(info.f_bsize)
    }

    func sysctlInt(_ name: String) -> Int? {
        Self.sysctlInt(name)
    }

    func fileExists(_ path: String) -> Bool {
        FileManager.default.fileExists(atPath: path)
    }

    func isExecutable(_ path: String) -> Bool {
        access(path, X_OK) == 0
    }

    func readFile(_ path: String) -> String? {
        guard let data = FileManager.default.contents(atPath: path), data.count <= 64 * 1024 else { return nil }
        return String(data: data, encoding: .utf8)
    }

    func sha256(ofFile path: String) -> String? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }
        var hasher = SHA256()
        while true {
            guard let chunk = try? handle.read(upToCount: 1 << 20) else { return nil }
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    static func sysctlInt(_ name: String) -> Int? {
        var value: Int32 = 0
        var size = MemoryLayout<Int32>.size
        guard sysctlbyname(name, &value, &size, nil, 0) == 0, size == MemoryLayout<Int32>.size else { return nil }
        return Int(value)
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
    The softnet backend needs a privileged softnet that only root can replace: root-owned, in directories that are
    root-owned and not group/world-writable all the way up to /. On a managed Mac IT installs it at
    \(SoftnetDiscovery.managedPath) (deploy/jamf/install-managed-softnet.sh). To do it yourself, once, in your own
    terminal from a sand checkout (sand never runs sudo):
      sudo deploy/jamf/install-managed-softnet.sh
    (downloads the pinned softnet release, verifies its SHA-256, installs it setuid root, executable only by the runner
    group (--group, default staff; this user must be in it), and writes a SHA-256 manifest).
    Never make the Homebrew softnet setuid root or sudoers-allowed: /opt/homebrew is writable by your user, so anything
    running as you could replace the binary and get root. Softnet runs its setup as root and rewrites the system bootpd
    prefs (DHCPLeaseTimeSecs=600). Without it, backend: auto (the default) uses hostOnly, which needs no root.
    To opt out of isolation instead: vm.run.network: { mode: shared }.
    """

    let processRunner: ProcessRunning
    let fileSystem: PreflightFileSystem
    let resolver: HostResolving
    let hostProbe: HostEgressProbing
    /// Optional in-process proxy self-test (P5); nil skips it.
    let proxySelfTest: (@Sendable (EgressPolicy) async -> [PreflightCheck])?
    let hostFacts: @Sendable () -> HostFacts
    /// P10; nil skips TLS-inspection detection (tests). Production passes `.live`.
    let tlsInspection: TLSInspectionDetector?

    init(
        processRunner: ProcessRunning,
        fileSystem: PreflightFileSystem = SystemPreflightFileSystem(),
        resolver: HostResolving = SystemHostResolver(),
        hostProbe: HostEgressProbing = SystemHostEgressProbe(),
        proxySelfTest: (@Sendable (EgressPolicy) async -> [PreflightCheck])? = NetworkPreflight.liveProxySelfTest,
        hostFacts: @escaping @Sendable () -> HostFacts = { HostFacts.current() },
        tlsInspection: TLSInspectionDetector? = nil
    ) {
        self.hostFacts = hostFacts
        self.tlsInspection = tlsInspection
        self.processRunner = processRunner
        self.fileSystem = fileSystem
        self.resolver = resolver
        self.hostProbe = hostProbe
        self.proxySelfTest = proxySelfTest
    }

    static func failures(_ checks: [PreflightCheck]) -> [PreflightCheck] {
        checks.filter { $0.status == .failed }
    }

    /// The production preflight: everything, including TLS-inspection detection.
    static func live(processRunner: ProcessRunning) -> NetworkPreflight {
        NetworkPreflight(processRunner: processRunner, tlsInspection: .live(processRunner: processRunner))
    }

    /// Everything, for startup and `sand doctor`.
    func run(policy: NetworkPolicy, includeSSHTools: Bool = true) async -> [PreflightCheck] {
        await runWithInspection(policy: policy, includeSSHTools: includeSSHTools).checks
    }

    /// Like `run`, plus the TLS-inspection report (whose CA certificates the
    /// runner installs in the guest under `tlsInspection: trustHostCA`).
    func runWithInspection(policy: NetworkPolicy, includeSSHTools: Bool = true) async -> (checks: [PreflightCheck], inspection: TLSInspectionReport?) {
        guard policy.isIsolated else {
            return ([PreflightCheck("P8 network mode", .warning, "mode shared: VM has unrestricted host/LAN/VPN/corporate network reach")], nil)
        }
        var checks: [PreflightCheck] = []
        var inspection: TLSInspectionReport?
        if let fallback = policy.host.autoFallback {
            checks.append(PreflightCheck(
                "P0 backend auto", fallback.loud ? .warning : .ok,
                "using hostOnly: \(fallback.reason)",
                remediation: fallback.loud ? Self.softnetRemediation : nil
            ))
        }
        checks.append(contentsOf: await checkTart(backend: policy.backend ?? .softnet))
        if policy.usesSoftnet {
            checks.append(contentsOf: await checkSoftnet(locateSoftnet(policy), pin: policy.host.softnetSHA256))
        } else {
            checks.append(PreflightCheck("P3 softnet privilege", .ok, "not needed: the hostOnly backend runs without root"))
            checks.append(checkIPForwarding(policy))
        }
        if let egress = policy.egress {
            checks.append(checkDirectCIDROverlap(egress))
            checks.append(contentsOf: await checkHostEgress())
            if let proxySelfTest {
                checks.append(contentsOf: await proxySelfTest(egress))
            }
            if let tlsInspection {
                let report = await tlsInspection.detect(hosts: TLSInspectionDetector.probeHosts(for: egress))
                inspection = report
                checks.append(contentsOf: Self.inspectionChecks(report, mode: policy.options.tlsInspection))
            }
        }
        if includeSSHTools {
            let missing = ["ssh", "sshpass"].filter { fileSystem.which($0) == nil }
            checks.append(missing.isEmpty
                ? PreflightCheck("P6 ssh tools", .ok, "ssh and sshpass found (guest sshd TCP forwarding is verified after boot)")
                : PreflightCheck("P6 ssh tools", .failed, "missing \(missing.joined(separator: ", "))", remediation: missing.contains("sshpass") ? "brew install hudochenkov/sshpass/sshpass" : nil))
        }
        checks.append(checkDisk())
        return (checks, inspection)
    }

    /// P10: interception of the proxy's upstream TLS. Off: fail closed with the
    /// list of hosts. trustHostCA: OK when every intercepting CA was exported.
    static func inspectionChecks(_ report: TLSInspectionReport, mode: NetworkConfig.TLSInspectionMode) -> [PreflightCheck] {
        var checks: [PreflightCheck] = []
        if !report.unreachable.isEmpty {
            let detail = report.unreachable.sorted { $0.key < $1.key }.map { "\($0.key): \($0.value)" }.joined(separator: "; ")
            checks.append(PreflightCheck("P10 TLS inspection probe", .warning, "could not inspect \(detail)"))
        }
        guard report.isIntercepted else {
            checks.append(PreflightCheck("P10 TLS inspection", .ok, "no interception of upstream TLS (\(report.probed.count - report.unreachable.count) host(s) chain to Apple-shipped roots)"))
            return checks
        }
        let hosts = report.interceptedHosts.joined(separator: ", ")
        let authorities = report.authorities.isEmpty ? "an unexportable CA" : report.authoritySummary
        switch mode {
        case .fail:
            checks.append(PreflightCheck(
                "P10 TLS inspection", .failed,
                "the host's upstream TLS is intercepted for \(hosts) (issuer: \(authorities)); the guest does not trust that CA, so Actions jobs would fail TLS",
                remediation: """
                Either ask IT to exempt these hosts from TLS inspection: \(hosts)
                (typically *.actions.githubusercontent.com, *.githubusercontent.com and the GitHub results *.blob.core.windows.net accounts),
                or opt in to trusting the inspection CA in the guest: vm.run.network.tlsInspection: trustHostCA
                (only the CA's public certificate is installed; its fingerprint is written to the audit log).
                """
            ))
        case .trustHostCA:
            if report.problems.isEmpty, !report.authorities.isEmpty {
                checks.append(PreflightCheck("P10 TLS inspection", .ok, "interception for \(hosts); guest will trust \(report.authoritySummary)"))
            } else {
                checks.append(PreflightCheck(
                    "P10 TLS inspection", .failed,
                    "interception for \(hosts) but the CA cannot be trusted in the guest: \(report.problems.joined(separator: "; "))",
                    remediation: "Ask IT to exempt these hosts from TLS inspection, or to install the inspection CA (public certificate) in /Library/Keychains/System.keychain."
                ))
            }
        }
        return checks
    }

    /// What `backend: auto` means on this host: softnet when a safely installed
    /// (root-owned path), new enough, privileged softnet exists; otherwise hostOnly
    /// (which needs no root). A privileged softnet in a user-writable location
    /// is never used: auto falls back loudly.
    ///
    /// A managed install (or `softnetPath`) is a statement that this Mac uses
    /// softnet: when it is present, auto keeps softnet whatever is wrong with it
    /// (unsafe path, unprivileged, too old, pin mismatch, old tart), so preflight
    /// fails closed instead of quietly downgrading a fleet to hostOnly. Only a
    /// PATH softnet (or none at all) is a reason to fall back.
    func resolveBackend(_ config: NetworkConfig) async -> EnforcementBackend {
        await resolveBackendWithReason(config).backend
    }

    func resolveBackendWithReason(_ config: NetworkConfig) async -> (backend: EnforcementBackend, fallback: NetworkPolicy.AutoFallback?) {
        switch config.backendChoice {
        case .hostOnly: return (.hostOnly, nil)
        case .softnet: return (.softnet, nil)
        case .auto:
            let location: SoftnetLocation
            switch SoftnetDiscovery.locate(configuredPath: config.softnetPath, fileSystem: fileSystem) {
            case let .missing(reason):
                if config.softnetPath != nil {
                    // An explicit path that is gone: fail closed (P2), never fall back.
                    return (.softnet, nil)
                }
                return (.hostOnly, .init(reason: reason, loud: false))
            case let .found(found):
                location = found
            }
            if location.source != .path {
                return (.softnet, nil)
            }
            let tart = await checkTart(backend: .softnet)
            let softnet = await checkSoftnet(.found(location), pin: config.softnetSHA256)
            let failures = Self.failures(tart + softnet)
            if failures.isEmpty || failures.allSatisfy({ $0.name == Self.pinCheckName }) {
                return (.softnet, nil)
            }
            let rejectedPrivileged = failures.contains { $0.name == Self.pathCheckName } && SoftnetDiscovery.isSetuidRoot(location.resolved, fileSystem: fileSystem)
            let reason = "softnet not usable: " + failures.map { "\($0.name): \($0.detail)" }.joined(separator: "; ")
            return (.hostOnly, .init(reason: reason, loud: rejectedPrivileged))
        }
    }

    /// Compiles a runner's policy, resolving `backend: auto` on this host unless
    /// a backend was already pinned (at startup) for this runner, and binds it to
    /// the softnet binary tart will exec.
    func compile(_ config: NetworkConfig, sshPort: Int, pinnedBackend: EnforcementBackend? = nil) async throws -> NetworkPolicy {
        let backend: EnforcementBackend
        var fallback: NetworkPolicy.AutoFallback?
        if let pinnedBackend, config.backendChoice == .auto {
            backend = pinnedBackend
        } else {
            (backend, fallback) = await resolveBackendWithReason(config)
        }
        var policy = try config.compile(sshPort: sshPort, autoBackend: backend)
        policy.host.softnetPath = config.softnetPath
        policy.host.softnetSHA256 = config.softnetSHA256
        policy.host.autoFallback = policy.isHostOnly ? fallback : nil
        if policy.usesSoftnet, case let .found(location) = SoftnetDiscovery.locate(configuredPath: config.softnetPath, fileSystem: fileSystem) {
            policy.host.softnet = location
        }
        return policy
    }

    /// The softnet a policy is bound to, or (for a policy compiled without a
    /// host) the one discovery finds now.
    func locateSoftnet(_ policy: NetworkPolicy) -> SoftnetDiscovery.Outcome {
        if let location = policy.host.softnet { return .found(location) }
        return SoftnetDiscovery.locate(configuredPath: policy.host.softnetPath, fileSystem: fileSystem)
    }

    /// Cheap re-check before every clone: privilege can be reset by `brew upgrade`.
    func perVM(policy: NetworkPolicy) async -> [PreflightCheck] {
        guard policy.isIsolated else { return [] }
        var checks: [PreflightCheck] = []
        if policy.usesSoftnet {
            // Not `--help` again; but the path, privilege and pin, since the
            // binary tart is about to exec must still be the one that was checked.
            switch locateSoftnet(policy) {
            case let .missing(reason):
                checks.append(PreflightCheck("P2 softnet", .failed, reason, remediation: Self.softnetRemediation))
            case let .found(location):
                let path = checkSoftnetPath(location)
                checks.append(path)
                if path.status != .failed {
                    checks.append(await checkSoftnetPrivilege(location))
                    checks.append(checkSoftnetPin(location, configured: policy.host.softnetSHA256))
                }
            }
        }
        if policy.isHostOnly {
            // VPN clients and Internet Sharing toggle forwarding at runtime.
            checks.append(checkIPForwarding(policy))
        }
        if let egress = policy.egress {
            checks.append(checkDirectCIDROverlap(egress))
            do {
                let addresses = try await resolver.resolve("github.com")
                checks.append(PreflightCheck("P4 resolve github.com", addresses.isEmpty ? .failed : .ok, "\(addresses.count) address(es)"))
            } catch {
                checks.append(PreflightCheck("P4 resolve github.com", .failed, "\(error)", remediation: "Check the host network/VPN connection."))
            }
        }
        return checks
    }

    func checkTart(backend: EnforcementBackend) async -> [PreflightCheck] {
        guard fileSystem.which("tart") != nil else {
            return [PreflightCheck("P1 tart", .failed, "tart not found in PATH", remediation: "brew install cirruslabs/cli/tart")]
        }
        let help = (try? await processRunner.run(executable: "tart", arguments: ["run", "--help"], wait: true))?.stdout ?? ""
        let version = ((try? await processRunner.run(executable: "tart", arguments: ["--version"], wait: true))?.stdout ?? "unknown")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        switch backend {
        case .softnet:
            guard help.contains("--net-softnet-allow") else {
                return [PreflightCheck("P1 tart", .failed, "tart \(version) does not support --net-softnet-allow", remediation: "brew upgrade cirruslabs/cli/tart")]
            }
            return [PreflightCheck("P1 tart", .ok, "tart \(version) supports softnet rules")]
        case .hostOnly:
            guard help.contains("--net-host") else {
                return [PreflightCheck("P1 tart", .failed, "tart \(version) does not support --net-host (host-only networking)", remediation: "brew upgrade cirruslabs/cli/tart")]
            }
            return [PreflightCheck("P1 tart", .ok, "tart \(version) supports --net-host (hostOnly backend, no root)")]
        }
    }

    static let pathCheckName = "P12 softnet path"
    static let pinCheckName = "P13 softnet pin"

    /// P2 (found, new enough), P12 (path safety), P3 (privilege), P13 (pin).
    /// Nothing is executed from an unsafe path: not `--help`, not `sudo -n`.
    func checkSoftnet(_ outcome: SoftnetDiscovery.Outcome, pin: String?) async -> [PreflightCheck] {
        let location: SoftnetLocation
        switch outcome {
        case let .missing(reason):
            return [PreflightCheck("P2 softnet", .failed, reason, remediation: Self.softnetRemediation)]
        case let .found(found):
            location = found
        }
        let path = checkSoftnetPath(location)
        guard path.status != .failed else { return [path] }
        let help = (try? await processRunner.run(executable: location.resolved, arguments: ["--help"], wait: true))?.stdout ?? ""
        guard help.contains("proto"), help.contains("@host") else {
            return [path, PreflightCheck("P2 softnet", .failed, "softnet (\(location.summary)) too old for stateful rules (needs 'proto' and '@host')", remediation: "Install softnet 0.26 or newer: " + Self.softnetRemediation)]
        }
        return [
            path,
            PreflightCheck("P2 softnet", .ok, "\(location.summary) supports stateful rules"),
            await checkSoftnetPrivilege(location),
            checkSoftnetPin(location, configured: pin)
        ]
    }

    /// P12: a softnet that runs as root must not be replaceable by a non-root user.
    func checkSoftnetPath(_ location: SoftnetLocation) -> PreflightCheck {
        let problems = SoftnetDiscovery.pathProblems(location, fileSystem: fileSystem)
        guard !problems.isEmpty else {
            return PreflightCheck(Self.pathCheckName, .ok, "\(location.summary): root-owned, no group/world-writable component up to /")
        }
        let setuid = SoftnetDiscovery.isSetuidRoot(location.resolved, fileSystem: fileSystem)
        let lead = setuid
            ? "\(location.summary) is setuid root but a non-root user can replace it (local privilege escalation); sand refuses to use it"
            : "\(location.summary) is not installed where only root can replace it; sand never runs a privileged softnet from such a path"
        return PreflightCheck(Self.pathCheckName, .failed, lead + ": " + problems.joined(separator: "; "), remediation: Self.softnetRemediation)
    }

    /// P3, same rule softnet applies: setuid root, or passwordless `sudo -n`.
    /// Only ever called for a path that passed P12.
    func checkSoftnetPrivilege(_ location: SoftnetLocation) async -> PreflightCheck {
        if SoftnetDiscovery.isSetuidRoot(location.resolved, fileSystem: fileSystem) {
            // The managed installer restricts the setuid binary to a runner group (mode 4550).
            guard fileSystem.isExecutable(location.resolved) else {
                return PreflightCheck(
                    "P3 softnet privilege", .failed,
                    "softnet (\(location.resolved)) is setuid root but not executable by this user; tart would fail to boot isolated VMs",
                    remediation: "Add this user to the group the managed softnet was installed for (install-managed-softnet.sh --group, Jamf parameter 8; default staff), or reinstall it for this user's group."
                )
            }
            return PreflightCheck("P3 softnet privilege", .ok, "softnet is setuid root")
        }
        // Non-interactive only: -n never prompts, and -k ignores a cached sudo
        // ticket (from running the installer in this terminal), so this passes
        // only for a NOPASSWD rule, as softnet's own `sudo -n` will need.
        // softnet re-execs itself via `sudo -n <its own path>`, which is
        // `resolved` because tart execs it from there.
        if (try? await processRunner.run(executable: "sudo", arguments: ["-n", "-k", location.resolved, "--help"], wait: true)) != nil {
            return PreflightCheck("P3 softnet privilege", .ok, "passwordless sudo is configured for \(location.resolved)")
        }
        return PreflightCheck("P3 softnet privilege", .failed, "softnet (\(location.resolved)) is neither setuid root nor allowed by passwordless sudo; tart would fail to boot isolated VMs", remediation: Self.softnetRemediation)
    }

    /// P13: `softnetSHA256` and/or the installer's manifest next to the binary.
    /// Any pin that is present must match; a bad manifest fails closed.
    func checkSoftnetPin(_ location: SoftnetLocation, configured: String?) -> PreflightCheck {
        let remediation = "Reinstall softnet with deploy/jamf/install-managed-softnet.sh, or review the binary and update vm.run.network.softnetSHA256."
        var expected: [(source: String, digest: String)] = []
        if let configured {
            expected.append(("vm.run.network.softnetSHA256", configured.lowercased()))
        }
        let manifest = (location.directory as NSString).appendingPathComponent(SoftnetDiscovery.manifestName)
        if fileSystem.fileExists(manifest) {
            guard let info = fileSystem.ownerAndMode(manifest), info.uid == 0, info.mode & UInt16(S_IWGRP | S_IWOTH) == 0 else {
                return PreflightCheck(Self.pinCheckName, .failed, "\(manifest) is not root-owned or is group/world-writable", remediation: remediation)
            }
            guard let text = fileSystem.readFile(manifest), let digest = SoftnetDiscovery.parseManifest(text) else {
                return PreflightCheck(Self.pinCheckName, .failed, "\(manifest) is unreadable or not a SHA-256 manifest", remediation: remediation)
            }
            expected.append((manifest, digest))
        }
        guard !expected.isEmpty else {
            return PreflightCheck(Self.pinCheckName, location.source == .managed ? .warning : .ok, "no SHA-256 pin for \(location.resolved) (set vm.run.network.softnetSHA256, or install with the managed installer, which writes \(SoftnetDiscovery.manifestName))")
        }
        guard let actual = fileSystem.sha256(ofFile: location.resolved) else {
            return PreflightCheck(Self.pinCheckName, .failed, "cannot read \(location.resolved) to hash it", remediation: remediation)
        }
        let mismatched = expected.filter { $0.digest != actual }
        guard mismatched.isEmpty else {
            let detail = mismatched.map { "expected \($0.digest) (\($0.source))" }.joined(separator: ", ")
            return PreflightCheck(Self.pinCheckName, .failed, "SHA-256 of \(location.resolved) is \(actual); \(detail)", remediation: remediation)
        }
        return PreflightCheck(Self.pinCheckName, .ok, "SHA-256 \(actual.prefix(16))... matches \(expected.map(\.source).joined(separator: " and "))")
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

    static let ipForwardingRemediation = """
    Under the hostOnly backend a guest with root (CI jobs usually have passwordless sudo) can add a route via the
    host's bridge address; with host IP forwarding on, the host then forwards its packets to the LAN, VPN and
    tailnet (for example a tailnet DNS resolver answers), outside the proxy, the allowlist and the audit log.
    Either turn forwarding off in your own terminal (sand never does this; a VPN client or Internet Sharing may turn it back on):
      sudo sysctl -w net.inet.ip.forwarding=0 net.inet6.ip6.forwarding=0
    or install the managed softnet (sudo deploy/jamf/install-managed-softnet.sh, or your Jamf policy) so the default
    backend: auto uses softnet, which filters guest packets before the host routes them,
    or accept the exposure explicitly: vm.run.network.ipForwarding: accept (every VM logs and audits it).
    """

    /// P11 (hostOnly): host IP forwarding must be off unless explicitly accepted.
    func checkIPForwarding(_ policy: NetworkPolicy) -> PreflightCheck {
        let state = IPForwardingState.read(fileSystem.sysctlInt)
        if state.isOff {
            return PreflightCheck("P11 host IP forwarding", .ok, "off (\(state.summary)): a guest route via the bridge reaches only the host itself")
        }
        if policy.options.ipForwarding == .accept {
            return PreflightCheck("P11 host IP forwarding", .warning, "on (\(state.summary)) and accepted by ipForwarding: accept: a guest with root can route through the host")
        }
        return PreflightCheck(
            "P11 host IP forwarding", .failed,
            "host IP forwarding is on or unreadable (\(state.summary)); a guest with root could route through the host and bypass the proxy",
            remediation: Self.ipForwardingRemediation
        )
    }

    /// P9: a reviewed `allowedCIDRs` entry must never cover the host itself or
    /// an attached subnet; the softnet allow would reach it directly.
    func checkDirectCIDROverlap(_ egress: EgressPolicy) -> PreflightCheck {
        guard !egress.extraCIDRs.isEmpty else {
            return PreflightCheck("P9 allowedCIDRs vs host", .ok, "no direct CIDR allows")
        }
        let overlaps = NetworkConfig.hostOverlaps(egress.extraCIDRs, facts: hostFacts())
        guard overlaps.isEmpty else {
            let detail = overlaps.map { "\($0.0.cidr): \($0.1)" }.joined(separator: "; ")
            return PreflightCheck("P9 allowedCIDRs vs host", .failed, detail, remediation: "Remove or narrow the allowedCIDRs entry; the VM must never reach the host or its LAN/VPN subnets directly.")
        }
        return PreflightCheck("P9 allowedCIDRs vs host", .ok, "\(egress.extraCIDRs.count) entr(ies) clear of host subnets")
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
