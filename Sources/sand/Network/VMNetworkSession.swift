import Foundation

enum NetworkEnforcementError: Error, CustomStringConvertible {
    case preflightFailed([PreflightCheck])
    case subnetOverlap(String)
    case tunnelFailed(String)
    case verificationFailed([GuestEgressVerifier.ProbeResult])

    var description: String {
        switch self {
        case let .preflightFailed(checks):
            return "network preflight failed: " + checks.map { "\($0.name): \($0.detail)" }.joined(separator: "; ")
                + (checks.compactMap(\.remediation).first.map { "\n\($0)" } ?? "")
        case let .subnetOverlap(detail):
            return "VM subnet overlaps a host route: \(detail)"
        case let .tunnelFailed(detail):
            return "guest proxy tunnel failed: \(detail)"
        case let .verificationFailed(results):
            return "guest egress verification failed: " + results.filter { !$0.passed }.map { "\($0.id) \($0.outcome) (\($0.detail))" }.joined(separator: "; ")
        }
    }
}

/// Everything the runner needs to enforce a network policy; injectable for tests.
struct RunnerNetworkDependencies: Sendable {
    var preflight: NetworkPreflight
    var resolver: HostResolving
    var hostFacts: @Sendable () -> HostFacts
    var routes: @Sendable () async -> RouteInspector
    var makeProxy: @Sendable (EgressPolicy, DestinationGuard, NetworkAudit) -> EgressProxying
    var audit: NetworkAudit
    var watchdogInterval: TimeInterval = 2
    var tunnelReadyTimeout: TimeInterval = 20
    var maxSubnetAttempts = 3

    static func live(processRunner: ProcessRunning, audit: NetworkAudit) -> RunnerNetworkDependencies {
        RunnerNetworkDependencies(
            preflight: NetworkPreflight(processRunner: processRunner),
            resolver: SystemHostResolver(),
            hostFacts: { HostFacts.current() },
            routes: { await RouteInspector.current(processRunner: processRunner) },
            makeProxy: { policy, guardrail, audit in
                EgressProxy(policy: policy, destinationGuard: guardrail, resolver: SystemHostResolver(), audit: audit)
            },
            audit: audit
        )
    }
}

/// The host-side enforcement for one booted VM: proxy, tunnel, watchdog.
final class VMNetworkSession: @unchecked Sendable {
    let policy: NetworkPolicy
    private let dependencies: RunnerNetworkDependencies
    private let processRunner: ProcessRunning
    private let logger: Logger
    private var proxy: EgressProxying?
    private var tunnel: ProcessHandle?
    private var watchdog: NetworkWatchdog?
    private let lock = NSLock()

    init(policy: NetworkPolicy, dependencies: RunnerNetworkDependencies, processRunner: ProcessRunning, logger: Logger) {
        self.policy = policy
        self.dependencies = dependencies
        self.processRunner = processRunner
        self.logger = logger
    }

    var audit: NetworkAudit { dependencies.audit }

    var guestEnv: GuestEgressEnv? {
        policy.egress == nil ? nil : .standard
    }

    /// Host routes (other than vmnet bridges) that overlap the VM's /29, or
    /// steered GitHub fronts that would be shadowed by it.
    func subnetConflict(vmIP: String) async -> String? {
        guard policy.requiresSoftnet, let subnet = RouteInspector.vmSubnet(for: vmIP) else { return nil }
        let routes = await dependencies.routes()
        if let overlap = routes.overlaps(subnet).first {
            let destination = overlap.destination.map { $0.description } ?? "default"
            return "\(subnet) overlaps \(destination) via \(overlap.interface)"
        }
        if let egress = policy.egress {
            for name in egress.steeredNames.sorted() {
                if let addresses = try? await dependencies.resolver.resolve(name), let shadowed = addresses.first(where: { subnet.contains($0) }) {
                    return "\(subnet) contains the GitHub front for \(name) (\(shadowed))"
                }
            }
        }
        return nil
    }

    /// Starts the proxy and tunnel and verifies the guest (profile github), or
    /// only verifies (profile offline). Throws on any failure: the caller must
    /// destroy the VM and must not register a runner.
    func establish(ssh: SSHClient, vmIP: String) async throws {
        let facts = dependencies.hostFacts().withVMSubnet(RouteInspector.vmSubnet(for: vmIP))
        if let egress = policy.egress {
            let proxy = dependencies.makeProxy(egress, DestinationGuard(hostFacts: facts), audit)
            lock.withLock { self.proxy = proxy }
            let port = try await proxy.start(port: 0)
            logger.info("egress proxy for VM listening on 127.0.0.1:\(port)")
            let tunnel = try ssh.startReverseTunnel(remotePort: NetworkPolicy.guestProxyPort, localPort: port)
            lock.withLock { self.tunnel = tunnel }
            try await waitForTunnel(ssh: ssh, tunnel: tunnel)
        }
        guard policy.verify != .off else {
            audit.emit("network.guest.verified", level: .warning, ["verify": "off", "policy_hash": policy.policyHash])
            return
        }
        let verifier = await makeVerifier(facts: facts)
        let output = (try await ssh.exec(command: verifier.script))?.stdout ?? ""
        let results = verifier.evaluate(output)
        let failed = results.filter { !$0.passed }
        guard failed.isEmpty else {
            audit.emit("network.guest.verify", level: .error, [
                "result": "failed",
                "failed": failed.map { "\($0.id):\($0.outcome)" }.joined(separator: ","),
                "policy_hash": policy.policyHash
            ])
            throw NetworkEnforcementError.verificationFailed(results)
        }
        audit.emit("network.guest.verified", [
            "verify": policy.verify.rawValue,
            "probes": String(results.count),
            "policy_hash": policy.policyHash
        ])
    }

    /// Starts polling enforcement; `onLost` fires at most once.
    func startWatchdog(tartRun: ProcessHandle, vmIP: String, onLost: @escaping @Sendable (String) async -> Void) async {
        let subnet = RouteInspector.vmSubnet(for: vmIP)
        let routes = dependencies.routes
        var overlap: (@Sendable () async -> String?)?
        if policy.requiresSoftnet, let subnet {
            overlap = {
                guard let route = await routes().overlaps(subnet).first else { return nil }
                let destination = route.destination.map { $0.description } ?? "default"
                return "\(destination)@\(route.interface)"
            }
        }
        let (proxy, tunnel) = lock.withLock { (self.proxy, self.tunnel) }
        let watchdog = NetworkWatchdog(
            components: .init(tartRun: tartRun, tunnel: tunnel, proxy: proxy, checkSoftnet: policy.requiresSoftnet, routeOverlap: overlap),
            interval: dependencies.watchdogInterval,
            processRunner: processRunner
        ) { [audit] component in
            audit.emit("network.enforcement.lost", level: .error, ["component": component])
            await onLost(component)
        }
        lock.withLock { self.watchdog = watchdog }
        await watchdog.start()
    }

    /// Idempotent: stop the watchdog first so expected teardown is not reported as a loss.
    func teardown() async {
        let (watchdog, tunnel, proxy) = lock.withLock { () -> (NetworkWatchdog?, ProcessHandle?, EgressProxying?) in
            defer {
                self.watchdog = nil
                self.tunnel = nil
                self.proxy = nil
            }
            return (self.watchdog, self.tunnel, self.proxy)
        }
        await watchdog?.stop()
        await tunnel?.terminate()
        proxy?.stop()
        if let summary = (proxy as? EgressProxy)?.summary {
            audit.emit("network.session.summary", [
                "allowed": String(summary.allowed),
                "denied": String(summary.denied),
                "bytes_up": String(summary.bytesUp),
                "bytes_down": String(summary.bytesDown),
                "top_denied": summary.deniedByHost.sorted { $0.value > $1.value }.prefix(5).map { "\($0.key):\($0.value)" }.joined(separator: ",")
            ])
        }
    }

    private func waitForTunnel(ssh: SSHClient, tunnel: ProcessHandle) async throws {
        let deadline = Date().addingTimeInterval(dependencies.tunnelReadyTimeout)
        let probe = "(exec 3<>/dev/tcp/127.0.0.1/\(NetworkPolicy.guestProxyPort)) 2>/dev/null && echo SAND_TUNNEL_OK || true"
        while Date() < deadline {
            if await tunnel.hasExited() {
                let stderr: String
                do {
                    stderr = try await tunnel.waitAsync(terminateOnCancel: false).stderr
                } catch let ProcessRunnerError.failed(_, _, message, _) {
                    stderr = message
                } catch {
                    stderr = "\(error)"
                }
                throw NetworkEnforcementError.tunnelFailed("ssh -R exited: \(stderr.trimmingCharacters(in: .whitespacesAndNewlines)) (guest sshd must allow TCP forwarding)")
            }
            if let output = try? await ssh.exec(command: probe)?.stdout, output.contains("SAND_TUNNEL_OK") {
                logger.info("guest proxy tunnel ready on guest 127.0.0.1:\(NetworkPolicy.guestProxyPort)")
                return
            }
            try await Task.sleep(nanoseconds: 500_000_000)
        }
        throw NetworkEnforcementError.tunnelFailed("guest 127.0.0.1:\(NetworkPolicy.guestProxyPort) not reachable after \(Int(dependencies.tunnelReadyTimeout))s")
    }

    private func makeVerifier(facts: HostFacts) async -> GuestEgressVerifier {
        let github = (try? await dependencies.resolver.resolve("github.com")) ?? []
        let direct = github.first(where: \.isIPv4)?.description ?? "140.82.112.3"
        var targets = GuestEgressVerifier.StrictTargets()
        if policy.verify == .strict {
            targets = .derive(facts: facts, routes: await dependencies.routes())
        }
        return GuestEgressVerifier(level: policy.verify, directGitHubAddress: direct, strictTargets: targets, expectsProxy: policy.egress != nil)
    }
}
