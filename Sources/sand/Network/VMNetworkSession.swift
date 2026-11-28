import Foundation

enum NetworkEnforcementError: Error, CustomStringConvertible {
    case preflightFailed([PreflightCheck])
    case subnetOverlap(String)
    case tunnelFailed(String)
    case verificationFailed([GuestEgressVerifier.ProbeResult])
    case hostListenersDenied([HostListener])
    /// tart (or its network backend) died before the VM was reachable.
    case backendFailed(reason: String, detail: String)
    /// The CA bundle for a trusted inspection CA could not be built in the guest.
    case inspectionTrustFailed(String)
    /// An enforcement component died while a job ran under `stopAfter`: the
    /// interrupted job cannot be retried, so `sand run` exits 78.
    case enforcementLost(component: String)
    /// Too many consecutive enforcement failures: `sand run` exits 78.
    case gaveUp(attempts: Int, last: String)

    /// Failures that end `sand run` with exit 78 instead of another retry.
    var isFatal: Bool {
        switch self {
        case .gaveUp, .enforcementLost: return true
        default: return false
        }
    }

    var description: String {
        switch self {
        case let .hostListenersDenied(listeners):
            return "host services are reachable from the VM on the host-only bridge (hostListeners: deny): " + listeners.map(\.description).joined(separator: ", ")
                + "\nStop or rebind them to 127.0.0.1, list accepted ones in vm.run.network.acceptedHostListeners, or use backend: softnet."
        case let .backendFailed(reason, detail):
            return "network enforcement backend failed (\(reason)): \(detail)"
        case let .inspectionTrustFailed(detail):
            return "could not trust the host TLS-inspection CA in the guest: \(detail)"
        case let .enforcementLost(component):
            return "network enforcement was lost while the job ran (\(component)); the VM was stopped and deleted and the job is not retried under stopAfter"
        case let .gaveUp(attempts, last):
            return "network enforcement failed \(attempts) time(s) in a row; giving up (sand never falls back to shared networking). Last failure: \(last)"
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
    /// Host sockets reachable on the given bridge addresses (hostOnly).
    var hostListeners: @Sendable ([IPAddress]) async -> HostListenerInspector.Result = { _ in .init(listeners: [], method: "none") }
    /// The host's addresses on the bridge that carries a VM IP.
    var bridgeAddresses: @Sendable (String) -> [IPAddress] = { _ in [] }
    /// Intercepting host CAs detected at startup, installed under `tlsInspection: trustHostCA`.
    var inspectionCAs: [InspectionCA] = []
    /// The backend `backend: auto` resolved to (and was preflighted with) at
    /// startup. Every later VM uses it: a lost softnet privilege then fails the
    /// per-VM preflight instead of silently downgrading to hostOnly.
    var pinnedBackend: EnforcementBackend?
    /// The host's DNS servers (hostOnly adversarial verifier targets).
    var hostResolvers: @Sendable () async -> [String] = { [] }
    /// Host IP forwarding (hostOnly): checked per VM and by the watchdog.
    var ipForwarding: @Sendable () -> IPForwardingState = { IPForwardingState.current() }

    static func live(processRunner: ProcessRunning, audit: NetworkAudit) -> RunnerNetworkDependencies {
        var dependencies = RunnerNetworkDependencies(
            preflight: NetworkPreflight(processRunner: processRunner),
            resolver: SystemHostResolver(),
            hostFacts: { HostFacts.current() },
            routes: { await RouteInspector.current(processRunner: processRunner) },
            makeProxy: { policy, guardrail, audit in
                EgressProxy(policy: policy, destinationGuard: guardrail, resolver: SystemHostResolver(), audit: audit)
            },
            audit: audit
        )
        dependencies.hostListeners = { addresses in await HostListenerInspector(processRunner: processRunner).inspect(bridgeAddresses: addresses) }
        dependencies.bridgeAddresses = { HostListenerInspector.bridgeAddresses(forVMIP: $0) }
        dependencies.hostResolvers = { await HostDNSServers.current(processRunner: processRunner) }
        return dependencies
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

    /// The intercepting CAs this VM's guest must trust (empty unless `tlsInspection: trustHostCA`).
    var inspectionCAs: [InspectionCA] {
        guard policy.egress != nil, policy.options.tlsInspection == .trustHostCA else { return [] }
        return dependencies.inspectionCAs
    }

    var guestEnv: GuestEgressEnv? {
        guard policy.egress != nil else { return nil }
        return inspectionCAs.isEmpty ? .standard : GuestEgressEnv.standard.trustingInspectionCA()
    }

    /// Host routes (other than vmnet bridges) that overlap the VM's /29, or
    /// steered GitHub fronts that would be shadowed by it.
    func subnetConflict(vmIP: String) async -> String? {
        guard policy.isIsolated, let subnet = RouteInspector.vmSubnet(for: vmIP) else { return nil }
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
        if policy.isHostOnly {
            try checkIPForwarding()
        }
        if let egress = policy.egress {
            let routes = await dependencies.routes()
            let steeredInterfaces = await DestinationGuard.learnSteeredInterfaces(names: egress.steeredNames, resolver: dependencies.resolver, routes: routes)
            audit.emit("network.steering.learned", ["interfaces": steeredInterfaces.sorted().joined(separator: ","), "policy_hash": policy.policyHash])
            let guardrail = DestinationGuard(hostFacts: facts, routes: routes, steeredInterfaces: steeredInterfaces)
            let proxy = dependencies.makeProxy(egress, guardrail, audit)
            lock.withLock { self.proxy = proxy }
            let port = try await proxy.start(port: 0)
            logger.info("egress proxy for VM listening on 127.0.0.1:\(port)")
            let tunnel = try ssh.startReverseTunnel(remotePort: NetworkPolicy.guestProxyPort, localPort: port)
            lock.withLock { self.tunnel = tunnel }
            try await waitForTunnel(ssh: ssh, tunnel: tunnel)
        }
        let listeners = try await checkHostListeners(vmIP: vmIP)
        guard policy.verify != .off else {
            audit.emit("network.guest.verified", level: .warning, ["verify": "off", "backend": policy.backend?.rawValue ?? "none", "policy_hash": policy.policyHash])
            return
        }
        let bridge = policy.isHostOnly ? dependencies.bridgeAddresses(vmIP) : []
        let gateway = bridge.first(where: \.isIPv4)?.description
        let gatewayV6 = bridge.first(where: \.isLinkLocalV6).map { $0.withoutEmbeddedScope.description }
        let verifier = await makeVerifier(facts: facts, hostServicePorts: listeners.filter { $0.proto == .tcp }.map(\.port), gateway: gateway, gatewayV6: gatewayV6)
        let output = (try await ssh.exec(command: verifier.script))?.stdout ?? ""
        let results = verifier.evaluate(output)
        let failed = results.filter { !$0.passed }
        guard failed.isEmpty else {
            audit.emit("network.guest.verify", level: .error, [
                "result": "failed",
                "failed": failed.map { "\($0.id):\($0.outcome)" }.joined(separator: ","),
                "backend": policy.backend?.rawValue ?? "none",
                "policy_hash": policy.policyHash
            ])
            throw NetworkEnforcementError.verificationFailed(results)
        }
        var fields = [
            "verify": policy.verify.rawValue,
            "probes": String(results.count),
            "backend": policy.backend?.rawValue ?? "none",
            "policy_hash": policy.policyHash
        ]
        let reached = verifier.reachableHostServices(results)
        if !reached.isEmpty {
            fields["host_services_reachable"] = reached.joined(separator: ",")
        }
        let routedOpen = verifier.routedReachable(results)
        if !routedOpen.isEmpty {
            // Only passes under ipForwarding: accept.
            fields["routed_reachable"] = routedOpen.map { id in results.first { $0.id == id }?.detail ?? id }.joined(separator: "; ")
            logger.warning("hostOnly: with a guest route via the host, the VM reached: \(fields["routed_reachable"] ?? "") (accepted by ipForwarding: accept)")
        }
        if verifier.routed != nil {
            fields["routed_probes"] = String(results.filter { $0.id.hasPrefix("R") }.count)
        }
        audit.emit("network.guest.verified", level: reached.isEmpty && routedOpen.isEmpty ? .info : .warning, fields)
    }

    /// hostOnly: forwarding may have been turned on since the per-VM preflight.
    /// Under `ipForwarding: accept` the exposure is logged and audited per VM.
    private func checkIPForwarding() throws {
        let state = dependencies.ipForwarding()
        guard !state.isOff else { return }
        let fields = ["state": state.summary, "policy": policy.options.ipForwarding.rawValue, "policy_hash": policy.policyHash]
        guard policy.options.ipForwarding == .accept else {
            audit.emit("network.host.forwarding", level: .error, fields.merging(["result": "denied"]) { $1 })
            throw NetworkEnforcementError.preflightFailed([PreflightCheck(
                "P11 host IP forwarding", .failed,
                "host IP forwarding turned on (\(state.summary))", remediation: NetworkPreflight.ipForwardingRemediation
            )])
        }
        audit.emit("network.host.forwarding", level: .warning, fields.merging(["result": "accepted", "risk": "guest root can route through the host"]) { $1 })
        logger.warning("hostOnly: host IP forwarding is on (\(state.summary)) and accepted (ipForwarding: accept): a job with root in the guest can route through the host to anything the host forwards to with a return path")
    }

    /// hostOnly only: host sockets a guest can reach (bound to all interfaces,
    /// to the bridge address, or to any other non-loopback host address, which a
    /// guest reaches by routing via the bridge). Loopback sockets, including this
    /// VM's own egress proxy, are never reachable and never reported. Reported
    /// under `hostListeners: warn`; `deny` refuses the VM.
    private func checkHostListeners(vmIP: String) async throws -> [HostListener] {
        guard policy.isHostOnly else { return [] }
        let bridge = dependencies.bridgeAddresses(vmIP)
        let reachable = HostListenerInspector.reachableAddresses(bridge: bridge, host: dependencies.hostFacts().interfaceAddresses)
        let inspected = await dependencies.hostListeners(reachable)
        let report = HostListenerReport(
            reachable: inspected.listeners,
            policy: policy.options.hostListeners,
            accepted: policy.options.acceptedHostListeners
        )
        var fields = [
            "policy": report.policy.rawValue,
            "method": inspected.method,
            "count": String(report.reachable.count),
            "listeners": report.reachable.prefix(40).map(\.description).joined(separator: ","),
            "bridge": bridge.filter(\.isIPv4).map(\.description).joined(separator: ","),
            "addresses": String(reachable.count),
            "policy_hash": policy.policyHash
        ]
        if !report.accepted.isEmpty {
            fields["accepted"] = report.accepted.map(\.key).joined(separator: ",")
        }
        if report.failed {
            audit.emit("network.host.listeners", level: .error, fields.merging(["result": "denied"]) { $1 })
            throw NetworkEnforcementError.hostListenersDenied(report.reachable)
        }
        audit.emit("network.host.listeners", level: report.reachable.isEmpty ? .info : .warning, fields)
        if !report.reachable.isEmpty {
            logger.warning("hostOnly: \(report.reachable.count) host service(s) reachable from the VM on the host-only bridge: \(report.reachable.prefix(12).map(\.description).joined(separator: ", "))\(report.reachable.count > 12 ? ", ..." : ""); set vm.run.network.hostListeners: deny to refuse, or use backend: softnet")
        }
        return report.reachable + report.accepted
    }

    /// Starts polling enforcement; `onLost` fires at most once and returns false
    /// when the loss is expected (the VM is already being torn down), in which
    /// case nothing is audited.
    func startWatchdog(tartRun: ProcessHandle, vmIP: String, onLost: @escaping @Sendable (String) async -> Bool) async {
        let subnet = RouteInspector.vmSubnet(for: vmIP)
        let routes = dependencies.routes
        var overlap: (@Sendable () async -> String?)?
        if policy.isIsolated, let subnet {
            overlap = {
                guard let route = await routes().overlaps(subnet).first else { return nil }
                let destination = route.destination.map { $0.description } ?? "default"
                return "\(destination)@\(route.interface)"
            }
        }
        let (proxy, tunnel) = lock.withLock { (self.proxy, self.tunnel) }
        let backendName = policy.backend?.rawValue ?? "none"
        var forwarding: (@Sendable () -> String?)?
        if policy.isHostOnly, policy.options.ipForwarding == .deny {
            let read = dependencies.ipForwarding
            forwarding = {
                let state = read()
                return state.isOff ? nil : state.summary
            }
        }
        let watchdog = NetworkWatchdog(
            components: .init(tartRun: tartRun, tunnel: tunnel, proxy: proxy, checkSoftnet: policy.usesSoftnet, routeOverlap: overlap, ipForwarding: forwarding),
            interval: dependencies.watchdogInterval,
            processRunner: processRunner
        ) { [audit] component in
            if await onLost(component) {
                audit.emit("network.enforcement.lost", level: .error, ["component": component, "backend": backendName])
            }
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
            audit.emit("network.session.summary", Self.summaryFields(summary))
        }
    }

    /// `network.session.summary` fields. `denied` counts every deny;
    /// `top_denied` lists only the ones that were not background noise, which
    /// `quiet_denied` / `top_quiet` count instead.
    static func summaryFields(_ summary: EgressProxy.Counters) -> [String: String] {
        func top(_ hosts: [String: Int]) -> String {
            hosts.sorted { ($0.value, $1.key) > ($1.value, $0.key) }.prefix(5).map { "\($0.key):\($0.value)" }.joined(separator: ",")
        }
        var fields = [
            "allowed": String(summary.allowed),
            "denied": String(summary.denied),
            "bytes_up": String(summary.bytesUp),
            "bytes_down": String(summary.bytesDown),
            "top_denied": top(summary.deniedByHost)
        ]
        if summary.quietDenied > 0 {
            fields["quiet_denied"] = String(summary.quietDenied)
            fields["top_quiet"] = top(summary.quietByHost)
        }
        return fields
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

    private func makeVerifier(facts: HostFacts, hostServicePorts: [Int], gateway: String?, gatewayV6: String?) async -> GuestEgressVerifier {
        let github = (try? await dependencies.resolver.resolve("github.com")) ?? []
        let direct = github.first(where: \.isIPv4)?.description ?? "140.82.112.3"
        var targets = GuestEgressVerifier.StrictTargets()
        var routed: GuestEgressVerifier.RoutedTargets?
        if policy.verify == .strict || policy.isHostOnly {
            let derived = GuestEgressVerifier.StrictTargets.derive(facts: facts, routes: await dependencies.routes())
            if policy.verify == .strict {
                targets = derived
            }
            if policy.isHostOnly {
                routed = GuestEgressVerifier.RoutedTargets(
                    hostGatewayV6: gatewayV6,
                    resolvers: await dependencies.hostResolvers(),
                    tunnelTargets: derived.tunnelTargets,
                    forwardingAccepted: policy.options.ipForwarding == .accept
                )
            }
        }
        return GuestEgressVerifier(
            level: policy.verify, directGitHubAddress: direct, strictTargets: targets, expectsProxy: policy.egress != nil,
            backend: policy.backend ?? .softnet,
            hostListenerPolicy: policy.options.hostListeners,
            acceptedHostListeners: policy.options.acceptedHostListeners,
            hostServicePorts: Array(Set(hostServicePorts)).sorted(),
            hostGateway: gateway,
            routed: routed
        )
    }
}
