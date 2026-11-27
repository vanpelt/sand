import Foundation

/// Polls the enforcement components of one VM every couple of seconds from the
/// moment SSH is ready until teardown. The first failure fires `onLost` once;
/// the runner then stops and deletes the VM and deregisters the runner. It never
/// restarts anything into shared NAT.
actor NetworkWatchdog {
    struct Components: Sendable {
        var tartRun: ProcessHandle
        var tunnel: ProcessHandle?
        var proxy: EgressProxying?
        /// Check that tart's softnet child is alive (needs the tart pid).
        var checkSoftnet: Bool
        /// Returns a description of a new host-route overlap with the VM subnet, or nil.
        var routeOverlap: (@Sendable () async -> String?)?
    }

    private let components: Components
    nonisolated let interval: TimeInterval
    private let processRunner: ProcessRunning
    private let onLost: @Sendable (String) async -> Void
    private var task: Task<Void, Never>?
    private(set) var lostComponent: String?

    init(components: Components, interval: TimeInterval = 2, processRunner: ProcessRunning, onLost: @escaping @Sendable (String) async -> Void) {
        self.components = components
        self.interval = interval
        self.processRunner = processRunner
        self.onLost = onLost
    }

    func start() {
        guard task == nil else { return }
        task = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                if let lost = await self.firstFailure() {
                    await self.fire(lost)
                    return
                }
                try? await Task.sleep(nanoseconds: UInt64(max(0.05, self.interval) * 1_000_000_000))
            }
        }
    }

    func stop() {
        task?.cancel()
        task = nil
    }

    private func fire(_ component: String) async {
        guard lostComponent == nil else { return }
        lostComponent = component
        await onLost(component)
    }

    /// One poll; exposed for tests.
    func firstFailure() async -> String? {
        if await components.tartRun.hasExited() {
            return "tart"
        }
        if let tunnel = components.tunnel, await tunnel.hasExited() {
            return "tunnel"
        }
        if let proxy = components.proxy, proxy.hasFailed {
            return "proxy"
        }
        if components.checkSoftnet, let pid = components.tartRun.processIdentifier {
            // Matches both a setuid child and `sudo --non-interactive .../softnet`.
            let alive = (try? await processRunner.run(executable: "pgrep", arguments: ["-f", "-P", String(pid), "softnet"], wait: true)) != nil
            if !alive {
                return "softnet"
            }
        }
        if let routeOverlap = components.routeOverlap, let overlap = await routeOverlap() {
            return "route-overlap(\(overlap))"
        }
        return nil
    }
}
