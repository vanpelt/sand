import Foundation

actor VMShutdownCoordinator {
    private var activeName: String?
    private var cleanupTask: Task<Void, Never>?
    private var deregistration: (@Sendable (_ reason: String) async -> Void)?
    private let destroyer: VMDestroyer
    private let logger: Logger

    init(destroyer: VMDestroyer, logger: Logger) {
        self.destroyer = destroyer
        self.logger = logger
    }

    func activate(name: String) {
        activeName = name
        cleanupTask = nil
        deregistration = nil
        logger.info("shutdown coordinator activated for VM \(name)")
    }

    /// True once cleanup started or nothing is active (used to ignore expected teardown signals).
    func isCleaningUp() -> Bool {
        cleanupTask != nil || activeName == nil
    }

    func setDeregistration(_ action: @escaping @Sendable () async -> Void) {
        deregistration = { _ in await action() }
    }

    /// Like `setDeregistration`, but the action learns the cleanup reason
    /// (for example "signal shutdown"), which broker mode reports on release.
    func setDeregistration(withReason action: @escaping @Sendable (_ reason: String) async -> Void) {
        deregistration = action
    }

    func cleanup(reason: String? = nil) async {
        let reasonLabel = reason ?? "unspecified"
        if let cleanupTask {
            logger.debug("cleanup already started; waiting for it (reason: \(reasonLabel))")
            await cleanupTask.value
            return
        }
        guard let name = activeName else {
            logger.debug("cleanup skipped: no active VM (reason: \(reasonLabel))")
            return
        }
        logger.info("cleanup start for VM \(name) (reason: \(reasonLabel))")
        let task = Task { [destroyer, deregistration] in
            _ = try? await destroyer.destroy(name: name)
            await deregistration?(reasonLabel)
        }
        cleanupTask = task
        await task.value
        logger.info("cleanup complete for VM \(name)")
        activeName = nil
    }
}
