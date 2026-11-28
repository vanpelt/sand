import Foundation

struct VMDestroyerError: Error, CustomStringConvertible {
    let name: String
    let underlying: String
    var description: String { "failed to delete VM \(name): \(underlying)" }
}

struct VMDestroyer {
    let tart: Tart
    let logger: Logger
    /// Pauses between delete attempts. A VM that cannot be deleted may still
    /// hold a denied job's token in memory, so deletion is retried and a final
    /// failure is reported to the caller instead of being swallowed.
    var deleteRetryDelays: [TimeInterval] = [1, 3]

    func destroy(name: String) async throws {
        logger.info("stop VM \(name)")
        do {
            try await tart.stop(name: name, timeout: 30)
        } catch {
            logger.warning("failed to stop VM \(name): \(String(describing: error))")
        }
        var attempt = 0
        while true {
            logger.info("delete VM \(name)")
            do {
                try await tart.delete(name: name)
                return
            } catch {
                // Already gone (or never created) counts as destroyed.
                if (try? await tart.status(name: name)) == .missing {
                    logger.info("VM \(name) is not present; nothing to delete")
                    return
                }
                guard attempt < deleteRetryDelays.count else {
                    throw VMDestroyerError(name: name, underlying: String(describing: error))
                }
                logger.warning("failed to delete VM \(name) (attempt \(attempt + 1)): \(String(describing: error)); retrying")
                try? await Task.sleep(nanoseconds: UInt64(max(0, deleteRetryDelays[attempt]) * 1_000_000_000))
                attempt += 1
            }
        }
    }
}
