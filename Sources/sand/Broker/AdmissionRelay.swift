import Foundation

/// The per-VM host admission relay (`docs/broker-api.md` §7). It listens on
/// host loopback; the guest reaches it as 127.0.0.1:3129 through `ssh -R`.
/// It checks the allocation id and nonce, forwards the hints to the broker
/// with the device session, and answers the hook with the plain text `allow`
/// or `deny`. Anything but a broker allow kills the VM through the controller.
final class AdmissionRelay: @unchecked Sendable {
    struct GuestRequest: Decodable {
        let allocationId: String
        let nonce: String
        let hints: AdmissionHints
    }

    static let maxBodyBytes = 4096

    private let controller: AdmissionController
    private let broker: BrokerClienting
    private let vmName: String
    private let timeout: TimeInterval
    private let now: @Sendable () -> Date
    private let lock = NSLock()
    private var used = false
    private var server: LoopbackHTTPServer?
    private(set) var brokerCalls = 0

    init(controller: AdmissionController, broker: BrokerClienting, vmName: String, timeout: TimeInterval = 45, now: @escaping @Sendable () -> Date = Date.init) {
        self.controller = controller
        self.broker = broker
        self.vmName = vmName
        self.timeout = timeout
        self.now = now
    }

    /// Starts on host 127.0.0.1 with an ephemeral port and returns it.
    func start() async throws -> UInt16 {
        let server = LoopbackHTTPServer(maxBodyBytes: 16_384) { [weak self] request in
            guard let self else { return .text(503, "deny") }
            return await self.handle(request)
        }
        lock.withLock { self.server = server }
        return try await server.start()
    }

    func stop() {
        lock.withLock { server }?.stop()
    }

    func handle(_ request: HTTPRequest) async -> HTTPResponse {
        guard request.path == "/v1/admission" else { return .text(404, "deny") }
        guard request.method == "POST" else { return .text(405, "deny") }
        let first = lock.withLock { () -> Bool in
            defer { used = true }
            return !used
        }
        guard first else {
            // One admission per VM; a second hook call never gets an allow.
            return .text(200, "deny")
        }
        let allocation = controller.allocation
        guard request.body.count <= Self.maxBodyBytes,
              let body = try? BrokerJSON.decoder().decode(GuestRequest.self, from: request.body) else {
            await deny(["hint_invalid"], cause: "admission.relay_error", job: nil)
            return .text(200, "deny")
        }
        guard constantTimeEquals(body.allocationId, allocation.allocationId), constantTimeEquals(body.nonce, allocation.nonce) else {
            await deny([DenyReason.nonceMismatch.rawValue], cause: "admission.denied", job: nil)
            return .text(200, "deny")
        }
        guard body.hints.isWellFormed else {
            await deny([DenyReason.hintInvalid.rawValue], cause: "admission.denied", job: nil)
            return .text(200, "deny")
        }
        let admission = AdmissionRequest(nonce: allocation.nonce, hints: body.hints, oidcToken: nil, relay: .init(receivedAt: now(), vmName: vmName))
        lock.withLock { brokerCalls += 1 }
        let result = await withTimeout(timeout) { [broker] in
            try await broker.admit(allocationId: allocation.allocationId, admission)
        }
        switch result {
        case let .success(decision) where decision.decision == .allow && decision.job != nil && decision.reasons.isEmpty:
            await controller.recordAllow(decision)
            // Re-check: the verifier may have killed the VM while the broker decided.
            return await controller.wasKilled ? .text(200, "deny") : .text(200, "allow")
        case let .success(decision):
            await deny(decision.reasons.map(\.rawValue), cause: "admission.denied", job: decision.job, hints: body.hints)
        case let .failure(error):
            let reason: String
            if let error = error as? BrokerClientError { reason = "relay_\(error.code ?? "error")" } else { reason = "relay_timeout" }
            await deny([reason], cause: "admission.relay_error", job: nil, hints: body.hints)
        }
        return .text(200, "deny")
    }

    private func deny(_ reasons: [String], cause: String, job: AdmissionJob?, hints: AdmissionHints? = nil) async {
        await controller.kill(.init(
            type: cause, reasons: reasons.isEmpty ? ["deny"] : reasons,
            jobId: job?.id, runId: job?.runId ?? hints?.runId, runAttempt: job?.runAttempt ?? hints?.runAttempt,
            byVerifier: false
        ))
    }
}

struct RelayTimeout: Error {}

/// Runs `operation` with a deadline; the loser is cancelled.
func withTimeout<T: Sendable>(_ seconds: TimeInterval, _ operation: @escaping @Sendable () async throws -> T) async -> Result<T, Error> {
    await withTaskGroup(of: Result<T, Error>?.self) { group in
        group.addTask {
            do { return .success(try await operation()) } catch { return .failure(error) }
        }
        group.addTask {
            try? await Task.sleep(nanoseconds: UInt64(max(0, seconds) * 1_000_000_000))
            return Task.isCancelled ? nil : .failure(RelayTimeout())
        }
        var outcome: Result<T, Error> = .failure(RelayTimeout())
        while let next = await group.next() {
            if let next {
                outcome = next
                break
            }
        }
        group.cancelAll()
        return outcome
    }
}
