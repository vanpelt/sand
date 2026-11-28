import Foundation

/// The per-VM host admission relay (`docs/broker-api.md` §7). It listens on
/// host loopback; the guest reaches it as 127.0.0.1:3129 through `ssh -R`.
/// It checks the allocation id and nonce, forwards the hints to the broker
/// with the device session, and answers the hook with the plain text `allow`
/// or `deny`. Once the nonce matched, anything but a broker allow kills the
/// VM through the controller.
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

    init(controller: AdmissionController, broker: BrokerClienting, vmName: String, timeout: TimeInterval = AdmissionTimeouts.relaySeconds, now: @escaping @Sendable () -> Date = Date.init) {
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

    /// Unauthenticated requests (wrong content type, unparsable body, wrong
    /// allocation id or nonce) get `deny` without spending the VM's single
    /// admission and without killing it: any local process can reach this
    /// loopback port, and it must not be able to destroy the VM. Only a
    /// request carrying the allocation's nonce is the hook speaking.
    func handle(_ request: HTTPRequest) async -> HTTPResponse {
        guard request.path == "/v1/admission" else { return .text(404, "deny") }
        guard request.method == "POST" else { return .text(405, "deny") }
        let contentType = (request.header("content-type") ?? "").split(separator: ";").first?
            .trimmingCharacters(in: .whitespaces).lowercased()
        guard contentType == "application/json" else {
            await controller.noteRejected("content_type")
            return .text(415, "deny")
        }
        let allocation = controller.allocation
        guard request.body.count <= Self.maxBodyBytes,
              let body = try? BrokerJSON.decoder().decode(GuestRequest.self, from: request.body) else {
            await controller.noteRejected(DenyReason.hintInvalid.rawValue)
            return .text(400, "deny")
        }
        guard constantTimeEquals(body.allocationId, allocation.allocationId), constantTimeEquals(body.nonce, allocation.nonce) else {
            await controller.noteRejected(DenyReason.nonceMismatch.rawValue)
            return .text(403, "deny")
        }
        let first = lock.withLock { () -> Bool in
            defer { used = true }
            return !used
        }
        guard first else {
            // One admission per VM; a second hook call never gets an allow.
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

    /// Records the kill and starts the VM teardown without waiting for it, so
    /// the hook gets `deny` (and kills the runner itself) at once instead of
    /// after the host has finished destroying the VM.
    private func deny(_ reasons: [String], cause: String, job: AdmissionJob?, hints: AdmissionHints? = nil) async {
        await controller.kill(.init(
            type: cause, reasons: reasons.isEmpty ? ["deny"] : reasons,
            jobId: job?.id, runId: job?.runId ?? hints?.runId, runAttempt: job?.runAttempt ?? hints?.runAttempt,
            byVerifier: false
        ), waitForAction: false)
    }
}

struct RelayTimeout: Error {}

/// Runs `operation` with a deadline. On timeout the operation is cancelled
/// but **not awaited**: a call that ignores cancellation (a Keychain signing
/// blocked on an approval prompt, for example) cannot hold the caller past
/// the deadline, as a task group would.
func withTimeout<T: Sendable>(_ seconds: TimeInterval, _ operation: @escaping @Sendable () async throws -> T) async -> Result<T, Error> {
    let once = TimeoutResumeOnce<Result<T, Error>>()
    return await withTaskCancellationHandler {
        await withCheckedContinuation { (continuation: CheckedContinuation<Result<T, Error>, Never>) in
            once.set(continuation)
            let work = Task {
                let result: Result<T, Error>
                do { result = .success(try await operation()) } catch { result = .failure(error) }
                once.resume(result)
            }
            let timer = Task {
                try? await Task.sleep(nanoseconds: UInt64(max(0, seconds) * 1_000_000_000))
                once.resume(.failure(RelayTimeout()))
            }
            // Whichever side won, stop the other (a finished task ignores cancel).
            once.onResume { timer.cancel(); work.cancel() }
        }
    } onCancel: {
        once.resume(.failure(CancellationError()))
    }
}

/// Resumes a continuation at most once, from whichever side finishes first.
final class TimeoutResumeOnce<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Value, Never>?
    private var pending: Value?
    private var done = false
    private var hooks: [@Sendable () -> Void] = []

    func set(_ continuation: CheckedContinuation<Value, Never>) {
        let value: Value? = lock.withLock {
            if let pending { self.pending = nil; return pending }
            self.continuation = continuation
            return nil
        }
        if let value { continuation.resume(returning: value) }
    }

    /// True when this call delivered the value.
    @discardableResult
    func resume(_ value: Value) -> Bool {
        let (continuation, hooks, delivered): (CheckedContinuation<Value, Never>?, [@Sendable () -> Void], Bool) = lock.withLock {
            guard !done else { return (nil, [], false) }
            done = true
            let c = self.continuation
            self.continuation = nil
            if c == nil { pending = value }
            let h = self.hooks
            self.hooks = []
            return (c, h, true)
        }
        continuation?.resume(returning: value)
        hooks.forEach { $0() }
        return delivered
    }

    func onResume(_ hook: @escaping @Sendable () -> Void) {
        let runNow: Bool = lock.withLock {
            if done { return true }
            hooks.append(hook)
            return false
        }
        if runNow { hook() }
    }
}
