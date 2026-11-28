import Foundation

/// Errors never carry response bodies, tokens or the JIT config: only the HTTP
/// status, the broker's error code and its retry hint.
enum BrokerClientError: Error, Equatable, CustomStringConvertible {
    case http(status: Int, code: String?, retryAfterSeconds: Int?)
    case invalidResponse
    case transport(String)

    var description: String {
        switch self {
        case let .http(status, code, retry):
            return "broker HTTP \(status)\(code.map { " \($0)" } ?? "")\(retry.map { " (retry after \($0)s)" } ?? "")"
        case .invalidResponse:
            return "broker returned an invalid response"
        case let .transport(detail):
            return "broker unreachable: \(detail)"
        }
    }

    var code: String? {
        if case let .http(_, code, _) = self { return code }
        return nil
    }

    var retryAfterSeconds: Int? {
        if case let .http(_, _, retry) = self { return retry }
        return nil
    }

    /// `409 no_eligible_demand` and `429`: wait and ask again, keeping the VM.
    var isRetryLater: Bool {
        guard case let .http(status, code, _) = self else { return false }
        return status == 429 || (status == 409 && code == "no_eligible_demand")
    }
}

/// The device-side broker API used by the runner, relay and verifier.
protocol BrokerClienting: Sendable {
    func allocate(_ request: AllocationRequest) async throws -> Allocation
    func status(allocationId: String) async throws -> AllocationStatus
    func admit(allocationId: String, _ request: AdmissionRequest) async throws -> AdmissionDecision
    func release(allocationId: String, _ request: ReleaseRequest) async throws -> ReleaseResult
    func audit(_ events: [AuditEvent]) async throws
}

/// HTTPS client for the Sand broker (`docs/broker-api.md`). Acquires and
/// refreshes a device session by challenge/response, adds `Sand-Request-Id` to
/// every request and a per-call `Idempotency-Key` to mutating POSTs (reused
/// across that call's retries).
actor BrokerClient: BrokerClienting {
    typealias Sleeper = @Sendable (TimeInterval) async throws -> Void

    let baseURL: URL
    let deviceId: String
    private let key: DeviceKey
    private let session: URLSessionProtocol
    private let now: @Sendable () -> Date
    private let sleep: Sleeper
    private let transportRetries: Int
    private var current: BrokerSession?
    private(set) var sessionsAcquired = 0

    init(
        baseURL: URL,
        deviceId: String,
        key: DeviceKey,
        session: URLSessionProtocol = URLSession(configuration: .ephemeral),
        now: @escaping @Sendable () -> Date = Date.init,
        sleep: @escaping Sleeper = { try await Task.sleep(nanoseconds: UInt64(max(0, $0) * 1_000_000_000)) },
        transportRetries: Int = 2
    ) {
        self.baseURL = baseURL
        self.deviceId = deviceId
        self.key = key
        self.session = session
        self.now = now
        self.sleep = sleep
        self.transportRetries = transportRetries
    }

    var owner: BrokerOwner? { current?.owner }

    // MARK: API

    func health() async throws -> BrokerHealth {
        try decode(try await send(method: "GET", path: "/v1/health", body: nil, authenticated: false, idempotencyKey: nil))
    }

    func allocate(_ request: AllocationRequest) async throws -> Allocation {
        try decode(try await call("POST", "/v1/allocations", body: request, mutating: true))
    }

    func status(allocationId: String) async throws -> AllocationStatus {
        try decode(try await call("GET", "/v1/allocations/\(try Self.checkedId(allocationId))", body: Optional<String>.none, mutating: false))
    }

    func admit(allocationId: String, _ request: AdmissionRequest) async throws -> AdmissionDecision {
        // Admissions are idempotent on (allocation, run, attempt) server side; no key needed.
        try decode(try await call("POST", "/v1/allocations/\(try Self.checkedId(allocationId))/admissions", body: request, mutating: false, retryTransport: false))
    }

    func release(allocationId: String, _ request: ReleaseRequest) async throws -> ReleaseResult {
        try decode(try await call("POST", "/v1/allocations/\(try Self.checkedId(allocationId))/release", body: request, mutating: true))
    }

    func audit(_ events: [AuditEvent]) async throws {
        for start in stride(from: 0, to: events.count, by: 100) {
            let batch = AuditBatch(events: Array(events[start..<min(events.count, start + 100)]))
            let _: AuditAccepted = try decode(try await call("POST", "/v1/audit-events", body: batch, mutating: true))
        }
    }

    // MARK: Sessions

    func ensureSession() async throws -> String {
        if let current, current.expiresAt.timeIntervalSince(now()) > 60 {
            return current.sessionToken
        }
        let challenge: BrokerChallenge = try decode(try await send(
            method: "POST", path: "/v1/device/challenges",
            body: try BrokerJSON.encoder().encode(ChallengeRequest(deviceId: deviceId)),
            authenticated: false, idempotencyKey: nil
        ))
        let signature = try key.sign(deviceId: deviceId, challengeId: challenge.challengeId, challenge: challenge.challenge)
        let request = SessionRequest(deviceId: deviceId, keyId: key.keyId, challengeId: challenge.challengeId, signature: signature)
        let session: BrokerSession = try decode(try await send(
            method: "POST", path: "/v1/device/sessions",
            body: try BrokerJSON.encoder().encode(request),
            authenticated: false, idempotencyKey: nil
        ))
        current = session
        sessionsAcquired += 1
        return session.sessionToken
    }

    // MARK: Transport

    private func call<Body: Encodable>(_ method: String, _ path: String, body: Body?, mutating: Bool, retryTransport: Bool = true) async throws -> Data {
        let encoded = try body.map { try BrokerJSON.encoder().encode($0) }
        let idempotencyKey = mutating ? UUID().uuidString.lowercased() : nil
        var reauthenticated = false
        var attempt = 0
        while true {
            do {
                return try await send(method: method, path: path, body: encoded, authenticated: true, idempotencyKey: idempotencyKey)
            } catch let error as BrokerClientError {
                if case .http(401, _, _) = error, !reauthenticated {
                    reauthenticated = true
                    current = nil
                    continue
                }
                let retryable: Bool
                switch error {
                case .transport: retryable = retryTransport
                case let .http(status, _, _): retryable = retryTransport && (status == 502 || status == 503)
                case .invalidResponse: retryable = false
                }
                guard retryable, attempt < transportRetries else { throw error }
                attempt += 1
                try await sleep(Double(attempt))
            }
        }
    }

    private func send(method: String, path: String, body: Data?, authenticated: Bool, idempotencyKey: String?) async throws -> Data {
        var request = URLRequest(url: baseURL.appendingPathComponent(String(path.dropFirst())))
        request.httpMethod = method
        request.timeoutInterval = 30
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("sand/\(SandVersion.current)", forHTTPHeaderField: "User-Agent")
        request.setValue(UUID().uuidString.lowercased(), forHTTPHeaderField: "Sand-Request-Id")
        if let idempotencyKey {
            request.setValue(idempotencyKey, forHTTPHeaderField: "Idempotency-Key")
        }
        if authenticated {
            request.setValue("Bearer \(try await ensureSession())", forHTTPHeaderField: "Authorization")
        }
        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = body
        }
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as URLError {
            throw BrokerClientError.transport("URLError \(error.code.rawValue)")
        } catch {
            throw BrokerClientError.transport(String(describing: type(of: error)))
        }
        guard let http = response as? HTTPURLResponse else {
            throw BrokerClientError.invalidResponse
        }
        guard (200...299).contains(http.statusCode) else {
            let detail = try? BrokerJSON.decoder().decode(BrokerErrorBody.self, from: data).error
            let header = http.value(forHTTPHeaderField: "Retry-After").flatMap(Int.init)
            throw BrokerClientError.http(status: http.statusCode, code: detail?.code, retryAfterSeconds: detail?.retryAfterSeconds ?? header)
        }
        return data
    }

    private func decode<T: Decodable>(_ data: Data) throws -> T {
        do {
            return try BrokerJSON.decoder().decode(T.self, from: data)
        } catch {
            throw BrokerClientError.invalidResponse
        }
    }

    static func checkedId(_ id: String) throws -> String {
        guard BrokerID.matches(id, prefix: "alc") else { throw BrokerClientError.invalidResponse }
        return id
    }
}
