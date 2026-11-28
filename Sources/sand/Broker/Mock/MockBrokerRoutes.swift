import CryptoKit
import Foundation

/// HTTP routing for the mock broker: authentication, request ids,
/// idempotency keys and error bodies around `MockBrokerStore`.
struct MockBrokerRoutes: Sendable {
    let store: MockBrokerStore

    func handle(_ request: HTTPRequest) async -> HTTPResponse {
        let requestId = request.header("Sand-Request-Id").flatMap(UUID.init(uuidString:))?.uuidString.lowercased() ?? UUID().uuidString.lowercased()
        var response: HTTPResponse
        do {
            response = try await route(request)
        } catch let error as BrokerAPIError {
            response = Self.error(error, requestId: requestId)
        } catch is DecodingError {
            response = Self.error(.invalid("malformed JSON body"), requestId: requestId)
        } catch {
            response = Self.error(.init(status: 503, code: "unavailable", message: "internal error"), requestId: requestId)
        }
        response.headers["Sand-Request-Id"] = requestId
        return response
    }

    private func route(_ request: HTTPRequest) async throws -> HTTPResponse {
        let parts = request.path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        let method = request.method
        let path = parts.joined(separator: "/")
        let allocationId: String? = parts.count >= 3 && parts[0] == "v1" && parts[1] == "allocations" ? parts[2] : nil
        let tail = parts.count > 3 ? parts[3...].joined(separator: "/") : ""
        switch (method, path) {
        case ("GET", "v1/health"):
            return .json(200, BrokerHealth(status: "ok", version: SandVersion.current, policyVersion: store.config.policy.version))
        case ("POST", "v1/device/challenges"):
            let body: ChallengeRequest = try decode(request)
            return .json(201, try await store.createChallenge(deviceId: body.deviceId))
        case ("POST", "v1/device/sessions"):
            let body: SessionRequest = try decode(request)
            return .json(201, try await store.createSession(body))
        case ("POST", "v1/allocations"):
            let device = try await authenticate(request)
            let key = try idempotencyKey(request)
            let body: AllocationRequest = try decode(request)
            let (status, allocation) = try await store.allocate(deviceId: device, request: body, idempotencyKey: key, requestHash: Self.hash(request.body))
            return .json(status, allocation)
        case ("POST", "v1/audit-events"):
            let device = try await authenticate(request)
            _ = try idempotencyKey(request)
            let body: AuditBatch = try decode(request)
            return .json(202, AuditAccepted(accepted: try await store.acceptAudit(deviceId: device, events: body.events)))
        default:
            break
        }
        guard let allocationId, parts.count <= 4 else {
            return Self.error(.init(status: 404, code: "not_found", message: "no such endpoint"), requestId: nil)
        }
        switch (method, tail) {
        case ("GET", ""):
            let device = try await authenticate(request)
            return .json(200, try await store.status(deviceId: device, allocationId: try checked(allocationId)))
        case ("POST", "admissions"):
            let device = try await authenticate(request)
            let body: AdmissionRequest = try decode(request)
            return .json(200, try await store.admit(deviceId: device, allocationId: try checked(allocationId), request: body))
        case ("POST", "release"):
            let device = try await authenticate(request)
            _ = try idempotencyKey(request)
            let body: ReleaseRequest = try decode(request)
            return .json(202, try await store.release(deviceId: device, allocationId: try checked(allocationId), request: body))
        default:
            return Self.error(.init(status: 404, code: "not_found", message: "no such endpoint"), requestId: nil)
        }
    }

    private func authenticate(_ request: HTTPRequest) async throws -> String {
        guard let header = request.header("Authorization"), header.hasPrefix("Bearer ") else {
            throw BrokerAPIError(status: 401, code: "session_expired", message: "missing bearer session")
        }
        return try await store.authenticate(token: String(header.dropFirst("Bearer ".count)))
    }

    private func idempotencyKey(_ request: HTTPRequest) throws -> String {
        guard let value = request.header("Idempotency-Key"), let uuid = UUID(uuidString: value) else {
            throw BrokerAPIError.invalid("Idempotency-Key (UUID) is required")
        }
        return uuid.uuidString.lowercased()
    }

    private func checked(_ id: String) throws -> String {
        guard BrokerID.matches(id, prefix: "alc") else { throw BrokerAPIError.notFound() }
        return id
    }

    private func decode<T: Decodable>(_ request: HTTPRequest) throws -> T {
        guard request.header("Content-Type")?.lowercased().hasPrefix("application/json") == true else {
            throw BrokerAPIError.invalid("Content-Type must be application/json")
        }
        return try BrokerJSON.decoder().decode(T.self, from: request.body)
    }

    static func hash(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func error(_ error: BrokerAPIError, requestId: String?) -> HTTPResponse {
        var headers: [String: String] = [:]
        if let retry = error.retryAfterSeconds {
            headers["Retry-After"] = String(retry)
        }
        return .json(error.status, BrokerErrorBody(
            error: .init(code: error.code, message: error.message, retryAfterSeconds: error.retryAfterSeconds),
            requestId: requestId
        ), headers: headers)
    }
}
