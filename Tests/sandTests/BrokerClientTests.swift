import Foundation
import Testing
@testable import sand

@Suite struct BrokerClientTests {
    static let base = URL(string: "https://broker.example.test")!

    /// A scripted broker that issues sessions and answers allocations with `allocate`.
    final class Script: @unchecked Sendable {
        let lock = NSLock()
        var sessions = 0
        var sessionTTL: TimeInterval = 900
        var allocate: [ScriptedSession.Reply] = []
        let clock = TestClock()

        func handle(_ request: URLRequest) throws -> ScriptedSession.Reply {
            let path = request.url!.path
            return lock.withLock {
                switch path {
                case "/v1/device/challenges":
                    return .init(201, #"{"challenge_id":"chl_00000000000000000000000000","challenge":"\#(String(repeating: "c", count: 43))","expires_at":"2030-01-01T00:00:00Z"}"#)
                case "/v1/device/sessions":
                    sessions += 1
                    let expiry = ISO8601DateFormatter().string(from: clock.now.addingTimeInterval(sessionTTL))
                    return .init(201, #"{"session_token":"TOKEN-\#(sessions)","expires_at":"\#(expiry)","device_id":"dev","owner":{"github_user_id":17,"github_login":"o"},"policy_version":"pilot-1"}"#)
                case "/v1/allocations":
                    return allocate.isEmpty ? .init(500) : allocate.removeFirst()
                default:
                    return .init(404, #"{"error":{"code":"not_found","message":"x"}}"#)
                }
            }
        }
    }

    static let allocationJSON = #"""
    {"allocation_id":"alc_01JDQ7Z6S8V4N3K2M1P0R9T8W7","state":"registered","nonce":"NONCE-SECRET-0000000000000000000000000000000","created_at":"2026-11-27T05:00:00Z","expires_at":"2026-11-27T05:15:00Z","repository":{"id":1473742157,"owner":"o","name":"r"},"runner":{"id":34,"name":"sand-dev-1","labels":["sand"],"runner_group_id":1,"ephemeral":true},"jit_config":"JIT-SECRET","admission":{"deadline_seconds":30,"require_oidc":false,"oidc_audience":"sand-broker"},"policy_version":"pilot-1"}
    """#

    private func client(_ script: Script, _ session: ScriptedSession) -> BrokerClient {
        BrokerClient(baseURL: Self.base, deviceId: "dev", key: DeviceKey.generate(), session: session, now: script.clock.clock, sleep: { _ in })
    }

    @Test func acquiresTheSessionOnceAndRefreshesOn401() async throws {
        let script = Script()
        script.allocate = [.init(201, Self.allocationJSON), .init(401, #"{"error":{"code":"session_expired","message":"x"}}"#), .init(201, Self.allocationJSON)]
        let session = ScriptedSession { try script.handle($0) }
        let client = client(script, session)
        let first = try await client.allocate(BrokerHarness.request)
        #expect(first.jitConfig == "JIT-SECRET")
        _ = try await client.allocate(BrokerHarness.request)
        #expect(await client.sessionsAcquired == 2, "one initial session, one refresh after the 401")
        let auth = session.requests.filter { $0.url!.path == "/v1/allocations" }.compactMap { $0.value(forHTTPHeaderField: "Authorization") }
        #expect(auth == ["Bearer TOKEN-1", "Bearer TOKEN-1", "Bearer TOKEN-2"])
    }

    @Test func refreshesASessionNearExpiry() async throws {
        let script = Script()
        script.allocate = [.init(201, Self.allocationJSON), .init(201, Self.allocationJSON)]
        let session = ScriptedSession { try script.handle($0) }
        let client = client(script, session)
        _ = try await client.allocate(BrokerHarness.request)
        script.clock.advance(850)
        _ = try await client.allocate(BrokerHarness.request)
        #expect(await client.sessionsAcquired == 2)
    }

    @Test func idempotencyKeyIsReusedAcrossRetriesAndRequestIdsArePresent() async throws {
        let script = Script()
        script.allocate = [.init(503), .init(503), .init(201, Self.allocationJSON)]
        let session = ScriptedSession { try script.handle($0) }
        let client = client(script, session)
        _ = try await client.allocate(BrokerHarness.request)
        let posts = session.requests.filter { $0.url!.path == "/v1/allocations" }
        #expect(posts.count == 3)
        let keys = Set(posts.compactMap { $0.value(forHTTPHeaderField: "Idempotency-Key") })
        #expect(keys.count == 1)
        #expect(UUID(uuidString: keys.first ?? "") != nil)
        #expect(session.requests.allSatisfy { UUID(uuidString: $0.value(forHTTPHeaderField: "Sand-Request-Id") ?? "") != nil })
        _ = script.lock.withLock { script.allocate = [.init(201, Self.allocationJSON)] }
        _ = try await client.allocate(BrokerHarness.request)
        let newKey = session.requests.filter { $0.url!.path == "/v1/allocations" }.last?.value(forHTTPHeaderField: "Idempotency-Key")
        #expect(newKey != keys.first, "a new call gets a new key")
    }

    @Test func errorsCarryNoBodiesOrSecrets() async throws {
        let script = Script()
        script.allocate = [.init(502, #"{"error":{"code":"github_error","message":"JIT-SECRET TOKEN leaked"}}"#)]
        let session = ScriptedSession { try script.handle($0) }
        let client = BrokerClient(baseURL: Self.base, deviceId: "dev", key: DeviceKey.generate(), session: session, now: script.clock.clock, sleep: { _ in }, transportRetries: 0)
        do {
            _ = try await client.allocate(BrokerHarness.request)
            Issue.record("expected an error")
        } catch {
            let text = "\(error) \(String(describing: error))"
            #expect(!text.contains("JIT-SECRET"))
            #expect(!text.contains("TOKEN"))
            #expect(error as? BrokerClientError == .http(status: 502, code: "github_error", retryAfterSeconds: nil))
        }
    }

    @Test func retryAfterIsReportedFor409And429() async throws {
        let script = Script()
        script.allocate = [
            .init(409, #"{"error":{"code":"no_eligible_demand","message":"x","retry_after_seconds":30}}"#),
            .init(429, #"{"error":{"code":"circuit_open","message":"x"}}"#, headers: ["Retry-After": "120"]),
        ]
        let session = ScriptedSession { try script.handle($0) }
        let client = client(script, session)
        for expected in [(409, 30), (429, 120)] {
            do {
                _ = try await client.allocate(BrokerHarness.request)
                Issue.record("expected \(expected.0)")
            } catch let error as BrokerClientError {
                #expect(error.isRetryLater)
                #expect(error.retryAfterSeconds == expected.1)
            }
        }
    }

    @Test func allocateWithRetryWaitsOutNoDemandWithoutGivingUp() async throws {
        let fake = FakeBrokerClient()
        fake.set {
            $0.allocateResults = [
                .failure(BrokerClientError.http(status: 409, code: "no_eligible_demand", retryAfterSeconds: 30)),
                .failure(BrokerClientError.http(status: 429, code: "circuit_open", retryAfterSeconds: 9999)),
                .success(Spike.allocation()),
            ]
        }
        let waits = LockedValues()
        let allocation = try await Runner.allocateWithRetry(broker: fake, request: BrokerHarness.request, sleep: { waits.append($0) }, log: { _ in })
        #expect(allocation.allocationId == Spike.allocation().allocationId)
        #expect(waits.values == [30, 300], "retry_after honoured, capped at 300 s")
    }

    @Test func allocateWithRetryThrowsOtherErrors() async {
        let fake = FakeBrokerClient()
        fake.set { $0.allocateResults = [.failure(BrokerClientError.http(status: 403, code: "repository_not_allowed", retryAfterSeconds: nil))] }
        await #expect(throws: BrokerClientError.self) {
            _ = try await Runner.allocateWithRetry(broker: fake, request: BrokerHarness.request, sleep: { _ in }, log: { _ in })
        }
    }
}

final class LockedValues: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [TimeInterval] = []
    var values: [TimeInterval] { lock.withLock { storage } }
    func append(_ value: TimeInterval) { lock.withLock { storage.append(value) } }
}
