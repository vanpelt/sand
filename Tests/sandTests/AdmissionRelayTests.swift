import Foundation
import Testing
@testable import sand

@Suite struct AdmissionRelayTests {
    final class KillLog: @unchecked Sendable {
        private let lock = NSLock()
        private var storage: [String] = []
        var reasons: [String] { lock.withLock { storage } }
        func add(_ reason: String) { lock.withLock { storage.append(reason) } }
    }

    struct Fixture {
        let broker = FakeBrokerClient()
        let kills = KillLog()
        let audit = AuditCollector()
        let controller: AdmissionController
        let relay: AdmissionRelay

        init(timeout: TimeInterval = 5) {
            let kills = self.kills
            controller = AdmissionController(allocation: Spike.allocation(), deviceId: "dev-laptop", audit: audit.audit) { kills.add($0) }
            relay = AdmissionRelay(controller: controller, broker: broker, vmName: "laptop-runner", timeout: timeout)
        }

        func body(allocationId: String = Spike.allocation().allocationId, nonce: String = Spike.allocation().nonce, hints: AdmissionHints = Spike.hints()) -> Data {
            let hintsJSON = String(decoding: try! BrokerJSON.encoder().encode(hints), as: UTF8.self)
            return Data(#"{"allocation_id":"\#(allocationId)","nonce":"\#(nonce)","hints":\#(hintsJSON)}"#.utf8)
        }

        func post(_ body: Data, path: String = "/v1/admission", method: String = "POST") async -> String {
            let response = await relay.handle(HTTPRequest(method: method, path: path, query: nil, headers: ["content-type": "application/json"], body: body))
            return String(decoding: response.body, as: UTF8.self)
        }
    }

    @Test func onlyPostAdmissionIsAccepted() async {
        let f = Fixture()
        #expect(await f.post(f.body(), path: "/v1/other") == "deny")
        #expect(await f.post(f.body(), method: "GET") == "deny")
        #expect(f.kills.reasons.isEmpty, "a stray request does not consume the admission")
        f.broker.set { $0.admitResult = .success(decision(.allow)) }
        #expect(await f.post(f.body()) == "allow")
    }

    @Test func oversizedBodyIsDenied() async {
        let f = Fixture()
        #expect(await f.post(Data(repeating: 0x20, count: 4097)) == "deny")
        #expect(f.kills.reasons.count == 1)
        #expect(f.broker.admitCalls.isEmpty)
    }

    @Test func mismatchedAllocationOrNonceIsDeniedWithoutABrokerCall() async {
        for (id, nonce) in [("alc_99999999999999999999999999", Spike.allocation().nonce), (Spike.allocation().allocationId, String(repeating: "x", count: 43))] {
            let f = Fixture()
            #expect(await f.post(f.body(allocationId: id, nonce: nonce)) == "deny")
            #expect(f.broker.admitCalls.isEmpty)
            #expect(f.kills.reasons.count == 1)
        }
    }

    @Test func brokerAllowAnswersAllow() async {
        let f = Fixture()
        f.broker.set { $0.admitResult = .success(decision(.allow)) }
        #expect(await f.post(f.body()) == "allow")
        #expect(await f.controller.admittedJob?.id == Spike.jobId)
        #expect(f.kills.reasons.isEmpty)
        let sent = f.broker.admitCalls.first
        #expect(sent?.nonce == Spike.allocation().nonce)
        #expect(sent?.hints == Spike.hints())
        #expect(sent?.relay?.vmName == "laptop-runner")
        #expect(f.audit.types == ["admission.allowed"])
    }

    @Test(arguments: ["deny", "error", "non200", "timeout"])
    func everythingElseDeniesAndKillsOnce(_ mode: String) async {
        let f = Fixture(timeout: 0.2)
        f.broker.set {
            switch mode {
            case "deny": $0.admitResult = .success(decision(.deny, [.workflowNotAllowed]))
            case "error": $0.admitResult = .failure(BrokerClientError.transport("down"))
            case "non200": $0.admitResult = .failure(BrokerClientError.http(status: 503, code: "unavailable", retryAfterSeconds: nil))
            default:
                $0.admitResult = .success(decision(.allow))
                $0.admitDelay = 2
            }
        }
        #expect(await f.post(f.body()) == "deny")
        #expect(f.kills.reasons.count == 1)
        #expect(await f.controller.admittedJob == nil)
        // A second request is denied and does not kill again.
        #expect(await f.post(f.body()) == "deny")
        #expect(f.kills.reasons.count == 1)
        if mode == "deny" {
            let denied = f.audit.events.first { $0.type == "admission.denied" }
            #expect(denied?.jobId == Spike.jobId)
            #expect(denied?.reasons == [.workflowNotAllowed])
        }
    }

    @Test func allowWithReasonsIsTreatedAsDeny() async {
        let f = Fixture()
        f.broker.set { $0.admitResult = .success(decision(.allow, [.labelsMismatch])) }
        #expect(await f.post(f.body()) == "deny")
    }

    @Test func secondRequestIsDenied() async {
        let f = Fixture()
        f.broker.set { $0.admitResult = .success(decision(.allow)) }
        #expect(await f.post(f.body()) == "allow")
        #expect(await f.post(f.body()) == "deny")
        #expect(f.broker.admitCalls.count == 1)
    }

    @Test func relayServesOverLoopback() async throws {
        let f = Fixture()
        f.broker.set { $0.admitResult = .success(decision(.allow)) }
        let port = try await f.relay.start()
        defer { f.relay.stop() }
        let body = f.body()
        let reply = try await Task.detached { () -> String in
            let client = try LoopbackClient(port: port, timeout: 5)
            try client.send("POST /v1/admission HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: \(body.count)\r\n\r\n")
            try client.send(Array(body))
            return String(decoding: client.read(upTo: 65_536), as: UTF8.self)
        }.value
        #expect(reply.hasPrefix("HTTP/1.1 200"))
        #expect(reply.hasSuffix("\r\n\r\nallow"))
    }
}
