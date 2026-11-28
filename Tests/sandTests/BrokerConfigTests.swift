import Foundation
import Testing
@testable import sand

@Suite struct BrokerConfigTests {
    static let keyPath: String = {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        return (try? DeviceKey.generate().save(directory: dir, deviceId: "dev-laptop").privatePath) ?? "/missing"
    }()

    private func config(_ github: String) throws -> Config {
        let yaml = """
        runners:
          - name: laptop-runner
            vm:
              source:
                type: local
                name: golden
            provisioner:
              type: github
              config:
        \(github.split(separator: "\n").map { "        " + $0 }.joined(separator: "\n"))
        """
        return try Config.load(path: writeTempFile(contents: yaml).path)
    }

    private func errors(_ github: String) throws -> [String] {
        ConfigValidator().validate(try config(github)).filter { $0.severity == .error }.map(\.message)
    }

    private func broker(url: String = "http://127.0.0.1:8787", deviceId: String = "dev-laptop", key: String = keyPath) -> String {
        """
        broker:
          url: \(url)
          deviceId: \(deviceId)
          deviceKeyPath: \(key)
        """
    }

    private let base = """
    organization: example-org
    repository: example-repo
    runnerName: laptop-runner
    """

    @Test func decodesTheBrokerBlockWithoutAnAppId() throws {
        let decoded = try config(base + "\n" + broker(key: "~/.sand/broker/dev-laptop.key.pem"))
        let github = try #require(decoded.runners.first?.provisioner.github)
        #expect(github.appId == nil)
        #expect(github.broker?.url == "http://127.0.0.1:8787")
        #expect(github.broker?.deviceId == "dev-laptop")
        #expect(github.broker?.deviceKeyPath.hasPrefix("~") == false, "the key path is expanded")
        #expect(try errors(base + "\n" + broker()).isEmpty)
    }

    @Test func keyAndBrokerTogetherIsAnError() throws {
        let messages = try errors(base + "\nappId: 1\nprivateKeyKeychainLabel: label\n" + broker())
        #expect(messages.contains { $0.contains("exactly one of privateKeyPath, privateKeyKeychainLabel or broker") })
    }

    @Test func neitherKeyNorBrokerIsAnError() throws {
        let messages = try errors(base + "\nappId: 1")
        #expect(messages.contains { $0.contains("exactly one of privateKeyPath, privateKeyKeychainLabel or broker") })
    }

    @Test func brokerNeedsARepository() throws {
        let messages = try errors("organization: example-org\nrunnerName: r\n" + broker())
        #expect(messages.contains { $0.contains("requires provisioner.config.repository") })
    }

    @Test func brokerForbidsRunnerGroupAndExtraLabels() throws {
        #expect(try errors(base + "\nrunnerGroup: g\n" + broker()).contains { $0.contains("runnerGroup is not allowed with broker") })
        #expect(try errors(base + "\nextraLabels: [x]\n" + broker()).contains { $0.contains("extraLabels is not allowed with broker") })
    }

    @Test func plainHTTPOnlyToLoopback() throws {
        #expect(try errors(base + "\n" + broker(url: "http://broker.example.com")).contains { $0.contains("must use https") })
        #expect(try errors(base + "\n" + broker(url: "http://10.0.0.5:8787")).contains { $0.contains("must use https") })
        #expect(try errors(base + "\n" + broker(url: "https://broker.example.com")).isEmpty)
        #expect(try errors(base + "\n" + broker(url: "http://localhost:8787")).isEmpty)
        #expect(try errors(base + "\n" + broker(url: "ftp://x")).contains { $0.contains("https") })
    }

    @Test func badDeviceIdAndMissingKeyFile() throws {
        #expect(try errors(base + "\n" + broker(deviceId: "Dev_Laptop")).contains { $0.contains("deviceId must match") })
        #expect(try errors(base + "\n" + broker(key: "/nonexistent/dev.key.pem")).contains { $0.contains("Device key not found") })
    }

    @Test func brokerFixtureLoadsAndValidatesApartFromTheLocalKeyFile() throws {
        let path = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("fixtures/sample_broker_config.yml").path
        let config = try Config.load(path: path)
        #expect(config.runners.first?.provisioner.github?.broker?.deviceId == "dev-laptop")
        let messages = ConfigValidator().validate(config).filter { $0.severity == .error }.map(\.message)
        #expect(messages.allSatisfy { $0.contains("Device key not found") }, "\(messages)")
    }

    @Test func localModeIsUnchanged() throws {
        #expect(try errors(base + "\nappId: 1\nprivateKeyKeychainLabel: label").isEmpty)
        #expect(try errors(base + "\nappId: 0\nprivateKeyKeychainLabel: label").contains { $0.contains("appId must be greater than 0") })
    }
}

@Suite struct AuditEventTests {
    @Test func forbiddenFieldsAreDroppedAndValuesBounded() {
        var fields: [String: String] = ["jit_config": "x", "nonce": "x", "session_token": "x", "oidc_token": "x", "signature": "x",
                                        "github_workflow": "x", "head_ref": "x", "commit_message": "x", "installation_token": "x",
                                        "vm_name": String(repeating: "é", count: 400)]
        for index in 0..<40 { fields["k\(index)"] = "v" }
        let event = AuditEvent.make(type: "admission.denied", fields: fields)
        #expect(event.fields.count <= AuditEvent.maxFields)
        for key in ["jit_config", "nonce", "session_token", "oidc_token", "signature", "github_workflow", "head_ref", "commit_message", "installation_token"] {
            #expect(event.fields[key] == nil, "\(key)")
        }
        #expect(event.fields.values.allSatisfy { $0.utf8.count <= AuditEvent.maxValueBytes })
        #expect(event.schema == "sand.audit.v1")
    }

    @Test func secretValuesAreRedactedInsideAllowedFields() {
        let event = AuditEvent.make(type: "vm.killed", fields: ["detail": "nonce abc123 leaked"], secrets: ["abc123"])
        #expect(event.fields["detail"] == "nonce [REDACTED] leaked")
    }

    @Test func encodesSnakeCase() {
        let line = AuditEvent.make(type: "admission.allowed", allocationId: "alc_1", jobId: 5).jsonLine()
        #expect(line.contains(#""allocation_id":"alc_1""#))
        #expect(line.contains(#""job_id":5"#))
        #expect(line.contains(#""schema":"sand.audit.v1""#))
    }
}

@Suite struct GitHubServiceBrokerTests {
    private func service(_ session: ScriptedSession) -> GitHubService {
        GitHubService(auth: MockAuth(), session: session, organization: "vanpelt", repository: "sand")
    }

    private static func base(_ request: URLRequest) -> ScriptedSession.Reply? {
        switch request.url!.path {
        case "/repos/vanpelt/sand/installation": return .init(200, #"{"id":7}"#)
        case "/app/installations/7/access_tokens": return .init(201, #"{"token":"ghs_x","expires_at":"2099-01-01T00:00:00Z"}"#)
        default: return nil
        }
    }

    @Test func jitRequestPathAndExactBody() async throws {
        let session = ScriptedSession { request in
            if let reply = Self.base(request) { return reply }
            return .init(201, #"{"runner":{"id":34,"name":"sand-dev-laptop-0011aabb","labels":[{"name":"sand"}]},"encoded_jit_config":"SECRET"}"#)
        }
        let jit = try await service(session).generateJITConfig(name: "sand-dev-laptop-0011aabb", labels: ["self-hosted", "sand"], runnerGroupId: 1)
        #expect(jit.runner.id == 34)
        #expect(jit.encodedJitConfig == "SECRET")
        let post = try #require(session.requests.last)
        #expect(post.httpMethod == "POST")
        #expect(post.url?.path == "/repos/vanpelt/sand/actions/runners/generate-jitconfig")
        #expect(String(decoding: post.httpBody ?? Data(), as: UTF8.self) == #"{"labels":["self-hosted","sand"],"name":"sand-dev-laptop-0011aabb","runner_group_id":1,"work_folder":"_work"}"#)
    }

    @Test func attemptJobsFollowsPagination() async throws {
        let session = ScriptedSession { request in
            if let reply = Self.base(request) { return reply }
            let page = request.url!.query!.contains("page=2") ? 2 : 1
            let id = page == 1 ? 1 : 2
            return .init(200, #"{"total_count":2,"jobs":[{"id":\#(id),"run_id":9,"run_attempt":2,"status":"in_progress","runner_id":34,"runner_name":"r","labels":["sand"]}]}"#)
        }
        let jobs = try await service(session).attemptJobs(runId: 9, attempt: 2)
        #expect(jobs.map(\.id) == [1, 2])
        #expect(session.requests.contains { $0.url!.path == "/repos/vanpelt/sand/actions/runs/9/attempts/2/jobs" })
    }

    @Test func runAttemptDecodesActors() async throws {
        let session = ScriptedSession { request in
            if let reply = Self.base(request) { return reply }
            return .init(200, #"{"id":9,"run_attempt":2,"event":"push","status":"in_progress","path":".github/workflows/a.yml","head_branch":"main","head_sha":"abc","repository":{"id":1},"head_repository":{"id":1},"actor":{"id":17,"login":"o","type":"User"},"triggering_actor":{"id":17,"login":"o","type":"User"},"referenced_workflows":[]}"#)
        }
        let run = try await service(session).runAttempt(runId: 9, attempt: 2)
        #expect(run.triggeringActor?.id == 17)
        #expect(session.requests.last?.url?.path == "/repos/vanpelt/sand/actions/runs/9/attempts/2")
    }

    @Test func deleteRunnerMapsStatuses() async throws {
        for (status, expected) in [(204, DeleteRunnerResult.deleted), (422, .busy), (404, .notFound)] {
            let session = ScriptedSession { request in Self.base(request) ?? .init(status, "") }
            #expect(try await service(session).deleteRunner(id: 34) == expected)
        }
        let failing = ScriptedSession { request in Self.base(request) ?? .init(500, "") }
        await #expect(throws: GitHubServiceError.self) { _ = try await service(failing).deleteRunner(id: 34) }
    }

    @Test func installationTokenIsCached() async throws {
        let session = ScriptedSession { request in Self.base(request) ?? .init(200, #"{"total_count":0,"runners":[]}"#) }
        let github = service(session)
        _ = try await github.listRunners()
        _ = try await github.listRunners()
        #expect(session.requests.filter { $0.url!.path.hasSuffix("/access_tokens") }.count == 1)
    }
}
