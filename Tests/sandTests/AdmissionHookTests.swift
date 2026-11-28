import Foundation
import Testing
@testable import sand

@Suite struct AdmissionHookTests {
    static let allocationId = "alc_01JDQ7Z6S8V4N3K2M1P0R9T8W7"
    static let nonce = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123456"

    @Test func generatedScriptIsFailClosed() throws {
        let script = try AdmissionHook.script(allocationId: Self.allocationId, nonce: Self.nonce)
        #expect(script.hasPrefix("#!/bin/bash\n"))
        #expect(script.contains("\nset +e\n"))
        #expect(!script.contains("@@"))
        #expect(script.contains("--noproxy '*'"))
        #expect(script.contains("/usr/bin/curl -q "), "-q must be the first argument to skip ~/.curlrc")
        #expect(script.contains("--proto '=http'"))
        #expect(script.contains("--max-time \(AdmissionTimeouts.hookCurlSeconds) "))
        #expect(script.contains("http://127.0.0.1:3129/v1/admission"))
        // The only exit is the allow path's `exit 0`.
        let exits = script.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter { $0.hasPrefix("exit") }
        #expect(exits == ["exit 0"])
        for line in script.split(separator: "\n") where line.contains("pkill") {
            for kill in line.components(separatedBy: ";") where kill.contains("pkill") {
                #expect(kill.trimmingCharacters(in: .whitespaces).hasSuffix("|| true"), "\(kill)")
            }
        }
        let echoes = script.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter { $0.hasPrefix("echo") }
        #expect(echoes == ["echo \"\(AdmissionHook.deniedMarker)\"", "echo \"\(AdmissionHook.admittedMarker)\""])
    }

    @Test func installIsReadOnlyOutsideTheRunnerDirectory() throws {
        let commands = AdmissionHook.installCommands(script: try AdmissionHook.script(allocationId: Self.allocationId, nonce: Self.nonce))
        let joined = commands.map(\.command).joined(separator: "\n")
        #expect(!joined.contains(Self.nonce), "the script travels on stdin")
        #expect(commands.last?.stdin?.contains(Self.nonce) == true)
        #expect(joined.contains("chmod 0555 \"$HOME/.sand/hooks/job-started.sh\""))
        #expect(joined.contains("chmod 0555 \"$HOME/.sand/hooks\""))
        #expect(!joined.contains("actions-runner"))
    }

    @Test func generationRefusesMalformedInputs() {
        #expect(throws: AdmissionHookError.invalidNonce) { try AdmissionHook.script(allocationId: Self.allocationId, nonce: "short") }
        #expect(throws: AdmissionHookError.invalidNonce) { try AdmissionHook.script(allocationId: Self.allocationId, nonce: String(repeating: "'", count: 43)) }
        #expect(throws: AdmissionHookError.invalidAllocationId) { try AdmissionHook.script(allocationId: "alc_x';rm -rf /", nonce: Self.nonce) }
    }

    // MARK: - Executing the hook under `bash -e`, as the runner does

    struct Execution {
        let exitCode: Int32
        let stdout: String
        let requests: [HTTPRequest]
    }

    final class Requests: @unchecked Sendable {
        private let lock = NSLock()
        private var storage: [HTTPRequest] = []
        var all: [HTTPRequest] { lock.withLock { storage } }
        func add(_ request: HTTPRequest) { lock.withLock { storage.append(request) } }
    }

    private func execute(verdict: String?, env overrides: [String: String] = [:], home: String = NSTemporaryDirectory()) async throws -> Execution {
        let requests = Requests()
        var port = 1
        var server: LoopbackHTTPServer?
        if let verdict {
            let stub = LoopbackHTTPServer(maxBodyBytes: 4096) { request in
                requests.add(request)
                return .text(200, verdict)
            }
            port = Int(try await stub.start())
            server = stub
        }
        defer { server?.stop() }
        // Test kill/block commands: a marker, then exit 77 instead of blocking forever.
        let script = try AdmissionHook.script(
            allocationId: Self.allocationId, nonce: Self.nonce, relayPort: port,
            killCommand: "echo KILLED-MARKER || true", blockCommand: "exit 77"
        )
        let path = try writeTempFile(contents: script, suffix: ".sh").path
        var environment = [
            "PATH": "/usr/bin:/bin", "HOME": home,
            "GITHUB_RUN_ID": "46107413025", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY_ID": "1473742157",
            "RUNNER_NAME": "sand-dev-laptop-3f9a1c2e", "GITHUB_JOB": "smoke",
            // A proxy in the environment must never be used for the relay call.
            "http_proxy": "http://127.0.0.1:1", "HTTP_PROXY": "http://127.0.0.1:1"
        ]
        for (key, value) in overrides {
            if value.isEmpty { environment.removeValue(forKey: key) } else { environment[key] = value }
        }
        let result = try await Task.detached { () -> (Int32, String) in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/bash")
            process.arguments = ["-e", path]
            process.environment = environment
            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            return (process.terminationStatus, String(decoding: data, as: UTF8.self))
        }.value
        return Execution(exitCode: result.0, stdout: result.1, requests: requests.all)
    }

    @Test func allowExitsZero() async throws {
        let run = try await execute(verdict: "allow")
        #expect(run.exitCode == 0)
        #expect(run.stdout == "\(AdmissionHook.admittedMarker)\n")
        #expect(run.requests.count == 1)
        let body = try #require(run.requests.first.map { String(decoding: $0.body, as: UTF8.self) })
        #expect(body == #"{"allocation_id":"alc_01JDQ7Z6S8V4N3K2M1P0R9T8W7","nonce":"abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123456","hints":{"repository_id":1473742157,"run_id":46107413025,"run_attempt":1,"runner_name":"sand-dev-laptop-3f9a1c2e","job_key":"smoke"}}"#)
        let decoded = try BrokerJSON.decoder().decode(AdmissionRelay.GuestRequest.self, from: run.requests[0].body)
        #expect(decoded.hints == Spike.hints())
    }

    @Test func denyKillsThenBlocks() async throws {
        let run = try await execute(verdict: "deny")
        #expect(run.exitCode == 77, "the test block command; the real one sleeps forever")
        #expect(run.stdout == "\(AdmissionHook.deniedMarker)\nKILLED-MARKER\n")
    }

    @Test func unexpectedVerdictDenies() async throws {
        let run = try await execute(verdict: "allow-ish")
        #expect(run.exitCode == 77)
    }

    @Test func relayDownDenies() async throws {
        let run = try await execute(verdict: nil)
        #expect(run.exitCode == 77)
        #expect(run.stdout.contains("KILLED-MARKER"))
    }

    @Test func malformedRunIdDeniesWithoutARequest() async throws {
        for bad in ["0", "12a", "1;id", "", "99999999999999999999"] {
            let run = try await execute(verdict: "allow", env: ["GITHUB_RUN_ID": bad])
            #expect(run.exitCode == 77, "GITHUB_RUN_ID=\(bad)")
            #expect(run.requests.isEmpty)
        }
        let badRunner = try await execute(verdict: "allow", env: ["RUNNER_NAME": "a\"b"])
        #expect(badRunner.exitCode == 77)
        #expect(badRunner.requests.isEmpty)
    }

    /// Finding: without -q curl reads ~/.curlrc, which could redirect or add options.
    @Test func plantedCurlrcIsIgnored() async throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
        try "header = \"X-Planted: 1\"\n".write(toFile: home + "/.curlrc", atomically: true, encoding: .utf8)
        let run = try await execute(verdict: "allow", home: home)
        #expect(run.exitCode == 0)
        #expect(run.requests.first?.header("x-planted") == nil)
    }

    @Test func quotedJobKeyIsSentEmpty() async throws {
        let run = try await execute(verdict: "allow", env: ["GITHUB_JOB": #"x","nonce":"evil"#])
        #expect(run.exitCode == 0)
        let body = String(decoding: run.requests.first?.body ?? Data(), as: UTF8.self)
        #expect(body.hasSuffix(#""job_key":""}}"#))
        #expect(!body.contains("evil"))
    }
}
