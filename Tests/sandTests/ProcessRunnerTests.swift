import XCTest
@testable import sand

final class ProcessRunnerTests: XCTestCase {
    func testFailedErrorDescriptionOmitsArguments() {
        let error = ProcessRunnerError.failed(
            exitCode: 255,
            stdout: "",
            stderr: "ssh: connect to host 10.0.0.1 port 22: Connection refused\n",
            command: ["sshpass", "-p", "hunter2", "ssh", "admin@10.0.0.1", "config.sh --token SECRET"]
        )
        let description = String(describing: error)
        XCTAssertEqual(description, "sshpass exited with code 255: ssh: connect to host 10.0.0.1 port 22: Connection refused")
        XCTAssertFalse(description.contains("hunter2"))
        XCTAssertFalse(description.contains("SECRET"))
    }

    func testFailedErrorDescriptionWithoutStderr() {
        let error = ProcessRunnerError.failed(exitCode: 1, stdout: "out", stderr: " \n", command: ["tart", "clone", "a", "b"])
        XCTAssertEqual(String(describing: error), "tart exited with code 1")
    }

    func testRedactReplacesSecrets() {
        let command = "~/actions-runner/config.sh --url https://github.com/org --token ABC123 --ephemeral"
        let redacted = Runner.redact(command, secrets: ["ABC123", ""])
        XCTAssertEqual(redacted, "~/actions-runner/config.sh --url https://github.com/org --token [REDACTED] --ephemeral")
    }

    func testWaitCollectsOutputLargerThanPipeBuffer() async throws {
        let result = try await withTimeout(seconds: 10) {
            try await SystemProcessRunner().run(
                executable: "sh",
                arguments: ["-c", "head -c 200000 /dev/zero | tr '\\0' a; head -c 100000 /dev/zero | tr '\\0' b >&2"],
                wait: true
            )
        }
        XCTAssertEqual(result?.stdout.count, 200_000)
        XCTAssertEqual(result?.stderr.count, 100_000)
    }

    func testDetachedProcessIsNotBlockedByUnreadOutput() async throws {
        let marker = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        defer { try? FileManager.default.removeItem(atPath: marker) }
        _ = try await SystemProcessRunner().run(
            executable: "sh",
            arguments: ["-c", "head -c 200000 /dev/zero; head -c 200000 /dev/zero >&2; touch '\(marker)'"],
            wait: false
        )
        let deadline = Date().addingTimeInterval(10)
        while !FileManager.default.fileExists(atPath: marker), Date() < deadline {
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker))
    }

    func testCancelledWaitCanLeaveProcessRunning() async throws {
        let marker = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        defer { try? FileManager.default.removeItem(atPath: marker) }
        let handle = try SystemProcessRunner().start(executable: "sh", arguments: ["-c", "sleep 0.5; touch '\(marker)'"])
        let waiter = Task { try await handle.waitAsync(terminateOnCancel: false) }
        try await Task.sleep(nanoseconds: 100_000_000)
        waiter.cancel()
        _ = try? await waiter.value
        let result = try await withTimeout(seconds: 10) { try await handle.waitAsync() }
        XCTAssertEqual(result.exitCode, 0)
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker))
    }

    private func withTimeout<T: Sendable>(
        seconds: UInt64,
        _ operation: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T?.self) { group in
            group.addTask { try await operation() }
            group.addTask {
                try await Task.sleep(nanoseconds: seconds * 1_000_000_000)
                return nil
            }
            defer { group.cancelAll() }
            guard let result = try await group.next(), let value = result else {
                throw CancellationError()
            }
            return value
        }
    }
}

final class ProcessRunnerStdinTests: XCTestCase {
    /// Secrets go to the child on stdin (closed after), never in arguments.
    func testStdinIsDeliveredAndClosed() async throws {
        let secret = String(repeating: "s", count: 100_000) // larger than a pipe buffer
        let handle = try SystemProcessRunner().start(executable: "/bin/bash", arguments: ["-c", "wc -c"], environment: nil, stdin: Data(secret.utf8))
        let result = try await handle.waitAsync()
        XCTAssertEqual(result.stdout.trimmingCharacters(in: .whitespacesAndNewlines), "100000")
    }
}

final class SSHClientStdinTests: XCTestCase {
    final class StdinRecorder: ProcessRunning, @unchecked Sendable {
        var arguments: [String] = []
        var stdin: Data?
        func run(executable: String, arguments: [String], wait: Bool) async throws -> ProcessResult? { nil }
        func start(executable: String, arguments: [String]) throws -> ProcessHandle {
            self.arguments = arguments
            return ProcessHandle(waitAsync: { ProcessResult(stdout: "", stderr: "", exitCode: 0) }, terminate: {})
        }
        func start(executable: String, arguments: [String], environment: [String: String]?, stdin: Data?) throws -> ProcessHandle {
            self.stdin = stdin
            return try start(executable: executable, arguments: arguments)
        }
    }

    func testStdinIsPassedAndNeverInArguments() throws {
        let runner = StdinRecorder()
        let ssh = SSHClient(processRunner: runner, host: "10.0.0.1", config: .init(user: "admin", password: "pw", port: 22))
        _ = try ssh.start(command: GitHubProvisioner.jitRunCommand(prefix: ""), stdin: "JIT-SECRET\n")
        XCTAssertEqual(runner.stdin, Data("JIT-SECRET\n".utf8))
        XCTAssertFalse(runner.arguments.joined(separator: " ").contains("JIT-SECRET"))
    }
}
