import XCTest
@testable import sand

final class SSHProcessRunner: ProcessRunning, @unchecked Sendable {
    struct Call: Equatable {
        let executable: String
        let arguments: [String]
        let wait: Bool
    }

    var runCalls: [Call] = []
    var startCalls: [Call] = []

    func run(executable: String, arguments: [String], wait: Bool) async throws -> ProcessResult? {
        runCalls.append(Call(executable: executable, arguments: arguments, wait: wait))
        return ProcessResult(stdout: "", stderr: "", exitCode: 0)
    }

    func start(executable: String, arguments: [String]) throws -> ProcessHandle {
        startCalls.append(Call(executable: executable, arguments: arguments, wait: false))
        return ProcessHandle(
            waitAsync: { ProcessResult(stdout: "", stderr: "", exitCode: 0) },
            terminate: {}
        )
    }
}

final class SSHClientTests: XCTestCase {
    func testStartBuildsSSHCommand() async throws {
        let runner = SSHProcessRunner()
        let ssh = SSHClient(
            processRunner: runner,
            host: "10.0.0.1",
            config: .init(user: "admin", password: "pw", port: 2222)
        )
        let handle = try ssh.start(command: "echo hi")
        _ = try await handle.waitAsync()
        let expected = SSHProcessRunner.Call(
            executable: "sshpass",
            arguments: [
                "-p", "pw",
                "ssh",
                "-F", "/dev/null",
                "-o", "ForwardAgent=no",
                "-o", "ForwardX11=no",
                "-o", "PermitLocalCommand=no",
                "-o", "ControlMaster=no",
                "-o", "ControlPath=none",
                "-o", "PreferredAuthentications=password",
                "-o", "PubkeyAuthentication=no",
                "-o", "IdentitiesOnly=yes",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "LogLevel=ERROR",
                "-o", "ConnectTimeout=10",
                "-o", "ServerAliveInterval=30",
                "-o", "ServerAliveCountMax=6",
                "-o", "ClearAllForwardings=yes",
                "-p", "2222",
                "admin@10.0.0.1",
                "/bin/bash -lc 'echo hi'"
            ],
            wait: false
        )
        XCTAssertEqual(runner.startCalls.first, expected)
    }

    func testEverySSHInvocationIgnoresUserConfigAndForwardsNothing() async throws {
        let runner = SSHProcessRunner()
        let ssh = SSHClient(processRunner: runner, host: "10.0.0.1", config: .init(user: "admin", password: "pw", port: 22))
        _ = try await ssh.exec(command: "true")
        _ = try await ssh.copy(localPath: "/tmp/a", remotePath: "/tmp/b")
        _ = try ssh.startReverseTunnel(remotePort: 3128, localPort: 50000)
        let calls = runner.runCalls + runner.startCalls
        XCTAssertEqual(calls.count, 3)
        for call in calls {
            let args = call.arguments
            guard let f = args.firstIndex(of: "-F") else {
                XCTFail("missing -F /dev/null in \(args)")
                continue
            }
            XCTAssertEqual(args[f + 1], "/dev/null")
            for option in ["ForwardAgent=no", "ForwardX11=no", "PermitLocalCommand=no", "ControlMaster=no", "ControlPath=none"] {
                XCTAssertTrue(args.contains(option), "\(option) missing")
            }
        }
        // exec and scp forward nothing; the tunnel keeps only its own -R.
        XCTAssertTrue(runner.runCalls.allSatisfy { $0.arguments.contains("ClearAllForwardings=yes") })
        let tunnel = runner.startCalls[0].arguments
        XCTAssertFalse(tunnel.contains("ClearAllForwardings=yes"))
        XCTAssertEqual(tunnel.filter { $0 == "-R" }.count, 1)
    }

    func testChildEnvironmentDropsTheAgentSocket() {
        let env = SSHClient.childEnvironment(["SSH_AUTH_SOCK": "/private/tmp/agent", "SSH_AGENT_PID": "1", "PATH": "/usr/bin"])
        XCTAssertNil(env["SSH_AUTH_SOCK"])
        XCTAssertNil(env["SSH_AGENT_PID"])
        XCTAssertEqual(env["PATH"], "/usr/bin")
    }
}
