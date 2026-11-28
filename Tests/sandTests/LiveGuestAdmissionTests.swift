import CryptoKit
import Foundation
import Testing
@testable import sand

/// Live checks of the broker-mode guest mechanics against a real, disposable
/// VM. Skipped unless `SAND_LIVE_GUEST_IP` names a running throwaway clone
/// (user/password admin/admin). Never point it at a VM you care about: it
/// overwrites `~/actions-runner/run.sh` and `~/.sand/hooks` in the guest.
@Suite(.serialized, .enabled(if: ProcessInfo.processInfo.environment["SAND_LIVE_GUEST_IP"] != nil))
struct LiveGuestAdmissionTests {
    let ssh = SSHClient(
        processRunner: SystemProcessRunner(),
        host: ProcessInfo.processInfo.environment["SAND_LIVE_GUEST_IP"] ?? "127.0.0.1",
        config: .standard
    )

    private func run(_ command: String, stdin: String? = nil) async throws -> ProcessResult {
        let handle = try ssh.start(command: command, stdin: stdin)
        return try await handle.waitAsync()
    }

    /// The JIT config travels on stdin: it reaches `run.sh` as
    /// ACTIONS_RUNNER_INPUT_JITCONFIG and appears in no command line on the
    /// host or in the guest while the runner command runs.
    @Test func jitConfigArrivesOnStdinAndNeverInACommandLine() async throws {
        let secret = "SANDLIVEJIT" + UUID().uuidString.replacingOccurrences(of: "-", with: "")
        let check = """
        #!/bin/bash
        expected=$(cat ~/.sand-live-expected)
        [ "$ACTIONS_RUNNER_INPUT_JITCONFIG" = "$expected" ] && echo JIT_MATCH || echo JIT_MISMATCH
        if /bin/ps -axww -o command= | /usr/bin/grep -F "$expected" | /usr/bin/grep -v grep >/dev/null; then echo GUEST_ARGV_LEAK; else echo GUEST_ARGV_CLEAN; fi
        if read -r line; then echo STDIN_OPEN; else echo STDIN_EOF; fi
        /bin/sleep 3
        """
        _ = try await run("mkdir -p ~/actions-runner && /bin/cat > ~/actions-runner/run.sh && chmod 0755 ~/actions-runner/run.sh", stdin: check)
        _ = try await run("umask 077 && /bin/cat > ~/.sand-live-expected", stdin: secret)
        let handle = try ssh.start(command: GitHubProvisioner.jitRunCommand(prefix: GuestEgressEnv.standard.envPrefix + " "), stdin: secret + "\n")
        try await Task.sleep(nanoseconds: 1_500_000_000)
        let hostPS = Process()
        hostPS.executableURL = URL(fileURLWithPath: "/bin/ps")
        hostPS.arguments = ["-axww", "-o", "command="]
        let pipe = Pipe()
        hostPS.standardOutput = pipe
        try hostPS.run()
        let hostCommands = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        hostPS.waitUntilExit()
        let result = try await handle.waitAsync()
        _ = try await run("rm -f ~/.sand-live-expected")
        #expect(!hostCommands.contains(secret), "host ps must not show the JIT config")
        #expect(hostCommands.contains("actions-runner/run.sh"), "the runner command was running during the host ps sample")
        #expect(result.stdout.contains("JIT_MATCH"), "\(result.stdout)")
        #expect(result.stdout.contains("GUEST_ARGV_CLEAN"), "\(result.stdout)")
        #expect(result.stdout.contains("STDIN_EOF"), "\(result.stdout)")
        #expect(!result.stdout.contains(secret))
    }

    /// The hook installs from stdin (0555), and the guest's own curl accepts
    /// `-q --proto =http`, ignores a planted ~/.curlrc, allows only on `allow`.
    @Test func hookInstallsFromStdinAndRunsWithTheGuestCurl() async throws {
        let allocationId = "alc_01JDQ7Z6S8V4N3K2M1P0R9T8W7"
        let nonce = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123456"
        let script = try AdmissionHook.script(allocationId: allocationId, nonce: nonce, relayPort: 3199,
                                              killCommand: "echo KILLED-MARKER || true", blockCommand: "exit 77")
        _ = try await run("chmod -R u+w ~/.sand/hooks 2>/dev/null; rm -rf ~/.sand/hooks")
        for command in AdmissionHook.installCommands(script: script) {
            _ = try await run(command.command, stdin: command.stdin)
        }
        let mode = try await run("stat -f '%Lp' ~/.sand/hooks/job-started.sh; stat -f '%Lp' ~/.sand/hooks; shasum -a 256 ~/.sand/hooks/job-started.sh | cut -d' ' -f1")
        let digest = SHA256Hex.of(script)
        #expect(mode.stdout == "555\n555\n\(digest)\n", "\(mode.stdout)")
        let env = "GITHUB_RUN_ID=46107413025 GITHUB_RUN_ATTEMPT=1 GITHUB_REPOSITORY_ID=1473742157 RUNNER_NAME=sand-dev-laptop-3f9a1c2e GITHUB_JOB=smoke"
        // A planted ~/.curlrc that would send the request elsewhere must be ignored (-q).
        _ = try await run("printf 'connect-to = ::127.0.0.1:1\\n' > ~/.curlrc")
        let allow = """
        (printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 5\\r\\nConnection: close\\r\\n\\r\\nallow' | /usr/bin/nc -l 127.0.0.1 3199 >/dev/null 2>&1 &); /bin/sleep 1; \
        set +e; env \(env) /bin/bash -e ~/.sand/hooks/job-started.sh; echo "exit=$?"
        """
        let allowed = try await run(allow)
        let denyRun = try await run("set +e; env \(env) /bin/bash -e ~/.sand/hooks/job-started.sh; echo \"exit=$?\"")
        _ = try await run("rm -f ~/.curlrc")
        #expect(allowed.stdout == "\(AdmissionHook.admittedMarker)\nexit=0\n", "\(allowed.stdout)")
        #expect(denyRun.stdout == "\(AdmissionHook.deniedMarker)\nKILLED-MARKER\nexit=77\n", "\(denyRun.stdout)")
    }

    /// The verifier's GitHub-independent probe sees a Runner.Worker process
    /// and does not match its own command line.
    @Test func workerProbeSeesAWorkerProcess() async throws {
        _ = try await run("/usr/bin/pkill -f 'sand-live/bin/Runner.Worker' || true; rm -rf /tmp/sand-live")
        let before = try await run(AssignmentVerifier.workerProbeCommand)
        #expect(try !AssignmentVerifier.parseWorkerProbe(before.stdout), "\(before.stdout)")
        _ = try await run("mkdir -p /tmp/sand-live/bin && cp /bin/sleep /tmp/sand-live/bin/Runner.Worker && (nohup /tmp/sand-live/bin/Runner.Worker 60 >/dev/null 2>&1 &)")
        let during = try await run(AssignmentVerifier.workerProbeCommand)
        _ = try await run("/usr/bin/pkill -f 'sand-live/bin/Runner.Worker' || true; rm -rf /tmp/sand-live")
        #expect(try AssignmentVerifier.parseWorkerProbe(during.stdout), "\(during.stdout)")
    }
}

enum SHA256Hex {
    static func of(_ text: String) -> String {
        SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}
