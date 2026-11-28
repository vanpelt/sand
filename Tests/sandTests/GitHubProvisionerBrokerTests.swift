import Foundation
import Testing
@testable import sand

@Suite struct GitHubProvisionerBrokerTests {
    static let jit = "JITCONFIG-SECRET-abc123=="
    static let allocation = Spike.allocation(nonce: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123456")

    @Test func jitRunnerWithoutConfigShOrToken() throws {
        let commands = try GitHubProvisioner().brokerScript(allocation: Self.allocation, jitConfig: Self.jit, egress: nil)
        let joined = commands.map(\.command).joined(separator: "\n")
        #expect(!joined.contains("config.sh"))
        #expect(!joined.contains("--token"))
        #expect(!joined.contains("--replace"))
        #expect(commands.last?.command == GitHubProvisioner.jitRunCommand(prefix: ""))
        #expect(commands.last?.stdin == Self.jit + "\n")
    }

    /// Finding: the JIT config must never be a process argument (host `ps`
    /// shows sshpass/ssh arguments to every local user for hours).
    @Test func secretsTravelOnStdinNeverInCommandText() throws {
        for egress in [nil, GuestEgressEnv.standard] {
            let commands = try GitHubProvisioner().brokerScript(allocation: Self.allocation, jitConfig: Self.jit, egress: egress)
            for command in commands {
                #expect(!command.command.contains(Self.jit))
                #expect(!command.command.contains(Self.allocation.nonce))
            }
            #expect(commands.compactMap(\.stdin).filter { $0.contains(Self.jit) }.count == 1)
            #expect(commands.compactMap(\.stdin).filter { $0.contains(Self.allocation.nonce) }.count == 1, "the hook script")
        }
    }

    @Test func hookIsWrittenBeforeRunSh() throws {
        let commands = try GitHubProvisioner().brokerScript(allocation: Self.allocation, jitConfig: Self.jit, egress: nil)
        let hook = try #require(commands.firstIndex { $0.command.contains("job-started.sh") && $0.command.contains("/bin/cat >") })
        let dotEnv = try #require(commands.firstIndex { $0.command.contains("/.env") })
        let run = try #require(commands.firstIndex { $0.command.hasSuffix("run.sh") })
        let extract = try #require(commands.firstIndex { $0.command.hasPrefix("tar xzf") })
        #expect(extract < hook && hook < dotEnv && dotEnv < run)
        #expect(commands[hook].stdin?.contains(Self.allocation.nonce) == true)
    }

    @Test func dotEnvCarriesTheHookWithHomeExpandedWithoutEgress() throws {
        let commands = try GitHubProvisioner().brokerScript(allocation: Self.allocation, jitConfig: Self.jit, egress: nil)
        let dotEnv = try #require(commands.first { $0.command.contains("/.env") })
        #expect(dotEnv.command == "printf '%s\\n' 'ACTIONS_RUNNER_HOOK_JOB_STARTED='\"$HOME\"'/.sand/hooks/job-started.sh' > ~/actions-runner/.env")
    }

    @Test func dotEnvKeepsProxyVariablesUnderEgressAndRunShUsesThePrefix() throws {
        let egress = GuestEgressEnv.standard
        let commands = try GitHubProvisioner().brokerScript(allocation: Self.allocation, jitConfig: Self.jit, egress: egress)
        let dotEnv = try #require(commands.first { $0.command.contains("/.env") })
        #expect(dotEnv.command.contains("'https_proxy=http://127.0.0.1:3128'"))
        #expect(dotEnv.command.contains("'ACTIONS_RUNNER_HOOK_JOB_STARTED='\"$HOME\"'/.sand/hooks/job-started.sh'"))
        #expect(commands.filter { $0.command.contains("/.env") }.count == 1, "written once, not appended")
        #expect(commands.last?.command.hasSuffix(egress.envPrefix + " ~/actions-runner/run.sh") == true)
    }

    /// Runs the real JIT wrapper in bash with a stand-in run.sh: the variable
    /// arrives from stdin, stdin is detached, and nothing reaches argv.
    @Test func jitWrapperReadsTheConfigFromStdinInARealShell() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        try FileManager.default.createDirectory(atPath: home + "/actions-runner", withIntermediateDirectories: true)
        let fake = home + "/actions-runner/run.sh"
        try "#!/bin/bash\nprintf 'jit=%s\\n' \"$ACTIONS_RUNNER_INPUT_JITCONFIG\"\nprintf 'args=%s\\n' \"$*\"\nprintf 'sand_jit=%s\\n' \"${SAND_JIT-unset}\"\nif read -r line; then echo stdin=open; else echo stdin=eof; fi\n".write(toFile: fake, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: fake)
        func run(_ input: String) throws -> (String, Int32) {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/bin/bash")
            process.arguments = ["-c", GitHubProvisioner.jitRunCommand(prefix: "")]
            process.environment = ["HOME": home, "PATH": "/usr/bin:/bin"]
            let stdin = Pipe(), stdout = Pipe()
            process.standardInput = stdin
            process.standardOutput = stdout
            process.standardError = Pipe()
            try process.run()
            stdin.fileHandleForWriting.write(Data(input.utf8))
            try stdin.fileHandleForWriting.close()
            process.waitUntilExit()
            return (String(data: stdout.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? "", process.terminationStatus)
        }
        let (output, status) = try run(Self.jit + "\nextra line\n")
        #expect(status == 0)
        #expect(output == "jit=\(Self.jit)\nargs=\nsand_jit=unset\nstdin=eof\n")
        let (_, emptyStatus) = try run("")
        #expect(emptyStatus == 97, "no runner without a JIT config")
    }

    @Test func dotEnvVariableReallyExpandsInAShell() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        try FileManager.default.createDirectory(atPath: home + "/actions-runner", withIntermediateDirectories: true)
        let command = GuestEgressEnv.dotEnvCommand(variables: [("ACTIONS_RUNNER_HOOK_JOB_STARTED", AdmissionHook.guestPath)], directory: home + "/actions-runner")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = ["-c", command]
        process.environment = ["HOME": home]
        try process.run()
        process.waitUntilExit()
        let written = try String(contentsOfFile: home + "/actions-runner/.env", encoding: .utf8)
        #expect(written == "ACTIONS_RUNNER_HOOK_JOB_STARTED=\(home)/.sand/hooks/job-started.sh\n")
    }

    @Test func malformedNonceAbortsScriptGeneration() {
        #expect(throws: AdmissionHookError.self) {
            _ = try GitHubProvisioner().brokerScript(allocation: Spike.allocation(nonce: "bad nonce"), jitConfig: Self.jit, egress: nil)
        }
    }
}
