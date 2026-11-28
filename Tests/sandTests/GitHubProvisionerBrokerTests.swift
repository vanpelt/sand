import Foundation
import Testing
@testable import sand

@Suite struct GitHubProvisionerBrokerTests {
    static let jit = "JITCONFIG-SECRET-abc123=="
    static let allocation = Spike.allocation(nonce: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123456")

    @Test func jitRunnerWithoutConfigShOrToken() throws {
        let commands = try GitHubProvisioner().brokerScript(allocation: Self.allocation, jitConfig: Self.jit, egress: nil)
        let joined = commands.joined(separator: "\n")
        #expect(!joined.contains("config.sh"))
        #expect(!joined.contains("--token"))
        #expect(!joined.contains("--replace"))
        #expect(commands.last == "env 'ACTIONS_RUNNER_INPUT_JITCONFIG=\(Self.jit)' ~/actions-runner/run.sh")
        #expect(commands.filter { $0.contains(Self.jit) }.count == 1, "the JIT config appears only in the run.sh command")
    }

    @Test func hookIsWrittenBeforeRunSh() throws {
        let commands = try GitHubProvisioner().brokerScript(allocation: Self.allocation, jitConfig: Self.jit, egress: nil)
        let hook = try #require(commands.firstIndex { $0.contains("job-started.sh") && $0.contains("printf") })
        let dotEnv = try #require(commands.firstIndex { $0.contains("/.env") })
        let run = try #require(commands.firstIndex { $0.hasSuffix("run.sh") })
        let extract = try #require(commands.firstIndex { $0.hasPrefix("tar xzf") })
        #expect(extract < hook && hook < dotEnv && dotEnv < run)
        #expect(commands[hook].contains(Self.allocation.nonce))
    }

    @Test func dotEnvCarriesTheHookWithHomeExpandedWithoutEgress() throws {
        let commands = try GitHubProvisioner().brokerScript(allocation: Self.allocation, jitConfig: Self.jit, egress: nil)
        let dotEnv = try #require(commands.first { $0.contains("/.env") })
        #expect(dotEnv == "printf '%s\\n' 'ACTIONS_RUNNER_HOOK_JOB_STARTED='\"$HOME\"'/.sand/hooks/job-started.sh' > ~/actions-runner/.env")
    }

    @Test func dotEnvKeepsProxyVariablesUnderEgressAndRunShUsesThePrefix() throws {
        let egress = GuestEgressEnv.standard
        let commands = try GitHubProvisioner().brokerScript(allocation: Self.allocation, jitConfig: Self.jit, egress: egress)
        let dotEnv = try #require(commands.first { $0.contains("/.env") })
        #expect(dotEnv.contains("'https_proxy=http://127.0.0.1:3128'"))
        #expect(dotEnv.contains("'ACTIONS_RUNNER_HOOK_JOB_STARTED='\"$HOME\"'/.sand/hooks/job-started.sh'"))
        #expect(commands.filter { $0.contains("/.env") }.count == 1, "written once, not appended")
        #expect(commands.last?.hasPrefix(egress.envPrefix + " env 'ACTIONS_RUNNER_INPUT_JITCONFIG=") == true)
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
