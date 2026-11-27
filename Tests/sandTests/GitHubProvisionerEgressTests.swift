import Foundation
import Testing
@testable import sand

@Suite struct GitHubProvisionerEgressTests {
    let config = GitHubProvisionerConfig(appId: 1, organization: "org", repository: "repo", privateKeyPath: "/tmp/key.pem", runnerName: "runner-1", extraLabels: nil)

    @Test func egressWritesDotEnvBeforeConfigAndDisablesUpdates() {
        let script = GitHubProvisioner().script(config: config, runnerName: "runner-1-0a1b2", runnerToken: "token", egress: .standard)
        let dotEnv = script.firstIndex { $0.contains("> ~/actions-runner/.env") }
        let configure = script.firstIndex { $0.contains("config.sh") }
        let extract = script.firstIndex { $0.hasPrefix("tar xzf") }
        #expect(dotEnv != nil && configure != nil && extract != nil)
        #expect(extract! < dotEnv! && dotEnv! < configure!)
        let configureLine = script[configure!]
        #expect(configureLine.hasPrefix("env https_proxy='http://127.0.0.1:3128' http_proxy='http://127.0.0.1:3128'"))
        #expect(configureLine.contains("no_proxy='localhost,127.0.0.1,::1'"))
        #expect(configureLine.hasSuffix("--disableupdate"))
        #expect(script[dotEnv!].contains("'https_proxy=http://127.0.0.1:3128'"))
        #expect(script.last == "~/actions-runner/run.sh")
    }

    @Test func withoutEgressTheScriptIsUnchanged() {
        #expect(GitHubProvisioner().script(config: config, runnerName: "runner-1-0a1b2", runnerToken: "token") == [
            "rm -rf ~/actions-runner && mkdir ~/actions-runner",
            "tar xzf ~/actions-runner.tar.gz -C ~/actions-runner",
            "echo \"Runner extracted\"",
            "~/actions-runner/config.sh --url https://github.com/org/repo --name runner-1-0a1b2 --token token --ephemeral --unattended --replace --labels sand",
            "echo \"Runner configured, starting ~/actions-runner/run.sh\"",
            "~/actions-runner/run.sh"
        ])
    }

    @Test func guestSetupIsBestEffortAndKeepsProfileSemantics() {
        let command = GuestEgressEnv.standard.guestSetupCommand
        #expect(command.contains(">> ~/.zshenv"))
        #expect(command.contains("if [ -f ~/.bash_profile ] || [ ! -f ~/.profile ]"))
        #expect(command.contains("sudo -n networksetup -setsecurewebproxy"))
        #expect(command.contains("-setdnsservers \"$svc\" 127.0.0.1"))
        #expect(command.contains("|| echo \"WARN:"))
        #expect(command.hasSuffix("; true"))
    }
}
