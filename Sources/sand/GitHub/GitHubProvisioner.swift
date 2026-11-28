import Foundation

struct GitHubProvisionerConfig: Decodable, Sendable {
    let appId: Int
    let organization: String
    let repository: String?
    let privateKeyPath: String?
    let privateKeyKeychainLabel: String?
    let runnerName: String
    let extraLabels: [String]?
    let runnerGroup: String?

    init(
        appId: Int,
        organization: String,
        repository: String?,
        privateKeyPath: String? = nil,
        privateKeyKeychainLabel: String? = nil,
        runnerName: String,
        extraLabels: [String]?,
        runnerGroup: String? = nil
    ) {
        self.appId = appId
        self.organization = organization
        self.repository = repository
        self.privateKeyPath = privateKeyPath
        self.privateKeyKeychainLabel = privateKeyKeychainLabel
        self.runnerName = runnerName
        self.extraLabels = extraLabels
        self.runnerGroup = runnerGroup
    }
}

struct GitHubProvisioner: Sendable {
    static let tarballRemotePath = "actions-runner.tar.gz"

    static func uniqueRunnerName(base: String) -> String {
        "\(base)-\(String(format: "%05x", Int.random(in: 0..<0x100000)))"
    }

    /// `egress` is set when the guest reaches the network only through Sand's
    /// proxy: the runner's `.env` is written before config.sh, config.sh runs
    /// with the proxy variables, and self-update is disabled (an update would
    /// download outside the verified host-side tarball path). Without egress
    /// the commands are unchanged.
    func script(
        config: GitHubProvisionerConfig,
        runnerName: String,
        runnerToken: String,
        egress: GuestEgressEnv? = nil
    ) -> [String] {
        let labels = labelsString(extraLabels: config.extraLabels)
        let url = runnerURL(organization: config.organization, repository: config.repository)
        let runnerGroupArgument = config.runnerGroup.map { " --runnergroup \(Self.shellQuote($0))" } ?? ""
        let configure = "~/actions-runner/config.sh --url \(url) --name \(runnerName) --token \(runnerToken) --ephemeral --unattended --replace --labels \(labels)\(runnerGroupArgument)"
        var commands = [
            "rm -rf ~/actions-runner && mkdir ~/actions-runner",
            "tar xzf ~/\(Self.tarballRemotePath) -C ~/actions-runner",
            "echo \"Runner extracted\""
        ]
        if let egress {
            commands.append(egress.runnerDotEnvCommand())
            commands.append("\(egress.envPrefix) \(configure) --disableupdate")
        } else {
            commands.append(configure)
        }
        commands.append(contentsOf: Self.spikeHookCommands())
        commands.append("echo \"Runner configured, starting ~/actions-runner/run.sh\"")
        commands.append("~/actions-runner/run.sh")
        return commands
    }

    /// SPIKE ONLY (spike/job-admission): when the host environment names a
    /// script in SAND_SPIKE_HOOK_SCRIPT, install it in the guest outside
    /// ~/actions-runner and point ACTIONS_RUNNER_HOOK_JOB_STARTED at it via
    /// the runner's .env. Not for production use.
    static func spikeHookCommands(environment: [String: String] = ProcessInfo.processInfo.environment) -> [String] {
        guard let path = environment["SAND_SPIKE_HOOK_SCRIPT"],
              let data = FileManager.default.contents(atPath: path) else { return [] }
        let encoded = data.base64EncodedString()
        return [
            "mkdir -p ~/sand-hook && printf '%s' \(encoded) | base64 --decode > ~/sand-hook/job-started.sh && chmod 0555 ~/sand-hook/job-started.sh",
            "printf 'ACTIONS_RUNNER_HOOK_JOB_STARTED=%s\\n' \"$HOME/sand-hook/job-started.sh\" >> ~/actions-runner/.env && echo \"spike hook installed\""
        ]
    }

    static func shellQuote(_ value: String) -> String {
        "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }

    private func labelsString(extraLabels: [String]?) -> String {
        var labels = ["sand"]
        if let extraLabels {
            labels.append(contentsOf: extraLabels)
        }
        return labels.joined(separator: ",")
    }

    private func runnerURL(organization: String, repository: String?) -> String {
        if let repository {
            return "https://github.com/\(organization)/\(repository)"
        }
        return "https://github.com/\(organization)"
    }
}
