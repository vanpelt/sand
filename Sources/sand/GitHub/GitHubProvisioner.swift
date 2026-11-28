struct GitHubProvisionerConfig: Decodable, Sendable {
    /// Required in local mode only; broker mode holds no App key.
    let appId: Int?
    let organization: String
    let repository: String?
    let privateKeyPath: String?
    let privateKeyKeychainLabel: String?
    let runnerName: String
    let extraLabels: [String]?
    let runnerGroup: String?
    let broker: BrokerConfig?

    init(
        appId: Int?,
        organization: String,
        repository: String?,
        privateKeyPath: String? = nil,
        privateKeyKeychainLabel: String? = nil,
        runnerName: String,
        extraLabels: [String]?,
        runnerGroup: String? = nil,
        broker: BrokerConfig? = nil
    ) {
        self.appId = appId
        self.organization = organization
        self.repository = repository
        self.privateKeyPath = privateKeyPath
        self.privateKeyKeychainLabel = privateKeyKeychainLabel
        self.runnerName = runnerName
        self.extraLabels = extraLabels
        self.runnerGroup = runnerGroup
        self.broker = broker
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
        commands.append("echo \"Runner configured, starting ~/actions-runner/run.sh\"")
        commands.append("~/actions-runner/run.sh")
        return commands
    }

    /// Broker mode (ADR 0001): a JIT runner (no config.sh, no registration token)
    /// with Sand's job-started admission hook installed read-only outside
    /// `actions-runner` and wired through `.env`, which the workflow cannot
    /// override. The `.env` is written whether or not egress isolation is on.
    ///
    /// The JIT config reaches the runner only via `ACTIONS_RUNNER_INPUT_JITCONFIG`,
    /// read from the SSH session's stdin: it is never in a host process
    /// argument (`ps` on the host) nor in a guest command line. It remains in
    /// the initial environment of `run.sh` and the Listener in the guest
    /// (`docs/broker-api.md` §6.5).
    func brokerScript(allocation: Allocation, jitConfig: String, egress: GuestEgressEnv?, relayPort: Int = NetworkPolicy.guestAdmissionPort) throws -> [GuestCommand] {
        let hook = try AdmissionHook.script(allocationId: allocation.allocationId, nonce: allocation.nonce, relayPort: relayPort)
        var commands = [
            GuestCommand("rm -rf ~/actions-runner && mkdir ~/actions-runner"),
            GuestCommand("tar xzf ~/\(Self.tarballRemotePath) -C ~/actions-runner"),
            GuestCommand("echo \"Runner extracted\"")
        ]
        commands += AdmissionHook.installCommands(script: hook)
        let hookVariable = [("ACTIONS_RUNNER_HOOK_JOB_STARTED", AdmissionHook.guestPath)]
        if let egress {
            commands.append(GuestCommand(egress.runnerDotEnvCommand(extra: hookVariable)))
        } else {
            commands.append(GuestCommand(GuestEgressEnv.dotEnvCommand(variables: hookVariable)))
        }
        commands.append(GuestCommand("echo \"Runner configured (JIT, admission hook installed), starting ~/actions-runner/run.sh\""))
        let prefix = egress.map { "\($0.envPrefix) " } ?? ""
        commands.append(GuestCommand(Self.jitRunCommand(prefix: prefix), stdin: jitConfig + "\n"))
        return commands
    }

    /// Reads the JIT config from stdin into the runner's variable, detaches
    /// stdin, then runs `run.sh`. Exits 97 without starting the runner when
    /// stdin carried nothing.
    static func jitRunCommand(prefix: String) -> String {
        "IFS= read -r SAND_JIT; [ -n \"$SAND_JIT\" ] || { echo 'sand: JIT config missing on stdin' >&2; exit 97; }; "
            + "export ACTIONS_RUNNER_INPUT_JITCONFIG=\"$SAND_JIT\"; unset SAND_JIT; exec </dev/null; "
            + "\(prefix)~/actions-runner/run.sh"
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
