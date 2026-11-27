import ArgumentParser
import Foundation

@available(macOS 15.0, *)
struct NetworkCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "network",
        abstract: "Inspect and debug VM network policies.",
        subcommands: [Explain.self, Proxy.self, Preflight.self]
    )

    static func loadPolicy(configPath: String, runner: String?) throws -> (Config.RunnerConfig, NetworkPolicy) {
        let config = try Config.load(path: configPath)
        let selected: Config.RunnerConfig?
        if let runner {
            selected = config.runners.first { $0.name == runner }
        } else {
            selected = config.runners.first
        }
        guard let runnerConfig = selected else {
            throw ValidationError("No runner \(runner ?? "") in \(configPath).")
        }
        let policy = try runnerConfig.vm.run.network.compile(sshPort: runnerConfig.vm.ssh.port)
        return (runnerConfig, policy)
    }

    struct Explain: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Print each runner's compiled network policy and hash.")

        @Option(name: .shortAndLong)
        var config: String = Config.defaultPath

        func run() async throws {
            let loaded = try Config.load(path: config)
            for runner in loaded.runners {
                print("runner \(runner.name):")
                let policy = try runner.vm.run.network.compile(sshPort: runner.vm.ssh.port)
                for line in policy.explain() {
                    print("  \(line)")
                }
            }
        }
    }

    struct Proxy: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "Run a runner's egress proxy standalone on loopback (development and live testing)."
        )

        @Option(name: .shortAndLong)
        var config: String = Config.defaultPath
        @Option(help: "Runner name (default: the first runner).")
        var runner: String?
        @Option(help: "Loopback address to listen on, 127.0.0.1:PORT.")
        var listen: String = "127.0.0.1:18080"
        @OptionGroup
        var logLevel: LogLevelOptions

        func run() async throws {
            let parts = listen.split(separator: ":")
            guard parts.count == 2, parts[0] == "127.0.0.1", let port = UInt16(parts[1]) else {
                throw ValidationError("--listen must be 127.0.0.1:PORT; the proxy never binds a non-loopback address.")
            }
            let (_, policy) = try NetworkCommand.loadPolicy(configPath: config, runner: runner)
            guard let egress = policy.egress else {
                throw ValidationError("Runner policy \(policy.name) has no egress proxy (only profile: github does).")
            }
            let logger = Logger(label: "network.proxy", minimumLevel: logLevel.resolvedLevel(), sink: try logLevel.makeLogFileSink())
            let audit = NetworkAudit(logger: logger, file: try logLevel.resolvedLogFile().map { try AuditFileSink(path: AuditFileSink.path(nextTo: $0)) })
            audit.emit("network.policy.compiled", ["hash": policy.policyHash, "profile": policy.name.replacingOccurrences(of: "=", with: ":"), "domains": String(egress.rules.count)])
            let proxy = EgressProxy(
                policy: egress,
                destinationGuard: DestinationGuard(hostFacts: HostFacts.current()),
                resolver: SystemHostResolver(),
                audit: audit
            )
            let bound = try await proxy.start(port: port)
            print("egress proxy listening on 127.0.0.1:\(bound) (policy \(policy.policyHash.prefix(12))); Ctrl-C to stop")
            while !proxy.hasFailed {
                try await Task.sleep(nanoseconds: 1_000_000_000)
            }
            throw ExitCode(1)
        }
    }

    struct Preflight: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Run the host network preflight for a config without booting a VM.")

        @Option(name: .shortAndLong)
        var config: String = Config.defaultPath

        func run() async throws {
            let loaded = try Config.load(path: config)
            let policies = try NetworkStartup.compiledPolicies(loaded)
            var failed = false
            for (policy, checks) in await NetworkStartup.preflight(policies.map(\.1), preflight: NetworkPreflight(processRunner: SystemProcessRunner()), includeSSHTools: true) {
                print("policy \(policy.name) (hash \(policy.policyHash.prefix(12))):")
                for check in checks {
                    print("  " + check.line.replacingOccurrences(of: "\n", with: "\n  "))
                }
                failed = failed || !NetworkPreflight.failures(checks).isEmpty
            }
            if failed {
                throw ExitCode(1)
            }
        }
    }
}
