import ArgumentParser
import Foundation

@available(macOS 15.0, *)
struct NetworkCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "network",
        abstract: "Inspect and debug VM network policies.",
        subcommands: [Explain.self, Proxy.self, Preflight.self, ProbeScript.self, Listeners.self]
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
            let preflight = NetworkPreflight(processRunner: SystemProcessRunner())
            for runner in loaded.runners {
                print("runner \(runner.name):")
                let policy = try await preflight.compile(runner.vm.run.network, sshPort: runner.vm.ssh.port)
                if runner.vm.run.network.backendChoice == .auto {
                    print("  backend: auto resolved to \(policy.backend?.rawValue ?? "none") on this host")
                }
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

    struct ProbeScript: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            commandName: "probe-script",
            abstract: "Print the guest egress probe script (pipe it into a test VM: tart exec -i VM bash -s < probe.sh)."
        )

        @Option(help: "basic or strict.")
        var verify: String = "strict"
        @Flag(help: "Omit the proxied probes (for a VM without the tunnel).")
        var noProxy = false
        @Flag(help: "Print the guest proxy setup command (shell profiles, macOS system proxy) instead.")
        var guestSetup = false
        @Option(help: "hostOnly: the host's bridge address, probed as the gateway when the guest has no default route (e.g. 192.168.128.1).")
        var hostGateway: String?

        func run() async throws {
            if guestSetup {
                print(GuestEgressEnv.standard.guestSetupCommand)
                return
            }
            guard let level = VerifyLevel(rawValue: verify), level != .off else {
                throw ValidationError("--verify must be basic or strict")
            }
            let facts = HostFacts.current()
            let routes = await RouteInspector.current(processRunner: SystemProcessRunner())
            let github = (try? await SystemHostResolver().resolve("github.com")) ?? []
            let targets = GuestEgressVerifier.StrictTargets.derive(facts: facts, routes: routes)
            // hostOnly: include the adversarial routed probes the runner adds.
            let routed = hostGateway == nil ? nil : GuestEgressVerifier.RoutedTargets(
                resolvers: await HostDNSServers.current(processRunner: SystemProcessRunner()),
                tunnelTargets: targets.tunnelTargets,
                forwardingAccepted: false
            )
            let verifier = GuestEgressVerifier(
                level: level,
                directGitHubAddress: github.first(where: \.isIPv4)?.description ?? "140.82.112.3",
                strictTargets: targets,
                expectsProxy: !noProxy,
                backend: hostGateway == nil ? .softnet : .hostOnly,
                hostGateway: hostGateway,
                routed: routed
            )
            print(verifier.script)
        }
    }

    struct Listeners: AsyncParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "List host services a hostOnly VM could reach (bound to all interfaces or to any non-loopback host address; what the post-boot check reports)."
        )

        @Option(help: "The VM's IP (to find the bridge), e.g. from `tart ip VM`.")
        var vmIp: String?
        @Option(help: "The host's bridge address instead of --vm-ip, e.g. 192.168.128.1.")
        var bridgeIp: String?

        func run() async throws {
            var bridge: [IPAddress] = []
            if let vmIp {
                bridge = HostListenerInspector.bridgeAddresses(forVMIP: vmIp)
            }
            if let bridgeIp, let address = IPAddress(bridgeIp) {
                bridge.append(address)
            }
            print("bridge addresses: \(bridge.isEmpty ? "(none)" : bridge.map(\.description).joined(separator: ", "))")
            // A guest that routes via the bridge reaches every non-loopback host address (weak host).
            let reachable = HostListenerInspector.reachableAddresses(bridge: bridge, host: HostFacts.current().interfaceAddresses)
            let result = await HostListenerInspector(processRunner: SystemProcessRunner()).inspect(bridgeAddresses: reachable)
            for listener in result.listeners {
                print("  \(listener)")
            }
            print("\(result.listeners.count) reachable listener(s) (method: \(result.method)); loopback-only sockets (including Sand's proxy) are never reachable")
        }
    }

    struct Preflight: AsyncParsableCommand {
        static let configuration = CommandConfiguration(abstract: "Run the host network preflight for a config without booting a VM.")

        @Option(name: .shortAndLong)
        var config: String = Config.defaultPath

        func run() async throws {
            let loaded = try Config.load(path: config)
            let preflight = NetworkPreflight.live(processRunner: SystemProcessRunner())
            let policies = try await NetworkStartup.compiledPolicies(loaded, preflight: preflight)
            var failed = false
            if let warning = NetworkStartup.peerIsolationWarning(policies) {
                print("warning: \(warning)")
            }
            for (policy, checks) in await NetworkStartup.preflight(policies.map(\.1), preflight: preflight, includeSSHTools: true) {
                print("policy \(policy.label) (hash \(policy.policyHash.prefix(12))):")
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
