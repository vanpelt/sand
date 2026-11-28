import ArgumentParser
import Darwin
import Foundation

@main
@available(macOS 15.0, *)
struct Sand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        subcommands: [Run.self, Destroy.self, Doctor.self, Validate.self, NetworkCommand.self, BrokerCommand.self]
    )
}

@available(macOS 15.0, *)
struct Run: AsyncParsableCommand {
    @Option(name: .shortAndLong)
    var config: String = Config.defaultPath
    @OptionGroup
    var logLevel: LogLevelOptions
    @Flag(name: .long, help: "Validate configuration and prepare VM images without booting.")
    var dryRun: Bool = false

    mutating func run() async throws {
        let level = logLevel.resolvedLevel()
        let logSink = try logLevel.makeLogFileSink()
        let logger = Logger(label: "sand", minimumLevel: level, sink: logSink)
        logger.info("=== sand run start ===")
        let requiredDependencies = dryRun ? ["tart"] : ["tart", "sshpass", "ssh", "scp"]
        let missing = DependencyChecker.missingCommands(requiredDependencies)
        if !missing.isEmpty {
            throw ValidationError("Missing required dependencies in PATH: \(missing.joined(separator: ", ")). Install them and re-run.")
        }
        let config = try Config.load(path: config)
        let validator = ConfigValidator()
        let issues = validator.validate(config)
        let errors = issues.filter { $0.severity == .error }
        if !errors.isEmpty {
            let message = errors.map(\.message).joined(separator: " ")
            throw ValidationError("Config validation failed: \(message)")
        }
        for warning in issues where warning.severity == .warning {
            logger.warning("\(warning.message)")
        }
        let processRunner = SystemProcessRunner()
        let auditFile = try logLevel.resolvedLogFile().map { try AuditFileSink(path: AuditFileSink.path(nextTo: $0)) }
        let audit = NetworkAudit(logger: Logger(label: "network", minimumLevel: level, sink: logSink), file: auditFile)
        // Fail closed before any clone: every distinct policy must pass the full preflight.
        let preflight = NetworkPreflight.live(processRunner: processRunner)
        let policies = try await NetworkStartup.compiledPolicies(config, preflight: preflight)
        for (runnerName, policy) in policies {
            var compiled = [
                "runner": runnerName,
                "hash": policy.policyHash,
                "profile": policy.name.replacingOccurrences(of: "=", with: ":"),
                "backend": policy.backend?.rawValue ?? "none",
                "domains": String(policy.egress?.rules.count ?? 0),
                "tart_args": policy.tartArguments.joined(separator: " ")
            ]
            if let softnet = policy.host.softnet {
                compiled["softnet"] = softnet.resolved
                compiled["softnet_source"] = softnet.source.rawValue
            }
            audit.emit("network.policy.compiled", compiled)
            logger.info("runner \(runnerName): effective network policy \(policy.label) (hash \(policy.policyHash.prefix(12)))")
            if let fallback = policy.host.autoFallback {
                audit.emit("network.backend.fallback", level: fallback.loud ? .warning : .info, [
                    "runner": runnerName, "chosen": "hostOnly", "requested": "auto", "reason": fallback.reason
                ])
                if fallback.loud {
                    logger.warning("runner \(runnerName): WARNING backend auto rejected softnet and uses hostOnly (no host-service or peer-VM isolation): \(fallback.reason)")
                } else {
                    logger.info("runner \(runnerName): backend auto uses hostOnly: \(fallback.reason)")
                }
            }
            if !policy.isIsolated {
                logger.warning("runner \(runnerName): network mode shared: VM has unrestricted host/LAN/VPN/corporate network reach")
            }
        }
        if let warning = NetworkStartup.peerIsolationWarning(policies) {
            logger.warning(warning)
            audit.emit("network.peer.isolation", level: .warning, ["backend": "hostOnly", "runners": policies.filter { $0.1.isHostOnly }.map(\.0).joined(separator: ",")])
        }
        var inspectionCAs: [String: [InspectionCA]] = [:]
        for (policy, checks, inspection) in await NetworkStartup.preflightWithInspection(policies.map(\.1), preflight: preflight, includeSSHTools: !dryRun) {
            let failures = NetworkPreflight.failures(checks)
            for check in checks {
                logger.log(check.status == .failed ? .error : (check.status == .warning ? .warning : .info), "network preflight (\(policy.label)) \(check.line)")
            }
            audit.emit(failures.isEmpty ? "network.preflight.ok" : "network.preflight.failed", level: failures.isEmpty ? .info : .error, [
                "policy": policy.name.replacingOccurrences(of: "=", with: ":"),
                "backend": policy.backend?.rawValue ?? "none",
                "hash": policy.policyHash,
                "failed": failures.map(\.name).joined(separator: ",")
            ])
            if let inspection, inspection.isIntercepted {
                audit.emit("network.tls.inspection", level: .warning, [
                    "hash": policy.policyHash,
                    "mode": policy.options.tlsInspection.rawValue,
                    "hosts": inspection.interceptedHosts.joined(separator: ","),
                    "ca_sha256": inspection.authorities.map(\.sha256).joined(separator: ","),
                    "ca_subject": inspection.authorities.map(\.subject).joined(separator: ",")
                ])
                if policy.options.tlsInspection == .trustHostCA, failures.isEmpty {
                    inspectionCAs[policy.policyHash] = inspection.authorities
                }
            }
            if !failures.isEmpty && !dryRun {
                FileHandle.standardError.write(Data((NetworkStartup.failureMessage(failures) + "\n").utf8))
                throw ExitCode(NetworkStartup.exitCode) // EX_CONFIG: the host is not prepared for the configured policy
            }
        }
        if dryRun {
            for (runnerName, policy) in policies {
                print("runner \(runnerName):")
                for line in policy.explain() {
                    print("  \(line)")
                }
            }
            for (index, runnerConfig) in config.runners.enumerated() {
                let runnerIndex = index + 1
                let runnerName = runnerConfig.name
                let logLabel = runnerName.isEmpty ? "runner\(runnerIndex)" : runnerName
                let tart = Tart(processRunner: processRunner, logger: Logger(label: "tart.\(logLabel)", minimumLevel: level, sink: logSink))
                let source = runnerConfig.vm.source.resolvedSource
                if runnerConfig.vm.source.type == .oci {
                    logger.info("dry-run: prepare source \(source) for \(logLabel)")
                    try await tart.prepare(source: source)
                } else {
                    logger.info("dry-run: local source \(source) for \(logLabel); skipping registry pull")
                }
            }
            logger.info("dry-run complete")
            return
        }

        let provisioner = GitHubProvisioner()
        let runnerVersionResolver = GitHubRunnerVersionResolver()
        let runnerCache = RunnerCache()
        var runners: [Runner] = []
        var cleanupTargets: [VMShutdownCoordinator] = []
        var runnerControls: [RunnerControl] = []
        for (index, runnerConfig) in config.runners.enumerated() {
            let runnerIndex = index + 1
            let runnerName = runnerConfig.name
            let logLabel = runnerName.isEmpty ? "runner\(runnerIndex)" : runnerName
            let tart = Tart(processRunner: processRunner, logger: Logger(label: "tart.\(logLabel)", minimumLevel: level, sink: logSink))
            let shutdownLogger = Logger(label: "sand.shutdown.\(runnerIndex)", minimumLevel: level, sink: logSink)
            let destroyer = VMDestroyer(tart: tart, logger: shutdownLogger)
            let shutdownCoordinator = VMShutdownCoordinator(destroyer: destroyer, logger: shutdownLogger)
            let runnerControl = RunnerControl()
            cleanupTargets.append(shutdownCoordinator)
            runnerControls.append(runnerControl)
            let github = try githubService(for: runnerConfig.provisioner)
            let broker = try brokerRuntime(
                for: runnerConfig.provisioner,
                audit: AdmissionAudit.logging(Logger(label: "admission.\(logLabel)", minimumLevel: level, sink: logSink), file: auditFile)
            )
            let runner = Runner(
                tart: tart,
                github: github,
                provisioner: provisioner,
                runnerVersionResolver: runnerVersionResolver,
                runnerCache: runnerCache,
                config: runnerConfig,
                shutdownCoordinator: shutdownCoordinator,
                control: runnerControl,
                vmName: runnerName,
                logLabel: logLabel,
                logLevel: level,
                logSink: logSink,
                audit: NetworkAudit(logger: Logger(label: "network.\(logLabel)", minimumLevel: level, sink: logSink), file: auditFile),
                inspectionCAs: inspectionCAs[policies[index].1.policyHash] ?? [],
                pinnedBackend: policies[index].1.backend,
                broker: broker
            )
            runners.append(runner)
        }
        let shutdownLogger = Logger(label: "sand.shutdown", minimumLevel: level, sink: logSink)
        let signalHandler = SignalHandler(signals: [SIGINT, SIGTERM], logger: shutdownLogger) {
            let group = DispatchGroup()
            for control in runnerControls {
                group.enter()
                Task {
                    await control.terminateProvisioning()
                    await control.cancelHealthCheck()
                    group.leave()
                }
            }
            for coordinator in cleanupTargets {
                group.enter()
                Task {
                    await coordinator.cleanup(reason: "signal shutdown")
                    group.leave()
                }
            }
            group.wait()
        }
        defer {
            _ = signalHandler
        }
        do {
            try await withThrowingTaskGroup(of: Void.self) { group in
                for runner in runners {
                    group.addTask {
                        try await runner.run()
                    }
                }
                try await group.waitForAll()
            }
        } catch let error as NetworkEnforcementError {
            // A runtime enforcement failure ends sand like a failed preflight (78),
            // after every slot's VM is stopped and deleted. Never a shared-NAT fallback.
            for control in runnerControls {
                await control.terminateProvisioning()
            }
            for coordinator in cleanupTargets {
                await coordinator.cleanup(reason: "network enforcement failed")
            }
            logger.error("\(error)")
            FileHandle.standardError.write(Data(("sand: \(error)\n").utf8))
            throw ExitCode(NetworkStartup.exitCode)
        }
    }

    private func githubService(for provisioner: Config.Provisioner?) throws -> GitHubService? {
        guard let provisioner, provisioner.type == .github, let githubConfig = provisioner.github,
              githubConfig.broker == nil, let appId = githubConfig.appId else {
            // Broker mode holds no GitHub App key.
            return nil
        }
        let auth = try GitHubAuth(
            appId: appId,
            privateKeyPath: githubConfig.privateKeyPath,
            privateKeyKeychainLabel: githubConfig.privateKeyKeychainLabel
        )
        return GitHubService(
            auth: auth,
            session: URLSession.shared,
            organization: githubConfig.organization,
            repository: githubConfig.repository
        )
    }

    private func brokerRuntime(for provisioner: Config.Provisioner?, audit: AdmissionAudit) throws -> BrokerRuntime? {
        guard let provisioner, provisioner.type == .github, let broker = provisioner.github?.broker else {
            return nil
        }
        guard let url = URL(string: broker.url) else {
            throw ValidationError("provisioner.config.broker.url is not a valid URL")
        }
        if let problem = BrokerConfig.urlProblem(broker.url, allowDevelopmentBroker: broker.allowDevelopmentBroker ?? false) {
            throw ValidationError(problem)
        }
        if broker.isDevelopmentBroker {
            FileHandle.standardError.write(Data("WARNING: broker \(broker.url) is a plain-http DEVELOPMENT broker; admission decisions are unauthenticated.\n".utf8))
        }
        let key = try DeviceKey.load(path: broker.deviceKeyPath)
        return BrokerRuntime(client: BrokerClient(baseURL: url, deviceId: broker.deviceId, key: key), deviceId: broker.deviceId, audit: audit)
    }
}
