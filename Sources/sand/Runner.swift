import Foundation

struct Runner: Sendable {
    let tart: Tart
    let github: GitHubService?
    let provisioner: GitHubProvisioner
    let runnerVersionResolver: GitHubRunnerVersionResolver
    let runnerCache: RunnerCache
    let config: Config.RunnerConfig
    let shutdownCoordinator: VMShutdownCoordinator
    let control: RunnerControl
    let vmName: String
    let network: RunnerNetworkDependencies
    private let logger: Logger
    private let vmLogger: Logger
    private let restartBackoff = RestartBackoff()
    private let enforcementFailures = EnforcementFailureCounter()
    private let sshRetryDelays: [TimeInterval] = [1, 2, 4, 8, 16, 30, 30, 30, 30, 30]
    private static let healthCheckExitMarker = "__SAND_HEALTHCHECK_EXIT_CODE__"

    enum RunnerError: Error {
        case missingGitHub
        case missingScript
        case invalidMountHostPath(String)
        case vmExitedBeforeIP
        case unsupportedRunnerPlatform(String)
        case sshNotReady
    }

    init(
        tart: Tart,
        github: GitHubService?,
        provisioner: GitHubProvisioner,
        runnerVersionResolver: GitHubRunnerVersionResolver,
        runnerCache: RunnerCache,
        config: Config.RunnerConfig,
        shutdownCoordinator: VMShutdownCoordinator,
        control: RunnerControl,
        vmName: String,
        logLabel: String,
        logLevel: LogLevel,
        logSink: LogFileSink?,
        network: RunnerNetworkDependencies? = nil,
        audit: NetworkAudit? = nil,
        inspectionCAs: [InspectionCA] = [],
        pinnedBackend: EnforcementBackend? = nil
    ) {
        self.tart = tart
        self.github = github
        self.provisioner = provisioner
        self.runnerVersionResolver = runnerVersionResolver
        self.runnerCache = runnerCache
        self.config = config
        self.shutdownCoordinator = shutdownCoordinator
        self.control = control
        self.vmName = vmName
        self.logger = Logger(label: "host.\(logLabel)", minimumLevel: logLevel, sink: logSink)
        self.vmLogger = Logger(label: "vm.\(logLabel)", minimumLevel: logLevel, sink: logSink)
        let networkAudit = audit ?? NetworkAudit(logger: Logger(label: "network.\(logLabel)", minimumLevel: logLevel, sink: logSink))
        var dependencies = network ?? .live(processRunner: tart.processRunner, audit: networkAudit)
        if !inspectionCAs.isEmpty {
            dependencies.inspectionCAs = inspectionCAs
        }
        if let pinnedBackend {
            dependencies.pinnedBackend = pinnedBackend
        }
        self.network = dependencies
    }

    func run() async throws {
        if let stopAfter = config.stopAfter {
            guard stopAfter > 0 else {
                return
            }
            // A network enforcement retry (backend died, verification failed, ...) is
            // not a finished iteration: it is retried up to maxEnforcementFailures and
            // then ends sand with exit 78, never with a silent exit 0.
            var completed = 0
            while completed < stopAfter {
                try Task.checkCancellation()
                do {
                    if try await runOnce() == .completed {
                        completed += 1
                    }
                } catch where error is CancellationError || Task.isCancelled {
                    throw CancellationError()
                } catch {
                    logger.error("runOnce failed (vm=\(vmName)): \(String(describing: error))")
                    throw error
                }
            }
            return
        }
        while true {
            // A finished run can schedule a zero backoff, so the backoff sleep alone doesn't see cancellation.
            try Task.checkCancellation()
            do {
                _ = try await runOnce()
            } catch where error is CancellationError || Task.isCancelled {
                // A cancelled tart or GitHub call can surface as its own error type; report it as cancellation, not a failure.
                throw CancellationError()
            } catch let error as NetworkEnforcementError where error.isFatal {
                // Bounded: repeated enforcement failures end sand (exit 78) instead of re-cloning forever.
                logger.error("\(error)")
                await shutdownCoordinator.cleanup(reason: "network enforcement failed")
                throw error
            } catch {
                // A transient failure (e.g. two slots cloning the same image at once) must not
                // retire this slot for good: sand keeps running the other slots, so launchd never restarts it.
                // The next runOnce waits out the backoff, which grows while the same failure repeats.
                _ = await handleStageFailure(error, stage: "runOnce", healthCheckState: nil)
                // No-op when the failing stage already cleaned up; otherwise don't keep the VM through the backoff.
                await shutdownCoordinator.cleanup(reason: "runOnce failed")
            }
        }
    }

    enum IterationOutcome: Equatable {
        /// The VM ran (or could not boot for a reason unrelated to network enforcement).
        case completed
        /// A counted network enforcement failure; the VM was destroyed and will be recreated.
        case enforcementRetry
    }

    /// Thrown by `recordEnforcementFailure` below the limit: unwinds to `runOnce`,
    /// which reports `.enforcementRetry`.
    private struct EnforcementRetry: Error {}

    private func runOnce() async throws -> IterationOutcome {
        let stopAfterLabel = config.stopAfter.map(String.init) ?? "nil"
        logger.debug("runOnce start (vm=\(vmName), stopAfter=\(stopAfterLabel))")
        try await applyRestartBackoffIfNeeded()
        // Compile and re-check the network policy before touching any VM, so an
        // unprepared host never clones or boots (and never falls back to shared NAT).
        // The backend is pinned to the one sand resolved and preflighted at startup.
        let networkPolicy = try await network.preflight.compile(config.vm.run.network, sshPort: config.vm.ssh.port, pinnedBackend: network.pinnedBackend)
        do {
            try await runIteration(networkPolicy: networkPolicy)
            return .completed
        } catch is EnforcementRetry {
            return .enforcementRetry
        } catch let error as NetworkEnforcementError where !error.isFatal && networkPolicy.isIsolated {
            // Every enforcement error counts toward maxEnforcementFailures, even one
            // thrown from a path that did not record it itself.
            await shutdownCoordinator.cleanup(reason: "network enforcement failed")
            do {
                try await recordEnforcementFailure(policy: networkPolicy, stage: "run", reason: Self.enforcementReason(error), detail: String(describing: error))
            } catch is EnforcementRetry {
                return .enforcementRetry
            }
        }
    }

    private func runIteration(networkPolicy: NetworkPolicy) async throws {
        let name = vmName
        let vm = config.vm
        let provisionerConfig = config.provisioner
        let source = vm.source.resolvedSource
        if networkPolicy.isIsolated {
            let failures = NetworkPreflight.failures(await network.preflight.perVM(policy: networkPolicy))
            if !failures.isEmpty {
                network.audit.emit("network.preflight.failed", level: .error, [
                    "stage": "per-vm",
                    "checks": failures.map(\.name).joined(separator: ",")
                ])
                logger.error("\(NetworkEnforcementError.preflightFailed(failures))")
                try await recordEnforcementFailure(
                    policy: networkPolicy, stage: "per-vm-preflight", reason: "preflight",
                    detail: failures.map { "\($0.name): \($0.detail)" }.joined(separator: "; ")
                )
            }
        } else {
            network.audit.emit("network.shared.unrestricted", level: .warning, ["vm": name])
        }
        if vm.source.type == .oci {
            logger.info("prepare source \(source)")
            do {
                try await tart.prepare(source: source)
            } catch {
                logger.error("prepare source \(source) failed: \(String(describing: error))")
                throw error
            }
        } else {
            logger.info("local source \(source); skipping registry pull")
        }
        do {
            if try await tart.isRunning(name: name) {
                logger.info("VM \(name) already running, stopping before boot")
                try await tart.stop(name: name)
            }
        } catch {
            logger.warning("preflight cleanup failed: \(String(describing: error))")
        }
        // Before cloning, so a bad mount path doesn't leave a cloned VM behind on every retry.
        let directoryMounts = try buildDirectoryMounts(vm: vm)
        let runOptions = Tart.RunOptions(
            directoryMounts: directoryMounts,
            noAudio: vm.hardware?.audio == false,
            noGraphics: vm.run.noGraphics,
            noClipboard: vm.run.noClipboard,
            nested: vm.run.nested,
            rootDiskOpts: vm.run.rootDiskOpts,
            network: networkPolicy
        )
        let session = VMNetworkSession(policy: networkPolicy, dependencies: network, processRunner: tart.processRunner, logger: logger)
        var bootAttempt = 0
        var booted: (tartRun: ProcessHandle, ip: String, ssh: SSHClient)?
        while booted == nil {
            bootAttempt += 1
            guard let result = try await bootVM(name: name, source: source, vm: vm, runOptions: runOptions, session: session) else {
                return
            }
            // softnet picks the VM subnet; if it collides with a host route (e.g. a
            // VPN's 172.16/16 carrying the steered GitHub fronts), recreate the VM.
            if let conflict = await session.subnetConflict(vmIP: result.ip) {
                logger.warning("VM subnet conflict (attempt \(bootAttempt)/\(network.maxSubnetAttempts)): \(conflict); recreating VM")
                await shutdownCoordinator.cleanup(reason: "VM subnet overlaps a host route")
                if bootAttempt >= network.maxSubnetAttempts {
                    try await recordEnforcementFailure(policy: networkPolicy, stage: "boot", reason: "subnet-overlap", detail: conflict)
                }
                continue
            }
            booted = result
        }
        guard let (tartRun, ip, ssh) = booted else { return }
        let healthCheckState = HealthCheckState()
        if networkPolicy.isIsolated {
            do {
                try await session.establish(ssh: ssh, vmIP: ip)
            } catch {
                logger.error("\(String(describing: error)); destroying VM without registering a runner")
                await session.teardown()
                await shutdownCoordinator.cleanup(reason: "network enforcement not verified")
                try await recordEnforcementFailure(policy: networkPolicy, stage: "establish", reason: Self.enforcementReason(error), detail: String(describing: error))
            }
        }
        // From here until teardown, losing any enforcement component (or tart itself)
        // ends the job: stop and delete the VM and deregister the runner at once.
        let lost = LostEnforcement()
        await session.startWatchdog(tartRun: tartRun, vmIP: ip) { [logger, control, shutdownCoordinator] component in
            guard await !shutdownCoordinator.isCleaningUp() else { return false }
            // Recorded first: the provisioner returns as soon as it is terminated below.
            lost.set(component)
            logger.error("network enforcement lost (\(component)); stopping VM")
            await healthCheckState.markFailed(message: "network enforcement lost: \(component)")
            await control.terminateProvisioning()
            await shutdownCoordinator.cleanup(reason: "network enforcement lost: \(component)")
            return true
        }
        if let env = session.guestEnv {
            logger.info("configure guest proxy settings (usability only; enforcement is host-side)")
            do {
                let result = try await execWithRetry(command: env.guestSetupCommand, ssh: ssh, stage: "guest proxy setup")
                logIfNonEmpty(label: "guest proxy setup", text: result?.stdout ?? "")
            } catch {
                await session.teardown()
                await shutdownCoordinator.cleanup(reason: "guest proxy setup failed")
                try await recordLossIfAny(lost, policy: networkPolicy)
                throw error
            }
        }
        if !session.inspectionCAs.isEmpty {
            do {
                try await installInspectionTrust(session.inspectionCAs, ssh: ssh, policy: networkPolicy)
            } catch {
                logger.error("\(String(describing: error)); destroying VM without registering a runner")
                await session.teardown()
                await shutdownCoordinator.cleanup(reason: "inspection CA trust failed")
                try await recordLossIfAny(lost, policy: networkPolicy)
                try await recordEnforcementFailure(policy: networkPolicy, stage: "inspection-ca", reason: Self.enforcementReason(error), detail: String(describing: error))
            }
        }
        do {
            try await runStages(
                name: name, vm: vm, provisionerConfig: provisionerConfig, ssh: ssh,
                healthCheckState: healthCheckState, egress: session.guestEnv
            )
        } catch {
            await session.teardown()
            await shutdownCoordinator.cleanup(reason: "runOnce failed")
            try await recordLossIfAny(lost, policy: networkPolicy)
            throw error
        }
        await session.teardown()
        try await recordLossIfAny(lost, policy: networkPolicy)
        // Consecutive: only a job that ran to the end with enforcement intact resets
        // the count, so a component that dies during every job still reaches the limit.
        if networkPolicy.isIsolated {
            await enforcementFailures.reset()
        }
    }

    /// Enforcement lost while the job ran (the watchdog already stopped and deleted
    /// the VM). Counted like any other enforcement failure; with `stopAfter` the
    /// interrupted job cannot be retried, so sand exits 78 at once.
    private func recordLossIfAny(_ lost: LostEnforcement, policy: NetworkPolicy) async throws {
        guard let component = lost.component, !Task.isCancelled else { return }
        try await recordEnforcementFailure(
            policy: policy, stage: "job", reason: "lost-\(component)",
            detail: "network enforcement component \(component) failed while the job ran",
            fatal: config.stopAfter != nil ? .enforcementLost(component: component) : nil
        )
    }

    /// Clone and boot the VM, then wait for its IP and SSH. Returns nil (after
    /// scheduling a restart and cleaning up) when the VM never became reachable
    /// for a reason unrelated to network enforcement; a network backend failure
    /// is counted (and unwinds) instead.
    private func bootVM(name: String, source: String, vm: Config.VM, runOptions: Tart.RunOptions, session: VMNetworkSession) async throws -> (tartRun: ProcessHandle, ip: String, ssh: SSHClient)? {
        // Leftover from a crash or a failed clone: tart clone refuses to overwrite it.
        do {
            try await tart.delete(name: name)
            logger.warning("deleted leftover VM \(name)")
        } catch {
            logger.debug("delete leftover VM \(name) skipped: \(String(describing: error))")
        }
        logger.info("clone VM \(name) from \(source)")
        do {
            try await tart.clone(source: source, name: name)
        } catch {
            logger.error("clone VM \(name) from \(source) failed: \(String(describing: error))")
            throw error
        }
        await shutdownCoordinator.activate(name: name)
        do {
            try await applyVMConfigIfNeeded(name: name, vm: vm)
        } catch {
            await shutdownCoordinator.cleanup(reason: "apply VM config failed")
            throw error
        }
        logRunOptions(name: name, options: runOptions)
        logger.info("boot VM \(name)")
        let tartRun: ProcessHandle
        do {
            tartRun = try tart.run(name: name, options: runOptions)
        } catch {
            logger.error("tart run failed for \(name): \(String(describing: error))")
            await shutdownCoordinator.cleanup(reason: "tart run failed")
            throw error
        }
        Task {
            await logTartRunExit(tartRun, name: name)
        }
        logger.info("wait for VM IP")
        let ip: String
        do {
            ip = try await resolveIP(name: name, whileRunning: tartRun)
        } catch {
            logger.warning("resolve VM IP failed; scheduling restart: \(String(describing: error))")
            // Sample before cleanup: cleanup stops tart, which would look like an early exit.
            let exitedEarly = await tartRun.hasExited()
            await shutdownCoordinator.cleanup(reason: "resolve VM IP failed")
            if exitedEarly {
                try await recordEarlyTartExit(tartRun, policy: runOptions.network, stage: "before-ip")
            } else if runOptions.network.isIsolated, !(error is CancellationError), !Task.isCancelled {
                // tart kept running but the isolated network never leased an address
                // (e.g. --net-host without DHCP): an enforcement failure, not a retry forever.
                try await recordEnforcementFailure(policy: runOptions.network, stage: "before-ip", reason: "no-ip", detail: String(describing: error))
            }
            await scheduleRestart(reason: .ipNotReady)
            return nil
        }
        logger.info("VM IP \(ip)")
        await logVMStatusAfterBoot(name: name)
        let initial = SSHClient(processRunner: tart.processRunner, host: ip, config: vm.ssh)
        // Under softnet the first lease can be stale; only an IP that answers SSH is trusted.
        guard let ssh = await waitForSSH(ssh: initial, tartRun: tartRun, refreshIP: runOptions.network.usesSoftnet) else {
            logger.debug("waitForSSH failed; scheduling restart")
            let exitedEarly = await tartRun.hasExited()
            await shutdownCoordinator.cleanup(reason: "ssh not ready")
            if exitedEarly {
                try await recordEarlyTartExit(tartRun, policy: runOptions.network, stage: "before-ssh")
            }
            await scheduleRestart(reason: .sshNotReady)
            return nil
        }
        return (tartRun, ssh.host, ssh)
    }

    /// Under an isolated policy, tart exiting before the VM is reachable is a
    /// network enforcement failure (softnet died, --net-host failed, ...).
    private func recordEarlyTartExit(_ tartRun: ProcessHandle, policy: NetworkPolicy, stage: String) async throws {
        guard policy.isIsolated, !Task.isCancelled else { return }
        let stderr: String
        do {
            stderr = try await tartRun.waitAsync(terminateOnCancel: false).stderr
        } catch let ProcessRunnerError.failed(exitCode, _, message, _) {
            stderr = "exit \(exitCode): \(message)"
        } catch {
            stderr = String(describing: error)
        }
        let reason = NetworkBackendFailure.classify(stderr: stderr, backend: policy.backend)
        let detail = NetworkBackendFailure.summary(stderr)
        logger.error("tart exited \(stage) under network policy \(policy.label) (\(reason)): \(detail)")
        try await recordEnforcementFailure(policy: policy, stage: stage, reason: reason, detail: detail)
    }

    /// The single place enforcement failures are counted. Never returns: below the
    /// limit it schedules a backoff and throws `EnforcementRetry` (the VM is
    /// recreated with the same policy); at the limit, or when `fatal` is given, it
    /// throws a fatal `NetworkEnforcementError` (exit 78). The caller must already
    /// have destroyed the VM.
    private func recordEnforcementFailure(policy: NetworkPolicy, stage: String, reason: String, detail: String, fatal: NetworkEnforcementError? = nil) async throws -> Never {
        let attempt = await enforcementFailures.record()
        let limit = max(1, policy.options.maxEnforcementFailures)
        let final = fatal != nil || attempt >= limit
        network.audit.emit("network.enforcement.failed", level: .error, [
            "vm": vmName,
            "stage": stage,
            "reason": reason,
            "backend": policy.backend?.rawValue ?? "none",
            "attempt": String(attempt),
            "max": String(limit),
            "final": String(final),
            "detail": detail,
            "policy_hash": policy.policyHash
        ])
        if let fatal {
            throw fatal
        }
        if final {
            throw NetworkEnforcementError.gaveUp(attempts: attempt, last: "\(stage) \(reason): \(detail)")
        }
        logger.warning("network enforcement failure \(attempt)/\(limit) (\(reason)); retrying with the same policy")
        await scheduleRestart(reason: .stageFailed("network enforcement"))
        throw EnforcementRetry()
    }

    static func enforcementReason(_ error: Error) -> String {
        guard let error = error as? NetworkEnforcementError else { return "establish-error" }
        switch error {
        case .preflightFailed: return "preflight"
        case .subnetOverlap: return "subnet-overlap"
        case .tunnelFailed: return "tunnel"
        case .verificationFailed: return "guest-verification"
        case .hostListenersDenied: return "host-listeners"
        case let .backendFailed(reason, _): return reason
        case .inspectionTrustFailed: return "inspection-ca"
        case let .enforcementLost(component): return "lost-\(component)"
        case .gaveUp: return "gave-up"
        }
    }

    /// `tlsInspection: trustHostCA`: install the public CA certificate(s) and the
    /// combined bundle before any workflow code runs.
    private func installInspectionTrust(_ authorities: [InspectionCA], ssh: SSHClient, policy: NetworkPolicy) async throws {
        logger.info("trust host TLS-inspection CA in the guest: \(authorities.map { "\($0.subject) sha256=\($0.sha256)" }.joined(separator: "; "))")
        let result = try await execWithRetry(command: GuestInspectionTrust.installCommand(authorities), ssh: ssh, stage: "inspection CA trust")
        let output = result?.stdout ?? ""
        for line in output.split(whereSeparator: \.isNewline) where line.hasPrefix("WARN") {
            logger.warning("guest inspection CA: \(line)")
        }
        guard output.contains(GuestInspectionTrust.okMarker) else {
            network.audit.emit("network.tls.inspection.trusted", level: .error, ["vm": vmName, "result": "failed", "policy_hash": policy.policyHash])
            throw NetworkEnforcementError.inspectionTrustFailed(output.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        network.audit.emit("network.tls.inspection.trusted", level: .warning, [
            "vm": vmName,
            "ca_sha256": authorities.map(\.sha256).joined(separator: ","),
            "ca_subject": authorities.map(\.subject).joined(separator: ","),
            "keychain": output.contains("WARN") ? "partial" : "ok",
            "policy_hash": policy.policyHash
        ])
    }

    private func runStages(
        name: String,
        vm: Config.VM,
        provisionerConfig: Config.Provisioner,
        ssh: SSHClient,
        healthCheckState: HealthCheckState,
        egress: GuestEgressEnv?
    ) async throws {
        if let preRun = config.preRun {
            logger.info("run preRun")
            logScript(preRun)
            do {
                let result = try await execWithRetry(command: preRun, ssh: ssh, stage: "preRun")
                if let result {
                    logIfNonEmpty(label: "stdout", text: result.stdout)
                    logIfNonEmpty(label: "stderr", text: result.stderr)
                }
                logger.info("preRun finished")
            } catch {
                if await handleStageFailure(error, stage: "preRun", healthCheckState: healthCheckState) {
                    await shutdownCoordinator.cleanup(reason: "preRun failed")
                    return
                }
                await shutdownCoordinator.cleanup(reason: "preRun failed")
                throw error
            }
        }
        logger.debug("healthCheck task preparing (vm=\(name))")
        let healthCheckTask = startHealthCheck(
            healthCheck: config.healthCheck ?? .standard,
            vmName: name,
            ssh: vm.ssh,
            control: control,
            state: healthCheckState
        )
        await control.setHealthCheckTask(healthCheckTask)
        func stopHealthCheck(_ task: Task<Void, Never>) async {
            logger.debug("healthCheck task cancel requested")
            task.cancel()
            await control.clearHealthCheckTask()
        }
        do {
            switch provisionerConfig.type {
            case .script:
                guard let run = provisionerConfig.script?.run else {
                    throw RunnerError.missingScript
                }
                logger.info("run script provisioner")
                let outcome = await runProvisionerCommands([run], ssh: ssh, healthCheckState: healthCheckState)
                switch outcome {
                case .completed:
                    logger.info("script provisioner finished")
                case let .failed(error):
                    if await handleStageFailure(error, stage: "provisioner", healthCheckState: healthCheckState) {
                        await stopHealthCheck(healthCheckTask)
                        await shutdownCoordinator.cleanup(reason: "provisioner failed")
                        return
                    }
                    await stopHealthCheck(healthCheckTask)
                    await shutdownCoordinator.cleanup(reason: "provisioner failed")
                    throw error
                case let .healthCheckFailed(message):
                    await scheduleRestart(reason: .healthCheckFailed(message))
                    await stopHealthCheck(healthCheckTask)
                    await shutdownCoordinator.cleanup(reason: "health check failed: \(message)")
                    return
                }
            case .github:
                guard let github, let githubConfig = provisionerConfig.github else {
                    throw RunnerError.missingGitHub
                }
                logger.info("run github provisioner")
                let credentials = try await github.runnerRegistrationCredentials()
                let token = credentials.runnerToken
                let runnerName = GitHubProvisioner.uniqueRunnerName(base: githubConfig.runnerName)
                logger.info("register runner as \(runnerName)")
                await shutdownCoordinator.setDeregistration { [github, logger] in
                    do {
                        if try await github.deleteRunner(named: runnerName) {
                            logger.info("deregistered runner \(runnerName)")
                        }
                    } catch {
                        logger.warning("failed to deregister runner \(runnerName): \(String(describing: error))")
                    }
                }
                try await installRunnerTarball(ssh: ssh, authToken: credentials.installationToken)
                let commands = provisioner.script(
                    config: githubConfig,
                    runnerName: runnerName,
                    runnerToken: token,
                    egress: egress
                )
                let outcome = await runProvisionerCommands(commands, ssh: ssh, healthCheckState: healthCheckState, secrets: [token])
                switch outcome {
                case .completed:
                    logger.warning("github provisioner completed; runner exited, restarting VM")
                    await scheduleRestart(reason: .provisionerExited)
                    await stopHealthCheck(healthCheckTask)
                    await shutdownCoordinator.cleanup(reason: "provisioner exited")
                    return
                case let .failed(error):
                    if await handleStageFailure(error, stage: "provisioner", healthCheckState: healthCheckState) {
                        await stopHealthCheck(healthCheckTask)
                        await shutdownCoordinator.cleanup(reason: "provisioner failed")
                        return
                    }
                    await stopHealthCheck(healthCheckTask)
                    await shutdownCoordinator.cleanup(reason: "provisioner failed")
                    throw error
                case let .healthCheckFailed(message):
                    await scheduleRestart(reason: .healthCheckFailed(message))
                    await stopHealthCheck(healthCheckTask)
                    await shutdownCoordinator.cleanup(reason: "health check failed: \(message)")
                    return
                }
            }
        } catch {
            if await handleStageFailure(error, stage: "provisioner", healthCheckState: healthCheckState) {
                await stopHealthCheck(healthCheckTask)
                await shutdownCoordinator.cleanup(reason: "provisioner failed")
                return
            }
            await stopHealthCheck(healthCheckTask)
            await shutdownCoordinator.cleanup(reason: "provisioner failed")
            throw error
        }
        if let postRun = config.postRun {
            logger.info("run postRun")
            logScript(postRun)
            do {
                let result = try await execWithRetry(command: postRun, ssh: ssh, stage: "postRun")
                if let result {
                    logIfNonEmpty(label: "stdout", text: result.stdout)
                    logIfNonEmpty(label: "stderr", text: result.stderr)
                }
                logger.info("postRun finished")
            } catch {
                if await handleStageFailure(error, stage: "postRun", healthCheckState: healthCheckState) {
                    await stopHealthCheck(healthCheckTask)
                    await shutdownCoordinator.cleanup(reason: "postRun failed")
                    return
                }
                await stopHealthCheck(healthCheckTask)
                await shutdownCoordinator.cleanup(reason: "postRun failed")
                throw error
            }
        }
        if let message = await healthCheckState.failureMessage() {
            await scheduleRestart(reason: .healthCheckFailed(message))
            await stopHealthCheck(healthCheckTask)
            await shutdownCoordinator.cleanup(reason: "health check failed: \(message)")
            return
        }
        await restartBackoff.reset()
        await stopHealthCheck(healthCheckTask)
        await shutdownCoordinator.cleanup(reason: "runOnce complete")
        logger.debug("runOnce complete (vm=\(vmName))")
    }

    private func applyVMConfigIfNeeded(name: String, vm: Config.VM) async throws {
        let hardware = vm.hardware
        let display: Tart.Display? = hardware?.display.map {
            Tart.Display(width: $0.width, height: $0.height, unit: $0.unit?.rawValue)
        }
        let displayRefit = hardware?.display?.refit
        let memoryMb = hardware?.ramGb.map { $0 * 1024 }
        let cpuCores = hardware?.cpuCores
        let diskSizeGb = vm.diskSizeGb
        guard cpuCores != nil || memoryMb != nil || display != nil || displayRefit != nil || diskSizeGb != nil else {
            return
        }
        try await tart.set(
            name: name,
            cpuCores: cpuCores,
            memoryMb: memoryMb,
            display: display,
            displayRefit: displayRefit,
            diskSizeGb: diskSizeGb
        )
    }

    private func installRunnerTarball(ssh: SSHClient, authToken: String) async throws {
        let platform = try await resolveRunnerPlatform(ssh: ssh)
        let directory = config.vm.cache?.hostPath ?? Config.expandPath(Config.Cache.defaultHostPath)
        try ensureDirectoryExists(directory)
        let tarball: String
        do {
            let release = try await runnerVersionResolver.latestRelease(authToken: authToken)
            let asset = RunnerAsset(platform: platform, version: release.version)
            guard let digest = release.digests[asset.name] else {
                throw RunnerCacheError.missingDigest(asset.name)
            }
            tarball = try await runnerCache.verifiedTarball(directory: directory, asset: asset, digest: digest)
            logger.info("runner \(release.version) verified at \(tarball)")
        } catch {
            guard let cached = RunnerCache.newestVerifiedTarball(directory: directory, platform: platform) else {
                logger.error("failed to obtain a verified Actions runner: \(String(describing: error))")
                throw error
            }
            logger.warning("failed to obtain the latest Actions runner; using verified cached \(cached.version): \(String(describing: error))")
            tarball = cached.path
        }
        _ = try await ssh.copy(localPath: tarball, remotePath: GitHubProvisioner.tarballRemotePath)
    }

    private func resolveRunnerPlatform(ssh: SSHClient) async throws -> String {
        let output = try await execWithRetry(command: "uname -s; uname -m", ssh: ssh, stage: "runner platform")?.stdout ?? ""
        let lines = output.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
        guard lines.count >= 2, let platform = RunnerAsset.platform(os: lines[0], arch: lines[1]) else {
            throw RunnerError.unsupportedRunnerPlatform(output)
        }
        return platform
    }

    private func waitForSSH(ssh initial: SSHClient, tartRun: ProcessHandle, refreshIP: Bool) async -> SSHClient? {
        var ssh = initial
        var attempt = 0
        var stoppedChecks = 0
        let maxRetries = ssh.config.connectMaxRetries
        var lastStatus: Tart.VMStatus?
        var lastStatusError: String?
        var lastSSHError: String?
        logger.debug("waitForSSH start (vm=\(vmName), maxRetries=\(maxRetries.map(String.init) ?? "nil"))")
        while true {
            if let maxRetries, attempt >= maxRetries {
                let statusLabel = lastStatus.map(statusLabel) ?? "unknown"
                let statusErrorLabel = lastStatusError ?? "none"
                let sshErrorLabel = lastSSHError ?? "none"
                logger.warning("SSH not ready after \(maxRetries) attempts (lastStatus=\(statusLabel), statusError=\(statusErrorLabel), sshError=\(sshErrorLabel)), restarting VM")
                return nil
            }
            attempt += 1
            if await tartRun.hasExited() {
                logger.error("Tart process exited before VM \(vmName) became SSH-ready; aborting startup")
                return nil
            }
            do {
                let status = try await tart.status(name: vmName)
                lastStatus = status
                lastStatusError = nil
                logger.debug("waitForSSH attempt \(attempt): VM status \(statusLabel(status))")
                if status != .running {
                    let reason = status == .missing ? "missing" : "stopped"
                    if status == .missing {
                        logger.warning("VM \(vmName) not running (\(reason)) while waiting for SSH (attempt \(attempt)), restarting VM")
                        return nil
                    }
                    stoppedChecks += 1
                    if stoppedChecks >= 5 {
                        logger.warning("VM \(vmName) not running (\(reason)) after \(stoppedChecks) checks, restarting VM")
                        return nil
                    }
                    logger.info("VM \(vmName) not running (\(reason)) while waiting for SSH (attempt \(attempt)), retrying")
                    do {
                        try await Task.sleep(nanoseconds: 1_000_000_000)
                    } catch {
                        return nil
                    }
                    continue
                }
            } catch {
                lastStatusError = String(describing: error)
                logger.warning("Failed to check VM \(vmName) running state: \(String(describing: error))")
            }
            do {
                try await ssh.checkConnection()
                stoppedChecks = 0
                lastSSHError = nil
                logger.info("SSH ready after \(attempt) attempt(s)")
                return ssh
            } catch {
                lastSSHError = String(describing: error)
                logger.debug("SSH checkConnection failed (attempt \(attempt)): \(String(describing: error))")
                if refreshIP, attempt % 5 == 0, let fresh = try? await tart.ip(name: vmName, wait: 5), fresh != ssh.host {
                    logger.warning("VM \(vmName) IP changed from \(ssh.host) to \(fresh) while waiting for SSH (stale lease); using the new address")
                    ssh = SSHClient(processRunner: ssh.processRunner, host: fresh, config: ssh.config)
                }
                if let maxRetries {
                    logger.info("SSH not ready, retrying in 1s (attempt \(attempt)/\(maxRetries))")
                } else {
                    logger.info("SSH not ready, retrying in 1s (attempt \(attempt))")
                }
                do {
                    try await Task.sleep(nanoseconds: 1_000_000_000)
                } catch {
                    return nil
                }
            }
        }
    }

    private func resolveIP(name: String, whileRunning tartRun: ProcessHandle) async throws -> String {
        try await withThrowingTaskGroup(of: String?.self) { group in
            group.addTask {
                try await resolveIP(name: name)
            }
            group.addTask {
                _ = try? await tartRun.waitAsync(terminateOnCancel: false)
                return nil
            }
            defer {
                group.cancelAll()
            }
            guard let ip = try await group.next() ?? nil else {
                throw RunnerError.vmExitedBeforeIP
            }
            return ip
        }
    }

    private func logTartRunExit(_ tartRun: ProcessHandle, name: String) async {
        do {
            let result = try await tartRun.waitAsync(terminateOnCancel: false)
            logIfNonEmpty(label: "tart run stderr", text: result.stderr)
            logger.info("tart run for \(name) exited with code 0")
        } catch {
            logger.error("tart run for \(name) exited: \(String(describing: error))")
        }
    }

    private func resolveIP(name: String) async throws -> String {
        var attempt = 0
        while true {
            attempt += 1
            do {
                logger.info("resolve VM IP (attempt \(attempt))")
                return try await tart.ip(name: name, wait: 180)
            } catch {
                try Task.checkCancellation()
                logger.warning("resolve VM IP failed (attempt \(attempt)): \(String(describing: error))")
                do {
                    let status = try await tart.status(name: name)
                    logger.warning("VM \(name) status while resolving IP: \(statusLabel(status))")
                } catch {
                    logger.warning("Failed to check VM \(name) status while resolving IP: \(String(describing: error))")
                }
                if attempt >= 3 {
                    logger.error("resolve VM IP failed after \(attempt) attempts; giving up")
                    throw error
                }
                try await Task.sleep(nanoseconds: nanos(from: 5))
            }
        }
    }

    private func resolveHealthCheckIP(name: String, interval: TimeInterval) async -> String? {
        let waitSeconds = max(5, Int(min(interval, 10)))
        do {
            return try await tart.ip(name: name, wait: waitSeconds)
        } catch {
            logger.debug("healthCheck failed to resolve IP: \(String(describing: error))")
            return nil
        }
    }

    private func startHealthCheck(
        healthCheck: Config.HealthCheck,
        vmName: String,
        ssh: Config.SSH,
        control: RunnerControl,
        state: HealthCheckState
    ) -> Task<Void, Never> {
        logger.info("healthCheck starting in \(healthCheck.delay)s")
        return Task {
            if healthCheck.delay > 0 {
                do {
                    try await Task.sleep(nanoseconds: nanos(from: healthCheck.delay))
                } catch {
                    self.logger.debug("healthCheck delay sleep cancelled")
                    return
                }
            }
            guard !Task.isCancelled else {
                self.logger.debug("healthCheck task cancelled before activation")
                return
            }
            logger.info("healthCheck active (interval: \(healthCheck.interval)s)")
            let activationTime = Date()
            var sawSuccess = false
            let startupGrace = max(healthCheck.interval, 10)
            let healthCheckLabel = commandSummary(healthCheck.command)
            let healthCheckDescriptor = healthCheckLabel.isEmpty ? "healthCheck" : "healthCheck (\(healthCheckLabel))"
            logger.info("healthCheck command: \(healthCheck.command)")
            while !Task.isCancelled {
                self.logger.debug("healthCheck tick (vm=\(vmName))")
                do {
                    let status = try await tart.status(name: vmName)
                    self.logger.debug("healthCheck VM status: \(statusLabel(status))")
                    if status != .running {
                        let message: String
                        switch status {
                        case .missing:
                            message = "vm missing"
                        case .stopped:
                            message = "vm stopped"
                        case .running:
                            message = "vm running"
                        }
                        logger.warning("VM \(vmName) not running (\(message)), marking healthCheck failed")
                        await state.markFailed(message: message)
                        await control.terminateProvisioning()
                        return
                    }
                } catch {
                    logger.warning("Failed to check VM \(vmName) running state: \(String(describing: error))")
                }
                do {
                    guard let ip = await resolveHealthCheckIP(name: vmName, interval: healthCheck.interval) else {
                        self.logger.debug("healthCheck failed to resolve IP; retrying")
                        continue
                    }
                    self.logger.debug("healthCheck resolved IP: \(ip)")
                    let probe = SSHClient(processRunner: tart.processRunner, host: ip, config: ssh)
                    let probeCommand = wrapHealthCheckCommand(healthCheck.command)
                    let result = try await probe.exec(command: probeCommand)
                    let output = result?.stdout ?? ""
                    let exitCode = parseHealthCheckExitCode(output: output) ?? 1
                    self.logger.debug("healthCheck exit code \(exitCode)")
                    if exitCode == 0 {
                        sawSuccess = true
                        self.logger.debug("healthCheck success")
                    } else {
                        let filteredOutput = stripHealthCheckMarker(output: output)
                        let outputLabel = healthCheckLabel.isEmpty ? "healthCheck output" : "healthCheck output (\(healthCheckLabel))"
                        logIfNonEmpty(label: outputLabel, text: filteredOutput)
                        let message = "exit code \(exitCode)"
                        let inStartupGrace = !sawSuccess && Date().timeIntervalSince(activationTime) < startupGrace
                        if inStartupGrace {
                            logger.warning("\(healthCheckDescriptor) failed with \(message) during startup grace, retrying")
                        } else {
                            logger.warning("\(healthCheckDescriptor) failed with \(message), marking healthCheck failed")
                            await state.markFailed(message: message)
                            await control.terminateProvisioning()
                            return
                        }
                    }
                } catch {
                    logger.warning("\(healthCheckDescriptor) error (will retry): \(String(describing: error))")
                }
                do {
                    try await Task.sleep(nanoseconds: nanos(from: healthCheck.interval))
                } catch {
                    self.logger.debug("healthCheck interval sleep cancelled")
                    return
                }
            }
            self.logger.debug("healthCheck task cancelled (vm=\(vmName))")
        }
    }

    private enum ProvisionerOutcome {
        case completed(ProcessResult)
        case failed(Error)
        case healthCheckFailed(String)
    }

    private enum ProvisionerSequenceOutcome {
        case completed
        case failed(Error)
        case healthCheckFailed(String)
    }

    private func runProvisionerCommands(
        _ commands: [String],
        ssh: SSHClient,
        healthCheckState: HealthCheckState,
        secrets: [String] = []
    ) async -> ProvisionerSequenceOutcome {
        for command in commands {
            let outcome = await runProvisionerCommand(command, ssh: ssh, healthCheckState: healthCheckState, secrets: secrets)
            switch outcome {
            case .completed:
                continue
            case let .failed(error):
                return .failed(error)
            case let .healthCheckFailed(message):
                return .healthCheckFailed(message)
            }
        }
        return .completed
    }

    private func runProvisionerCommand(
        _ command: String,
        ssh: SSHClient,
        healthCheckState: HealthCheckState,
        secrets: [String]
    ) async -> ProvisionerOutcome {
        let displayCommand = Runner.redact(command, secrets: secrets)
        logScript(displayCommand)
        var attempt = 0
        while true {
            do {
                let commandLabel = commandSummary(displayCommand)
                let labeledCommand = commandLabel.isEmpty ? "provisioner command" : "provisioner command (\(commandLabel))"
                logger.debug("\(labeledCommand) starting (attempt \(attempt + 1))")
                let handle = try ssh.start(command: command)
                await control.setProvisioningHandle(handle)
                logger.debug("\(labeledCommand) started; awaiting completion or healthCheck failure")
                let outcome = await awaitProvisionerCommand(handle: handle, healthCheckState: healthCheckState)
                switch outcome {
                case let .completed(result):
                    let stdoutLabel = commandLabel.isEmpty ? "stdout" : "stdout (\(commandLabel))"
                    let stderrLabel = commandLabel.isEmpty ? "stderr" : "stderr (\(commandLabel))"
                    logIfNonEmpty(label: stdoutLabel, text: result.stdout)
                    logIfNonEmpty(label: stderrLabel, text: result.stderr)
                    let completionLabel = commandLabel.isEmpty ? "provisioner command" : "provisioner command (\(commandLabel))"
                    logger.info("\(completionLabel) completed with exit code \(result.exitCode)")
                    if isRunnerCommand(command) {
                        logger.warning("github runner exited with code \(result.exitCode)")
                    }
                    await control.clearProvisioningHandle(handle)
                    return .completed(result)
                case let .failed(error):
                    if await retrySSHIfNeeded(error: error, stage: "provisioner", attempt: &attempt) {
                        await control.clearProvisioningHandle(handle)
                        continue
                    }
                    await control.clearProvisioningHandle(handle)
                    return .failed(error)
                case let .healthCheckFailed(message):
                    logger.warning("healthCheck failed; terminating provisioner command wait: \(message)")
                    await control.terminateProvisioning()
                    Task.detached {
                        _ = try? await handle.waitAsync()
                    }
                    await control.clearProvisioningHandle(handle)
                    return .healthCheckFailed(message)
                }
            } catch {
                if await retrySSHIfNeeded(error: error, stage: "provisioner", attempt: &attempt) {
                    continue
                }
                return .failed(error)
            }
        }
    }

    private func awaitProvisionerCommand(
        handle: ProcessHandle,
        healthCheckState: HealthCheckState
    ) async -> ProvisionerOutcome {
        await withTaskGroup(of: ProvisionerOutcome?.self) { group in
            group.addTask {
                do {
                    let result = try await handle.waitAsync()
                    return .completed(result)
                } catch {
                    return .failed(error)
                }
            }
            group.addTask {
                do {
                    let message = try await healthCheckState.waitForFailure()
                    return .healthCheckFailed(message)
                } catch is CancellationError {
                    return nil
                } catch {
                    return .failed(error)
                }
            }
            while let outcome = await group.next() {
                if let outcome {
                    logger.debug("provisioner outcome received: \(provisionerOutcomeLabel(outcome))")
                    group.cancelAll()
                    return outcome
                }
            }
            return .failed(ProcessRunnerError.invalidCommand)
        }
    }

    static func redact(_ text: String, secrets: [String]) -> String {
        secrets
            .filter { !$0.isEmpty }
            .reduce(text) { $0.replacingOccurrences(of: $1, with: "[REDACTED]") }
    }

    private func wrapHealthCheckCommand(_ command: String) -> String {
        let marker = Runner.healthCheckExitMarker
        return "set +e; (\(command)); code=$?; echo \(marker):$code; exit 0"
    }

    private func parseHealthCheckExitCode(output: String) -> Int? {
        let marker = Runner.healthCheckExitMarker + ":"
        for line in output.split(whereSeparator: \.isNewline).reversed() {
            if line.hasPrefix(marker) {
                let value = line.dropFirst(marker.count)
                return Int(value)
            }
        }
        return nil
    }

    private func stripHealthCheckMarker(output: String) -> String {
        let marker = Runner.healthCheckExitMarker + ":"
        let lines = output.split(whereSeparator: \.isNewline).filter { !$0.hasPrefix(marker) }
        return lines.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func nanos(from seconds: TimeInterval) -> UInt64 {
        if seconds <= 0 {
            return 0
        }
        let nanos = seconds * 1_000_000_000
        if nanos >= Double(UInt64.max) {
            return UInt64.max
        }
        return UInt64(nanos)
    }

    private func execWithRetry(command: String, ssh: SSHClient, stage: String) async throws -> ProcessResult? {
        var attempt = 0
        while true {
            do {
                return try await ssh.exec(command: command)
            } catch {
                if await retrySSHIfNeeded(error: error, stage: stage, attempt: &attempt) {
                    continue
                }
                throw error
            }
        }
    }

    private func retrySSHIfNeeded(error: Error, stage: String, attempt: inout Int) async -> Bool {
        guard shouldRetrySSH(error), attempt < sshRetryDelays.count else {
            return false
        }
        let delay = sshRetryDelays[attempt]
        attempt += 1
        let attemptLabel = "\(attempt)/\(sshRetryDelays.count)"
        if delay > 0 {
            logger.warning("SSH failed during \(stage), retrying in \(delay)s (attempt \(attemptLabel))")
        } else {
            logger.warning("SSH failed during \(stage), retrying (attempt \(attemptLabel))")
        }
        do {
            try await Task.sleep(nanoseconds: nanos(from: delay))
        } catch {
            return false
        }
        return true
    }

    private func shouldRetrySSH(_ error: Error) -> Bool {
        guard let runnerError = error as? ProcessRunnerError else {
            return false
        }
        switch runnerError {
        case let .failed(exitCode, _, _, command):
            guard exitCode == 255 else {
                return false
            }
            return command.first == "sshpass"
        case .invalidCommand:
            return false
        }
    }

    private func scheduleRestart(reason: RestartReason) async {
        logger.debug("restart requested (\(reason))")
        let delay = await restartBackoff.schedule(reason: reason)
        let snapshot = await restartBackoff.snapshot()
        logger.debug("restart backoff state: \(snapshot)")
        if delay > 0 {
            logger.warning("restart scheduled in \(delay)s (\(reason))")
        } else {
            logger.warning("restart scheduled (\(reason))")
        }
    }

    private func applyRestartBackoffIfNeeded() async throws {
        let (delay, reason) = await restartBackoff.takePending()
        guard delay > 0 else {
            logger.debug("restart backoff: none pending")
            return
        }
        if let reason {
            logger.debug("restart backoff pending \(delay)s (\(reason))")
        } else {
            logger.debug("restart backoff pending \(delay)s (no reason)")
        }
        if let reason {
            logger.warning("restart backoff \(delay)s (\(reason))")
        } else {
            logger.warning("restart backoff \(delay)s")
        }
        try await Task.sleep(nanoseconds: nanos(from: delay))
    }

    private func logLines(logger: Logger, _ text: String, level: LogLevel) {
        for line in text.split(whereSeparator: \.isNewline) {
            logger.log(level, "\(line)")
        }
    }

    private func logIfNonEmpty(label: String, text: String) {
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return
        }
        logLines(logger: vmLogger, "[\(label)] \(text)", level: .info)
    }

    private func commandSummary(_ command: String) -> String {
        let trimmed = command.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return ""
        }
        let firstLine = trimmed.split(whereSeparator: \.isNewline).first.map(String.init) ?? ""
        let compact = firstLine.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !compact.isEmpty else {
            return ""
        }
        if compact.count > 80 {
            return String(compact.prefix(77)) + "..."
        }
        return compact
    }

    private func isRunnerCommand(_ command: String) -> Bool {
        let trimmed = command.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return false
        }
        let firstToken = trimmed.split(whereSeparator: \.isWhitespace).first.map(String.init) ?? ""
        guard !firstToken.isEmpty else {
            return false
        }
        return firstToken.hasSuffix("actions-runner/run.sh")
    }

    private func logRunOptions(name: String, options: Tart.RunOptions) {
        logger.info("VM \(name) run options: noGraphics=\(options.noGraphics) noAudio=\(options.noAudio) noClipboard=\(options.noClipboard) nested=\(options.nested) rootDiskOpts=\(options.rootDiskOpts ?? "default") network=\(options.network.name)")
        if options.directoryMounts.isEmpty {
            logger.info("VM \(name) mounts: none")
            return
        }
        for mount in options.directoryMounts {
            let mode = mount.readOnly ? "ro" : "rw"
            logger.info("VM \(name) mount: \(mount.name) <- \(mount.hostPath) (\(mode))")
        }
    }

    private func logVMStatusAfterBoot(name: String) async {
        do {
            let status = try await tart.status(name: name)
            logger.info("VM \(name) status after tart run: \(statusLabel(status))")
        } catch {
            logger.warning("Failed to read VM \(name) status after tart run: \(String(describing: error))")
        }
    }

    private func statusLabel(_ status: Tart.VMStatus) -> String {
        switch status {
        case .missing:
            return "missing"
        case .stopped:
            return "stopped"
        case .running:
            return "running"
        }
    }

    private func logScript(_ script: String) {
        vmLogger.log(.info, "[executing]\n\(script)")
    }

    private func handleStageFailure(_ error: Error, stage: String, healthCheckState: HealthCheckState?) async -> Bool {
        if let healthCheckState, let message = await healthCheckState.failureMessage() {
            logger.debug("\(stage) failed while healthCheck already failed: \(message)")
            await scheduleRestart(reason: .healthCheckFailed(message))
            return true
        }
        logStageFailure(error, stage: stage)
        guard config.stopAfter == nil else {
            logger.debug("\(stage) failed; stopAfter set, not restarting")
            return false
        }
        logger.warning("\(stage) failed, restarting VM")
        await scheduleRestart(reason: .stageFailed(stage))
        return true
    }

    private func logStageFailure(_ error: Error, stage: String) {
        if let runnerError = error as? ProcessRunnerError {
            switch runnerError {
            case let .failed(exitCode, stdout, stderr, _):
                logger.error("\(stage) failed with exit code \(exitCode)")
                logIfNonEmpty(label: "stdout", text: stdout)
                logIfNonEmpty(label: "stderr", text: stderr)
            case .invalidCommand:
                logger.error("\(stage) failed: invalid command")
            }
            return
        }
        logger.error("\(stage) failed: \(String(describing: error))")
    }

    private func provisionerOutcomeLabel(_ outcome: ProvisionerOutcome) -> String {
        switch outcome {
        case .completed:
            return "completed"
        case .failed:
            return "failed"
        case .healthCheckFailed:
            return "healthCheckFailed"
        }
    }

    private func buildDirectoryMounts(vm: Config.VM) throws -> [Tart.DirectoryMount] {
        var mounts: [Tart.DirectoryMount] = []
        for mount in vm.mounts {
            let hostPath = mount.hostPath
            try ensureDirectoryExists(hostPath)
            let name = Config.resolveMountName(hostPath: hostPath, name: mount.name)
            mounts.append(Tart.DirectoryMount(hostPath: hostPath, name: name, readOnly: mount.mode == .ro))
        }
        return mounts
    }

    private func ensureDirectoryExists(_ path: String) throws {
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw RunnerError.invalidMountHostPath(path)
        }
        var isDirectory: ObjCBool = false
        let fileManager = FileManager.default
        if fileManager.fileExists(atPath: trimmed, isDirectory: &isDirectory) {
            guard isDirectory.boolValue else {
                throw RunnerError.invalidMountHostPath(trimmed)
            }
            return
        }
        try fileManager.createDirectory(atPath: trimmed, withIntermediateDirectories: true)
    }
}

private actor HealthCheckState {
    private var failureMessageStorage: String?
    private var waiters: [UUID: CheckedContinuation<String, Error>] = [:]

    func markFailed(message: String) {
        if failureMessageStorage == nil {
            failureMessageStorage = message
            let pending = waiters
            waiters = [:]
            for continuation in pending.values {
                continuation.resume(returning: message)
            }
        }
    }

    func failureMessage() -> String? {
        failureMessageStorage
    }

    func waitForFailure() async throws -> String {
        if let failureMessageStorage {
            return failureMessageStorage
        }
        let waiterID = UUID()
        return try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { continuation in
                if let failureMessageStorage {
                    continuation.resume(returning: failureMessageStorage)
                    return
                }
                waiters[waiterID] = continuation
                if Task.isCancelled {
                    if let continuation = waiters.removeValue(forKey: waiterID) {
                        continuation.resume(throwing: CancellationError())
                    }
                }
            }
        }, onCancel: {
            Task { await cancelWaiter(id: waiterID) }
        })
    }

    private func cancelWaiter(id: UUID) {
        if let continuation = waiters.removeValue(forKey: id) {
            continuation.resume(throwing: CancellationError())
        }
    }
}

/// Consecutive network enforcement failures for one runner slot.
/// The enforcement component the watchdog lost during one VM's job, if any.
private final class LostEnforcement: @unchecked Sendable {
    private let lock = NSLock()
    private var lost: String?

    var component: String? { lock.withLock { lost } }

    func set(_ component: String) {
        lock.withLock {
            if lost == nil { lost = component }
        }
    }
}

private actor EnforcementFailureCounter {
    private var count = 0

    func record() -> Int {
        count += 1
        return count
    }

    func reset() {
        count = 0
    }
}
