import Foundation

struct ConfigValidationIssue: Equatable {
    enum Severity: String {
        case warning
        case error
    }

    let severity: Severity
    let message: String
}

final class ConfigValidator {
    func validate(_ config: Config) -> [ConfigValidationIssue] {
        var issues: [ConfigValidationIssue] = []
        if config.runners.isEmpty {
            issues.append(.init(severity: .error, message: "runners must not be empty."))
            return issues
        }
        issues.append(contentsOf: validateRunners(config.runners))
        return issues
    }

    private func validateRunners(_ runners: [Config.RunnerConfig]) -> [ConfigValidationIssue] {
        var issues: [ConfigValidationIssue] = []
        var seenNames = Set<String>()
        // Each runner's VM is named after the runner and deleted before every clone,
        // so it must never share a name with a local source image. Tart VMs are directories,
        // and macOS volumes are case-insensitive by default, so names are compared lowercased.
        let localSourceNames = Set(runners.compactMap { $0.vm.source.type == .local ? $0.vm.source.name?.lowercased() : nil })

        for runner in runners {
            let trimmedName = runner.name.trimmingCharacters(in: .whitespacesAndNewlines)
            let label = trimmedName.isEmpty ? "runner <unnamed>" : "runner \(trimmedName)"
            if trimmedName.isEmpty {
                issues.append(.init(severity: .error, message: "runner name must not be empty."))
            } else if !seenNames.insert(trimmedName.lowercased()).inserted {
                issues.append(.init(severity: .error, message: "runner name must be unique: \(trimmedName)."))
            }
            if let stopAfter = runner.stopAfter, stopAfter <= 0 {
                issues.append(.init(
                    severity: .warning,
                    message: "\(label): stopAfter is \(stopAfter); sand will exit immediately."
                ))
            }
            var runnerIssues: [ConfigValidationIssue] = []
            if let preRun = runner.preRun, preRun.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                runnerIssues.append(.init(severity: .error, message: "preRun must not be empty when provided."))
            }
            if let postRun = runner.postRun, postRun.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                runnerIssues.append(.init(severity: .error, message: "postRun must not be empty when provided."))
            }
            if localSourceNames.contains(runner.name.lowercased()) {
                runnerIssues.append(.init(severity: .error, message: "runner name must differ from every local vm.source.name."))
            }
            validateVM(runner.vm, issues: &runnerIssues)
            validateProvisioner(runner.provisioner, issues: &runnerIssues)
            if let healthCheck = runner.healthCheck {
                validateHealthCheck(healthCheck, issues: &runnerIssues)
            }
            validateRunnerCache(runner, issues: &runnerIssues)
            issues.append(contentsOf: runnerIssues.map {
                ConfigValidationIssue(
                    severity: $0.severity,
                    message: "\(label): \($0.message)"
                )
            })
        }

        return issues
    }

    private func validateVM(_ vm: Config.VM, issues: inout [ConfigValidationIssue]) {
        switch vm.source.type {
        case .oci:
            if (vm.source.image ?? "").trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                issues.append(.init(severity: .error, message: "vm.source.image is required for OCI sources."))
            }
        case .local:
            if (vm.source.name ?? "").trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                issues.append(.init(severity: .error, message: "vm.source.name is required for local sources."))
            }
        }

        if let ramGb = vm.hardware?.ramGb, ramGb <= 0 {
            issues.append(.init(severity: .error, message: "vm.hardware.ramGb must be greater than 0."))
        }
        if let cpuCores = vm.hardware?.cpuCores, cpuCores <= 0 {
            issues.append(.init(severity: .error, message: "vm.hardware.cpuCores must be greater than 0."))
        }
        if let display = vm.hardware?.display {
            if display.width <= 0 || display.height <= 0 {
                issues.append(.init(severity: .error, message: "vm.hardware.display width/height must be greater than 0."))
            }
        }
        if let diskSizeGb = vm.diskSizeGb, diskSizeGb <= 0 {
            issues.append(.init(severity: .error, message: "vm.diskSizeGb must be greater than 0."))
        }
        if let rootDiskOpts = vm.run.rootDiskOpts, rootDiskOpts.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            issues.append(.init(severity: .error, message: "vm.run.rootDiskOpts must not be empty when set."))
        }
        validateNetwork(vm, issues: &issues)

        if vm.ssh.user.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            issues.append(.init(severity: .error, message: "vm.ssh.user must not be empty."))
        }
        if vm.ssh.password.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            issues.append(.init(severity: .error, message: "vm.ssh.password must not be empty."))
        }
        if vm.ssh.port <= 0 || vm.ssh.port > 65_535 {
            issues.append(.init(severity: .error, message: "vm.ssh.port must be between 1 and 65535."))
        }
        if let connectMaxRetries = vm.ssh.connectMaxRetries, connectMaxRetries <= 0 {
            issues.append(.init(severity: .error, message: "vm.ssh.connectMaxRetries must be greater than 0."))
        }

        for mount in vm.mounts {
            let hostPath = mount.hostPath.trimmingCharacters(in: .whitespacesAndNewlines)
            if hostPath.isEmpty {
                issues.append(.init(severity: .error, message: "vm.mounts.host must not be empty."))
            } else {
                var isDirectory: ObjCBool = false
                if FileManager.default.fileExists(atPath: hostPath, isDirectory: &isDirectory), !isDirectory.boolValue {
                    issues.append(.init(severity: .error, message: "vm.mounts.host must be a directory: \(hostPath)."))
                }
            }
            let resolvedName = Config.resolveMountName(hostPath: mount.hostPath, name: mount.name)
            validateMountName(resolvedName, label: "vm.mounts.name", issues: &issues)
        }
    }


    private func validateNetwork(_ vm: Config.VM, issues: inout [ConfigValidationIssue]) {
        let network = vm.run.network
        func error(_ message: String) {
            issues.append(.init(severity: .error, message: message))
        }
        func warning(_ message: String) {
            issues.append(.init(severity: .warning, message: message))
        }
        let profileOnlyKeysUsed = !network.presets.isEmpty || !network.allowedDomains.isEmpty || !network.allowedCIDRs.isEmpty
        switch network.selection {
        case .mode(.shared):
            warning("vm.run.network.mode is shared: VM has unrestricted host/LAN/VPN/corporate network reach.")
        case .mode(.softnet):
            warning("vm.run.network.mode softnet blocks private ranges, so VPN split-DNS (e.g. BlastShield) GitHub fronts are unreachable; prefer the default profile: github.")
        case .mode(.restricted):
            if network.allowCIDRs.isEmpty {
                error("vm.run.network.restricted requires at least one explicit IPv4 allowCIDR (e.g. a proxy /32).")
            }
            for cidr in network.allowCIDRs where !NetworkPolicy.isAllowedCIDR(cidr) {
                error("vm.run.network.allowCIDRs entry '\(cidr)' must be an IPv4 CIDR with prefix /24 through /32.")
            }
        case .profile(.offline):
            if profileOnlyKeysUsed {
                error("vm.run.network.profile offline does not allow presets, allowedDomains or allowedCIDRs.")
            }
        case .profile(.github):
            if network.verify == .off {
                error("vm.run.network.verify: off is only allowed with profile: offline; guest egress must be verified before registration.")
            }
            for domain in network.allowedDomains {
                do {
                    let rule = try DomainRule.parse(domain)
                    if rule.port == 22 || rule.port == 25 {
                        warning("vm.run.network.allowedDomains entry '\(domain)' opens port \(rule.port); the proxy only forwards TLS, so SSH/SMTP will not work and this is likely a mistake.")
                    }
                } catch {
                    self.appendDomainError(domain, error, issues: &issues)
                }
            }
            for allow in network.allowedCIDRs {
                do {
                    try NetworkConfig.checkDirectCIDR(allow)
                    if allow.allowPrivate {
                        warning("vm.run.network.allowedCIDRs entry \(allow.cidr) uses allowPrivate: true; the guest can reach that private range directly.")
                    } else {
                        warning("vm.run.network.allowedCIDRs entry \(allow.cidr) port \(allow.port) bypasses the egress proxy and its audit log.")
                    }
                } catch let failure {
                    error("vm.run.network.allowedCIDRs: \(failure)")
                }
            }
        }
        if network.mode != nil {
            if profileOnlyKeysUsed || network.verify != nil {
                error("vm.run.network presets, allowedDomains, allowedCIDRs and verify require a profile, not mode.")
            }
        }
        if network.mode != nil {
            if network.backend != nil {
                error("vm.run.network.backend applies to profiles only; mode \(network.mode?.rawValue ?? "") always uses softnet (or shared NAT).")
            }
            if network.hostListeners != nil || !network.acceptedHostListeners.isEmpty || network.tlsInspection != nil || network.ipForwarding != nil {
                error("vm.run.network hostListeners, acceptedHostListeners, tlsInspection and ipForwarding require a profile, not mode.")
            }
        }
        if let path = network.softnetPath {
            if path.contains(":") {
                error("vm.run.network.softnetPath must not contain ':' (tart finds softnet through PATH, which ':' splits).")
            }
            if !path.hasPrefix("/") || (path as NSString).lastPathComponent != "softnet" {
                error("vm.run.network.softnetPath must be an absolute path to a binary named softnet (tart execs `softnet` from PATH), e.g. \(SoftnetDiscovery.managedPath).")
            }
            if path.hasPrefix("/opt/homebrew/") || path.hasPrefix("/usr/local/Cellar/") || path.hasPrefix("/usr/local/Homebrew/") {
                warning("vm.run.network.softnetPath \(path) is a Homebrew location, which your user can write; preflight P12 refuses a privileged softnet there. Install it with deploy/jamf/install-managed-softnet.sh instead.")
            }
        }
        if let digest = network.softnetSHA256, !SoftnetDiscovery.isSHA256(digest) {
            error("vm.run.network.softnetSHA256 must be 64 hex digits (shasum -a 256 of the softnet binary).")
        }
        if network.softnetPath != nil || network.softnetSHA256 != nil {
            if network.mode == .shared {
                error("vm.run.network softnetPath/softnetSHA256 do not apply to mode: shared.")
            } else if network.backendChoice == .hostOnly {
                warning("vm.run.network softnetPath/softnetSHA256 have no effect with backend: hostOnly.")
            }
        }
        if network.profile == .offline, network.tlsInspection != nil {
            error("vm.run.network.tlsInspection applies to profile: github only (offline has no proxy).")
        }
        if network.profile != .github, !network.quietDenies.isEmpty || network.quietOSBackground != nil || network.requireSteering != nil {
            error("vm.run.network quietDenies, quietOSBackground and requireSteering apply to profile: github only (they configure the egress proxy).")
        }
        for entry in network.quietDenies {
            if entry.contains(":") {
                error("vm.run.network.quietDenies entry '\(entry)' must be a hostname pattern without a port.")
                continue
            }
            do {
                _ = try DomainPattern.parse(entry)
            } catch let failure {
                error("vm.run.network.quietDenies entry '\(entry)': \(failure)")
            }
        }
        if !network.allowedCIDRs.isEmpty, network.profile != nil, network.backendChoice != .softnet {
            error("vm.run.network.allowedCIDRs requires backend: softnet; the \(network.backendChoice.rawValue) backend \(network.backendChoice == .auto ? "may resolve to hostOnly, which has" : "has") no direct route off the host.")
        }
        for entry in network.acceptedHostListeners {
            do {
                _ = try HostListenerPattern.parse(entry)
            } catch let failure {
                error("vm.run.network.\(failure)")
            }
        }
        if network.backendChoice == .softnet, network.profile != nil, network.hostListeners != nil || !network.acceptedHostListeners.isEmpty {
            warning("vm.run.network hostListeners/acceptedHostListeners only apply to the hostOnly backend; softnet already blocks guest access to host services.")
        }
        if network.backendChoice == .softnet, network.profile != nil, network.ipForwarding != nil {
            warning("vm.run.network.ipForwarding only applies to the hostOnly backend; softnet filters guest packets before they reach the host's routing.")
        }
        if network.ipForwarding == .accept, network.backendChoice != .softnet {
            warning("vm.run.network.ipForwarding: accept runs hostOnly VMs while host IP forwarding is on: a job with root in the guest can route through the host to anything the host forwards to with a return path (for example a tailnet resolver or a NATing VPN), outside the proxy and the audit log.")
        }
        if network.hostListeners == .warn, !network.acceptedHostListeners.isEmpty {
            warning("vm.run.network.acceptedHostListeners has no effect with hostListeners: warn (every listener is only reported).")
        }
        if network.tlsInspection == .trustHostCA {
            warning("vm.run.network.tlsInspection: trustHostCA installs the host's TLS-inspection CA certificate in the guest when interception is detected; the inspection vendor can then read the job's TLS to intercepted hosts.")
        }
        if let max = network.maxEnforcementFailures, !(1...100).contains(max) {
            error("vm.run.network.maxEnforcementFailures must be between 1 and 100.")
        }
        if network.mode == .shared, network.maxEnforcementFailures != nil {
            error("vm.run.network.maxEnforcementFailures does not apply to mode: shared (nothing is enforced).")
        }
        if network.mode != .restricted, !network.allowCIDRs.isEmpty {
            error("vm.run.network.allowCIDRs is supported only when mode is restricted (use allowedCIDRs with a profile).")
        }
        if network.allowGitHubSSH {
            error("vm.run.network.allowGitHubSSH is reserved; only HTTPS checkout is supported.")
        }
        if network.transport == .gateway {
            error("vm.run.network.transport: gateway is reserved and not implemented; omit it to use the SSH tunnel.")
        }
        guard network.isIsolated else {
            return
        }
        let label = network.label
        if !vm.run.noClipboard {
            if network.mode == .restricted {
                error("vm.run.network.restricted requires vm.run.noClipboard: true.")
            } else {
                warning("vm.run.network \(label) with noClipboard: false shares the host clipboard with the guest.")
            }
        }
        if vm.run.nested {
            error("vm.run.network \(label) requires vm.run.nested: false.")
        }
        if !vm.mounts.isEmpty {
            error("vm.run.network \(label) does not permit host directory mounts.")
        }
        do {
            _ = try network.compile(sshPort: vm.ssh.port)
        } catch let failure {
            // Every individual rule was reported above; this catches anything else.
            if !issues.contains(where: { $0.severity == .error }) {
                error("vm.run.network policy failed to compile: \(failure)")
            }
        }
    }

    private func appendDomainError(_ domain: String, _ failure: Error, issues: inout [ConfigValidationIssue]) {
        issues.append(.init(
            severity: .error,
            message: "vm.run.network.allowedDomains entry rejected: \(failure)."
        ))
    }

    private func validateHealthCheck(_ healthCheck: Config.HealthCheck, issues: inout [ConfigValidationIssue]) {
        if healthCheck.command.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            issues.append(.init(severity: .error, message: "healthCheck.command must not be empty."))
        }
        if healthCheck.interval <= 0 {
            issues.append(.init(severity: .error, message: "healthCheck.interval must be greater than 0."))
        }
        if healthCheck.delay < 0 {
            issues.append(.init(severity: .error, message: "healthCheck.delay must be greater than or equal to 0."))
        }
    }

    private func validateProvisioner(_ provisioner: Config.Provisioner, issues: inout [ConfigValidationIssue]) {
        switch provisioner.type {
        case .script:
            let script = provisioner.script?.run.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if script.isEmpty {
                issues.append(.init(severity: .error, message: "provisioner.config.run must not be empty for script provisioner."))
            }
        case .github:
            guard let github = provisioner.github else {
                issues.append(.init(severity: .error, message: "provisioner.config is required for github provisioner."))
                return
            }
            if github.appId <= 0 {
                issues.append(.init(severity: .error, message: "provisioner.config.appId must be greater than 0."))
            }
            if github.organization.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                issues.append(.init(severity: .error, message: "provisioner.config.organization must not be empty."))
            }
            if github.runnerName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                issues.append(.init(severity: .error, message: "provisioner.config.runnerName must not be empty."))
            }
            switch (github.privateKeyPath, github.privateKeyKeychainLabel) {
            case (let path?, nil):
                if path.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    issues.append(.init(severity: .error, message: "provisioner.config.privateKeyPath must not be empty."))
                } else if !FileManager.default.fileExists(atPath: path) {
                    issues.append(.init(severity: .error, message: "Private key not found at \(path)."))
                }
            case (nil, let label?):
                if label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    issues.append(.init(severity: .error, message: "provisioner.config.privateKeyKeychainLabel must not be empty."))
                }
            default:
                issues.append(.init(
                    severity: .error,
                    message: "provisioner.config requires exactly one of privateKeyPath or privateKeyKeychainLabel."
                ))
            }
            if let repository = github.repository, repository.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                issues.append(.init(severity: .warning, message: "provisioner.config.repository is set but empty."))
            }
            if let runnerGroup = github.runnerGroup {
                if runnerGroup.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    issues.append(.init(severity: .error, message: "provisioner.config.runnerGroup must not be empty when set."))
                }
                if github.repository != nil {
                    issues.append(.init(severity: .error, message: "provisioner.config.runnerGroup requires organization-level registration; remove provisioner.config.repository."))
                }
            }
        }
    }

    private func validateRunnerCache(_ runner: Config.RunnerConfig, issues: inout [ConfigValidationIssue]) {
        guard let cache = runner.vm.cache else {
            return
        }
        if runner.provisioner.type != .github {
            issues.append(.init(
                severity: .warning,
                message: "vm.cache is set but provisioner is not github; cache will be ignored."
            ))
        }
        let hostPath = cache.hostPath.trimmingCharacters(in: .whitespacesAndNewlines)
        if hostPath.isEmpty {
            issues.append(.init(severity: .error, message: "vm.cache.host must not be empty."))
        } else {
            var isDirectory: ObjCBool = false
            if FileManager.default.fileExists(atPath: hostPath, isDirectory: &isDirectory), !isDirectory.boolValue {
                issues.append(.init(
                    severity: .error,
                    message: "vm.cache.host must be a directory: \(hostPath)."
                ))
            }
        }
        if cache.name != nil {
            issues.append(.init(
                severity: .warning,
                message: "vm.cache.name is ignored; the runner cache stays on the host and is copied into each VM."
            ))
        }
    }

    private func validateMountName(_ name: String, label: String, issues: inout [ConfigValidationIssue]) {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            issues.append(.init(severity: .error, message: "\(label) must not be empty."))
            return
        }
        if trimmed.contains("/") {
            issues.append(.init(severity: .error, message: "\(label) must not contain '/'."))
        }
        if trimmed.contains(":") {
            issues.append(.init(severity: .error, message: "\(label) must not contain ':'."))
        }
    }
}
