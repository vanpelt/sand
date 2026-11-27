import Foundation

/// Startup helpers shared by `sand run`, `sand doctor` and `sand network preflight`.
enum NetworkStartup {
    static func compiledPolicies(_ config: Config) throws -> [(String, NetworkPolicy)] {
        try config.runners.map { runner in
            (runner.name, try runner.vm.run.network.compile(sshPort: runner.vm.ssh.port))
        }
    }

    /// Runs the full preflight once per distinct policy.
    static func preflight(_ policies: [NetworkPolicy], preflight: NetworkPreflight, includeSSHTools: Bool) async -> [(NetworkPolicy, [PreflightCheck])] {
        var seen = Set<String>()
        var results: [(NetworkPolicy, [PreflightCheck])] = []
        for policy in policies where seen.insert(policy.policyHash).inserted {
            results.append((policy, await preflight.run(policy: policy, includeSSHTools: includeSSHTools)))
        }
        return results
    }

    static func failureMessage(_ failures: [PreflightCheck]) -> String {
        var lines = ["Network preflight failed; no VM was cloned or booted (sand never falls back to shared networking):"]
        lines.append(contentsOf: failures.map { "  - \($0.name): \($0.detail)" })
        let remediation = failures.compactMap(\.remediation).first
        if let remediation {
            lines.append(remediation)
        }
        if remediation?.contains("mode: shared") != true {
            lines.append("To opt out of isolation explicitly: set vm.run.network: { mode: shared } (unrestricted host/LAN/VPN reach).")
        }
        return lines.joined(separator: "\n")
    }
}
