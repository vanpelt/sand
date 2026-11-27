import Foundation

/// Startup helpers shared by `sand run`, `sand doctor` and `sand network preflight`.
enum NetworkStartup {
    /// EX_CONFIG: the host cannot enforce the configured network policy.
    static let exitCode: Int32 = 78

    /// Compiles every runner's policy, resolving `backend: auto` on this host.
    static func compiledPolicies(_ config: Config, preflight: NetworkPreflight) async throws -> [(String, NetworkPolicy)] {
        var policies: [(String, NetworkPolicy)] = []
        for runner in config.runners {
            policies.append((runner.name, try await preflight.compile(runner.vm.run.network, sshPort: runner.vm.ssh.port)))
        }
        return policies
    }

    /// Runs the full preflight once per distinct policy.
    static func preflight(_ policies: [NetworkPolicy], preflight: NetworkPreflight, includeSSHTools: Bool) async -> [(NetworkPolicy, [PreflightCheck])] {
        await preflightWithInspection(policies, preflight: preflight, includeSSHTools: includeSSHTools).map { ($0.0, $0.1) }
    }

    static func preflightWithInspection(_ policies: [NetworkPolicy], preflight: NetworkPreflight, includeSSHTools: Bool) async -> [(NetworkPolicy, [PreflightCheck], TLSInspectionReport?)] {
        var seen = Set<String>()
        var results: [(NetworkPolicy, [PreflightCheck], TLSInspectionReport?)] = []
        for policy in policies where seen.insert(policy.policyHash).inserted {
            let (checks, inspection) = await preflight.runWithInspection(policy: policy, includeSSHTools: includeSSHTools)
            results.append((policy, checks, inspection))
        }
        return results
    }

    /// hostOnly puts every VM on one host-only bridge with no peer isolation.
    static func peerIsolationWarning(_ policies: [(String, NetworkPolicy)]) -> String? {
        let hostOnly = policies.filter { $0.1.isHostOnly }.map(\.0)
        guard hostOnly.count > 1 else { return nil }
        return "runners \(hostOnly.joined(separator: ", ")) use the hostOnly backend concurrently; their VMs share one host-only bridge and can reach each other (no peer-VM isolation). Use backend: softnet (privileged softnet) for peer isolation, or run one VM per host."
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
