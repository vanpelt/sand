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

    /// hostOnly does not promise peer isolation. tart 2.42 was observed to give
    /// each concurrent --net-host VM its own bridge (peers unreachable), but
    /// nothing guarantees that across tart/vmnet versions.
    static func peerIsolationWarning(_ policies: [(String, NetworkPolicy)]) -> String? {
        let hostOnly = policies.filter { $0.1.isHostOnly }.map(\.0)
        guard hostOnly.count > 1 else { return nil }
        return "runners \(hostOnly.joined(separator: ", ")) use the hostOnly backend concurrently; peer-VM isolation is not guaranteed (tart may place VMs on separate host-only bridges, as observed with tart 2.42, or on a shared one where they can reach each other). Use backend: softnet (privileged softnet) for enforced peer isolation, or run one VM per host."
    }

    static func failureMessage(_ failures: [PreflightCheck]) -> String {
        var lines = ["Network preflight failed; no VM was cloned or booted (sand never falls back to shared networking):"]
        lines.append(contentsOf: failures.map { "  - \($0.name): \($0.detail)" })
        // Every failed check's fix, not only the first one.
        var remediations: [String] = []
        for remediation in failures.compactMap(\.remediation) where !remediations.contains(remediation) {
            remediations.append(remediation)
        }
        lines.append(contentsOf: remediations)
        if !remediations.contains(where: { $0.contains("mode: shared") }) {
            lines.append("To opt out of isolation explicitly: set vm.run.network: { mode: shared } (unrestricted host/LAN/VPN reach).")
        }
        return lines.joined(separator: "\n")
    }
}
