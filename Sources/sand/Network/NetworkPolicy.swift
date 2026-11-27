import CryptoKit
import Foundation

enum SandBuildInfo {
    static let version = "0.0.0-dev"
}

/// The compiled, enforced network policy for one VM. Produced only by
/// `NetworkConfig.compile`, so every softnet rule it carries was validated.
struct NetworkPolicy: Sendable, Equatable {
    enum Kind: Sendable, Equatable {
        case shared
        case softnet
        case restricted([String])
        case egressProxy(EgressPolicy)
        case offline
    }

    /// Port the guest sees the egress proxy on (forwarded by the SSH reverse tunnel).
    static let guestProxyPort = 3128

    let kind: Kind
    let softnet: SoftnetRuleSet?

    static let shared = NetworkPolicy(kind: .shared, softnet: nil)

    var tartArguments: [String] {
        switch kind {
        case .shared:
            return []
        case .softnet:
            return ["--net-softnet"]
        case .restricted, .egressProxy, .offline:
            return softnet?.tartArguments ?? ["--net-softnet", "--net-softnet-block=0.0.0.0/0"]
        }
    }

    var requiresSoftnet: Bool {
        kind != .shared
    }

    var egress: EgressPolicy? {
        if case let .egressProxy(policy) = kind { return policy }
        return nil
    }

    var name: String {
        switch kind {
        case .shared:
            return "mode=shared"
        case .softnet:
            return "mode=softnet"
        case .restricted:
            return "mode=restricted"
        case .egressProxy:
            return "profile=github"
        case .offline:
            return "profile=offline"
        }
    }

    /// SHA-256 over a canonical encoding of everything that determines
    /// enforcement: tart arguments, domain rules, steered names, verify level,
    /// preset version and the sand version.
    var policyHash: String {
        var canonical: [String: [String]] = [
            "kind": [name],
            "tartArguments": tartArguments,
            "policyVersion": [EgressPreset.policyVersion],
            "sandVersion": [SandBuildInfo.version]
        ]
        if let egress {
            canonical["domains"] = egress.rules.map(\.description).sorted()
            canonical["steered"] = egress.steeredNames.sorted()
            canonical["verify"] = [egress.verify.rawValue]
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = (try? encoder.encode(canonical)) ?? Data()
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// Human-readable summary for `sand network explain` and dry runs.
    func explain() -> [String] {
        var lines = [
            "network policy: \(name)",
            "policy hash: \(policyHash)",
            "policy version: \(EgressPreset.policyVersion)",
            "tart arguments: \(tartArguments.isEmpty ? "(none: shared NAT)" : tartArguments.joined(separator: " "))"
        ]
        switch kind {
        case .shared:
            lines.append("WARNING: VM has unrestricted host/LAN/VPN/corporate network reach")
        case .softnet:
            lines.append("softnet built-in isolation: private ranges blocked, public IPv4 reachable")
        case let .restricted(cidrs):
            lines.append("direct IPv4 allows: \(cidrs.joined(separator: ", "))")
        case .offline:
            lines.append("guest egress: none (host SSH only)")
        case let .egressProxy(egress):
            lines.append("guest egress: HTTPS CONNECT proxy at 127.0.0.1:\(Self.guestProxyPort) in the guest (SSH reverse tunnel)")
            lines.append("verify: \(egress.verify.rawValue)")
            lines.append("steered names (VPN split-DNS fronts allowed): \(egress.steeredNames.sorted().joined(separator: ", "))")
            lines.append("allowed destinations (\(egress.rules.count)):")
            lines.append(contentsOf: egress.rules.map { "  - \($0)" })
            if !egress.extraCIDRs.isEmpty {
                lines.append("direct CIDR allows (bypass the proxy):")
                lines.append(contentsOf: egress.extraCIDRs.map { "  - \($0.proto.rawValue) \($0.cidr) port \($0.port)" })
            }
        }
        return lines
    }

    /// Require narrow, explicitly spelled IPv4 prefixes. In particular this
    /// rejects @host, 0.0.0.0/0, hostnames, IPv6 and oversized IP ranges.
    /// It intentionally allows private /32 proxies; administrators must ensure
    /// those endpoints are not the host or reachable corporate services.
    static func isAllowedCIDR(_ cidr: String) -> Bool {
        let parts = cidr.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let prefix = Int(parts[1]), (24...32).contains(prefix) else {
            return false
        }
        let octets = parts[0].split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4 else { return false }
        return octets.allSatisfy { octet in
            guard !octet.isEmpty,
                  (octet.count == 1 || octet.first != "0"),
                  octet.allSatisfy({ $0.isASCII && $0.isNumber }),
                  let number = Int(octet), (0...255).contains(number) else {
                return false
            }
            return true
        }
    }
}
