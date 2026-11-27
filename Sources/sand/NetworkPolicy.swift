import Foundation

/// Opt-in network isolation for Tart VMs. This is an IPv4 destination policy,
/// not a complete enterprise firewall or domain-aware egress proxy.
struct NetworkPolicy: Decodable, Sendable, Equatable {
    enum Mode: String, Decodable, Sendable {
        /// Existing Tart shared NAT behavior. No Softnet enforcement.
        case shared
        /// Softnet's built-in host/private-network isolation; public IPv4 remains reachable.
        case softnet
        /// Deny all forwarded IPv4 egress except explicitly allowed narrow CIDRs.
        case restricted
    }

    let mode: Mode
    let allowCIDRs: [String]

    static let shared = NetworkPolicy(mode: .shared)

    init(mode: Mode, allowCIDRs: [String] = []) {
        self.mode = mode
        self.allowCIDRs = allowCIDRs
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        // An explicit network block must specify a mode; never silently fall back
        // to unrestricted NAT because someone misspelled/omitted the mode.
        mode = try container.decode(Mode.self, forKey: .mode)
        allowCIDRs = try container.decodeIfPresent([String].self, forKey: .allowCIDRs) ?? []
    }

    private enum CodingKeys: String, CodingKey {
        case mode
        case allowCIDRs
    }

    var tartArguments: [String] {
        switch mode {
        case .shared:
            return []
        case .softnet:
            return ["--net-softnet"]
        case .restricted:
            var args = ["--net-softnet", "--net-softnet-block=0.0.0.0/0"]
            if !allowCIDRs.isEmpty {
                args.append("--net-softnet-allow=" + allowCIDRs.joined(separator: ","))
            }
            return args
        }
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
