import Foundation

/// Decides which resolved address (if any) the proxy may connect to. This is
/// what keeps an allowlisted *name* from reaching the host, the LAN, the
/// tailnet, metadata services or corporate ranges, e.g. by DNS rebinding.
struct DestinationGuard: Sendable {
    enum Decision: Equatable, Sendable {
        case allow(IPAddress, steered: Bool)
        case deny(String)
    }

    static let alwaysDeniedV4: [(IPNetwork, String)] = [
        ("0.0.0.0/8", "this-network"),
        ("10.0.0.0/8", "private"),
        ("100.64.0.0/10", "cgnat/tailnet"),
        ("127.0.0.0/8", "loopback"),
        ("169.254.0.0/16", "link-local/metadata"),
        ("172.16.0.0/12", "private"),
        ("192.168.0.0/16", "private"),
        ("192.0.0.0/24", "ietf-protocol"),
        ("192.0.2.0/24", "documentation"),
        ("192.88.99.0/24", "6to4-relay"),
        ("198.18.0.0/15", "benchmark"),
        ("198.51.100.0/24", "documentation"),
        ("203.0.113.0/24", "documentation"),
        ("224.0.0.0/4", "multicast"),
        ("240.0.0.0/4", "reserved"),
        ("255.255.255.255/32", "broadcast")
    ].map { (IPNetwork($0.0)!, $0.1) }

    static let alwaysDeniedV6: [(IPNetwork, String)] = [
        ("::/128", "unspecified"),
        ("::1/128", "loopback"),
        ("fe80::/10", "link-local"),
        ("fc00::/7", "unique-local"),
        ("ff00::/8", "multicast"),
        ("fec0::/10", "site-local"),
        ("::/96", "ipv4-compatible"),
        ("64:ff9b::/96", "nat64"),
        ("64:ff9b:1::/48", "nat64-local"),
        ("100::/64", "discard"),
        ("2001::/32", "teredo"),
        ("2001:db8::/32", "documentation"),
        ("2002::/16", "6to4")
    ].map { (IPNetwork($0.0)!, $0.1) }

    /// Never reachable through the proxy, not even for a reviewed
    /// `allowedCIDRs` entry with `allowPrivate: true`.
    static let hardDenied: [(IPNetwork, String)] = [
        ("0.0.0.0/8", "this-network"),
        ("127.0.0.0/8", "loopback"),
        ("169.254.0.0/16", "link-local/metadata"),
        ("224.0.0.0/4", "multicast"),
        ("240.0.0.0/4", "reserved"),
        ("::/128", "unspecified"),
        ("::1/128", "loopback"),
        ("fe80::/10", "link-local"),
        ("ff00::/8", "multicast")
    ].map { (IPNetwork($0.0)!, $0.1) }

    /// RFC1918 ranges in which a VPN-steered GitHub front may live.
    static let steerableRanges: [IPNetwork] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"].compactMap(IPNetwork.init)

    let hostFacts: HostFacts
    /// Test hook: addresses allowed regardless of range (e.g. a loopback echo server).
    let testAllowance: Set<IPAddress>
    /// When set, a steered private answer is only used if the host routes it
    /// out one of these interfaces (learned when the VM's proxy started from
    /// where the steered GitHub names actually resolved). This keeps a hostile
    /// resolver from pointing github.com at a tailnet or other VPN subnet.
    let steeredInterfaces: Set<String>?
    let routes: RouteInspector?

    init(hostFacts: HostFacts, testAllowance: Set<IPAddress> = [], routes: RouteInspector? = nil, steeredInterfaces: Set<String>? = nil) {
        self.hostFacts = hostFacts
        self.testAllowance = testAllowance
        self.routes = routes
        self.steeredInterfaces = steeredInterfaces
    }

    /// Resolves the steered names now and records which interfaces carry their
    /// private (VPN-front) answers. Public answers contribute nothing.
    static func learnSteeredInterfaces(names: Set<String>, resolver: HostResolving, routes: RouteInspector) async -> Set<String> {
        var interfaces = Set<String>()
        for name in names.sorted() {
            guard let addresses = try? await resolver.resolve(name) else { continue }
            for address in addresses where steerableRanges.contains(where: { $0.contains(address) }) {
                if let interface = routes.interface(for: address) {
                    interfaces.insert(interface)
                }
            }
        }
        return interfaces
    }

    /// Returns the first acceptable address. `steeredName` says whether the
    /// host is one of the policy's steered names (private answers allowed).
    func check(host: String, port: Int, resolved: [IPAddress], steeredName: Bool) -> Decision {
        guard !resolved.isEmpty else {
            return .deny("no-address")
        }
        var reasons: [String] = []
        for address in resolved {
            switch classify(address, steeredName: steeredName) {
            case let .allow(ip, steered):
                return .allow(ip, steered: steered)
            case let .deny(reason):
                reasons.append("\(address)=\(reason)")
            }
        }
        return .deny("blocked-address(" + reasons.joined(separator: ";") + ")")
    }

    /// An IP-literal CONNECT that a reviewed `allowedCIDRs` entry covers. The
    /// host itself, its on-link subnets, the VM subnet and the hard-denied
    /// ranges are refused unconditionally; other private/reserved space only
    /// when the covering entry set `allowPrivate`.
    func checkLiteral(_ input: IPAddress, allowPrivate: Bool) -> Decision {
        if testAllowance.contains(input) {
            return .allow(input, steered: false)
        }
        let address = input.unwrappedIPv4Mapped ?? input
        if let reason = hostLocalReason(address, original: input) {
            return .deny(reason)
        }
        if let (_, reason) = Self.hardDenied.first(where: { $0.0.contains(address) }) {
            return .deny(reason)
        }
        let table = address.isIPv4 ? Self.alwaysDeniedV4 : Self.alwaysDeniedV6
        if let (_, reason) = table.first(where: { $0.0.contains(address) }), !allowPrivate {
            return .deny(reason)
        }
        return .allow(input, steered: false)
    }

    private func hostLocalReason(_ address: IPAddress, original: IPAddress) -> String? {
        if hostFacts.interfaceAddresses.contains(address) || hostFacts.interfaceAddresses.contains(original) {
            return "host-address"
        }
        if let vmSubnet = hostFacts.vmSubnet, vmSubnet.contains(address) {
            return "vm-subnet"
        }
        if hostFacts.onLinkSubnets.contains(where: { $0.contains(address) }) {
            return "on-link"
        }
        return nil
    }

    func classify(_ input: IPAddress, steeredName: Bool) -> Decision {
        if testAllowance.contains(input) {
            return .allow(input, steered: false)
        }
        // ::ffff:a.b.c.d is checked as the IPv4 address it reaches.
        let address = input.unwrappedIPv4Mapped ?? input
        if let reason = hostLocalReason(address, original: input) {
            return .deny(reason)
        }
        let table = address.isIPv4 ? Self.alwaysDeniedV4 : Self.alwaysDeniedV6
        guard let (_, reason) = table.first(where: { $0.0.contains(address) }) else {
            return .allow(input, steered: false)
        }
        if steeredName, Self.steerableRanges.contains(where: { $0.contains(address) }) {
            if let steeredInterfaces {
                guard let interface = routes?.interface(for: address), steeredInterfaces.contains(interface) else {
                    return .deny("steered-route-mismatch")
                }
            }
            return .allow(address, steered: true)
        }
        return .deny(reason)
    }
}
