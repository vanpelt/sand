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
        ("198.18.0.0/15", "benchmark"),
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
        ("64:ff9b::/96", "nat64")
    ].map { (IPNetwork($0.0)!, $0.1) }

    /// RFC1918 ranges in which a VPN-steered GitHub front may live.
    static let steerableRanges: [IPNetwork] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"].compactMap(IPNetwork.init)

    let hostFacts: HostFacts
    /// Test hook: addresses allowed regardless of range (e.g. a loopback echo server).
    let testAllowance: Set<IPAddress>

    init(hostFacts: HostFacts, testAllowance: Set<IPAddress> = []) {
        self.hostFacts = hostFacts
        self.testAllowance = testAllowance
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

    func classify(_ input: IPAddress, steeredName: Bool) -> Decision {
        if testAllowance.contains(input) {
            return .allow(input, steered: false)
        }
        // ::ffff:a.b.c.d is checked as the IPv4 address it reaches.
        let address = input.unwrappedIPv4Mapped ?? input
        if hostFacts.interfaceAddresses.contains(address) || hostFacts.interfaceAddresses.contains(input) {
            return .deny("host-address")
        }
        if let vmSubnet = hostFacts.vmSubnet, vmSubnet.contains(address) {
            return .deny("vm-subnet")
        }
        if hostFacts.onLinkSubnets.contains(where: { $0.contains(address) }) {
            return .deny("on-link")
        }
        let table = address.isIPv4 ? Self.alwaysDeniedV4 : Self.alwaysDeniedV6
        guard let (_, reason) = table.first(where: { $0.0.contains(address) }) else {
            return .allow(input, steered: false)
        }
        if steeredName, Self.steerableRanges.contains(where: { $0.contains(address) }) {
            return .allow(address, steered: true)
        }
        return .deny(reason)
    }
}
