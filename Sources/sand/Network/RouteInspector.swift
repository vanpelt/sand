import Foundation

struct HostRoute: Equatable, Sendable {
    /// nil for `default`.
    let destination: IPNetwork?
    let gateway: String
    let flags: String
    let interface: String

    var isDefault: Bool { destination == nil }
}

/// Parses `netstat -rn -f inet` so Sand can detect when softnet's VM subnet
/// collides with a host route (for example a VPN's 172.16/16 that carries the
/// steered GitHub fronts). A collision would shadow those routes or make the
/// guard's on-link reasoning wrong, so the VM is recreated instead.
struct RouteInspector: Sendable {
    let routes: [HostRoute]

    init(routes: [HostRoute]) {
        self.routes = routes
    }

    init(netstatOutput: String) {
        routes = netstatOutput.split(whereSeparator: \.isNewline).compactMap { Self.parseLine(String($0)) }
    }

    static func current(processRunner: ProcessRunning) async -> RouteInspector {
        let output = (try? await processRunner.run(executable: "netstat", arguments: ["-rn", "-f", "inet"], wait: true))?.stdout ?? ""
        return RouteInspector(netstatOutput: output)
    }

    /// The VM's assumed subnet: the /29 that contains its address.
    static func vmSubnet(for ip: String) -> IPNetwork? {
        guard let address = IPAddress(ip), address.isIPv4 else { return nil }
        return IPNetwork(address: address, prefixLength: 29)
    }

    /// Non-default host routes, not via a vmnet bridge or loopback, that overlap `subnet`.
    func overlaps(_ subnet: IPNetwork) -> [HostRoute] {
        routes.filter { route in
            guard let destination = route.destination else { return false }
            if route.interface.hasPrefix("bridge") || route.interface.hasPrefix("lo") || route.interface.hasPrefix("vmenet") {
                return false
            }
            return destination.overlaps(subnet)
        }
    }

    /// Subnets reached through tunnel interfaces (VPNs): useful strict-probe targets.
    var tunnelSubnets: [(IPNetwork, String)] {
        routes.compactMap { route in
            guard let destination = route.destination, route.interface.hasPrefix("utun"),
                  destination.prefixLength < 32 else { return nil }
            return (destination, route.interface)
        }
    }

    var defaultGateways: [String] {
        routes.filter { $0.isDefault && IPAddress($0.gateway) != nil }.map(\.gateway)
    }

    static func parseLine(_ line: String) -> HostRoute? {
        let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        guard fields.count >= 4 else { return nil }
        let destinationField = fields[0]
        guard destinationField != "Destination", destinationField != "Internet:", destinationField != "Routing" else {
            return nil
        }
        let gateway = fields[1]
        let flags = fields[2]
        let interface = fields[3]
        guard flags.first?.isUppercase == true else { return nil }
        if destinationField == "default" {
            return HostRoute(destination: nil, gateway: gateway, flags: flags, interface: interface)
        }
        guard let destination = parseDestination(destinationField) else { return nil }
        return HostRoute(destination: destination, gateway: gateway, flags: flags, interface: interface)
    }

    /// netstat abbreviates: `10/24` is 10.0.0.0/24, `172.16` is 172.16.0.0/16,
    /// `127` is 127.0.0.0/8 and a full dotted quad without a length is a host route.
    static func parseDestination(_ field: String) -> IPNetwork? {
        let trimmed = field.split(separator: "%").first.map(String.init) ?? field
        let parts = trimmed.split(separator: "/", omittingEmptySubsequences: false)
        guard let addressPart = parts.first, parts.count <= 2 else { return nil }
        var octets = addressPart.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard (1...4).contains(octets.count), octets.allSatisfy({ !$0.isEmpty && $0.allSatisfy(\.isNumber) }) else {
            return nil
        }
        let implied = octets.count * 8
        while octets.count < 4 {
            octets.append("0")
        }
        guard let address = IPAddress(octets.joined(separator: ".")) else { return nil }
        let length: Int
        if parts.count == 2 {
            guard let value = Int(parts[1]) else { return nil }
            length = value
        } else {
            length = implied
        }
        return IPNetwork(address: address, prefixLength: length)
    }
}
