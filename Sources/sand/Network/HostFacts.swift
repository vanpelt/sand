import Darwin
import Foundation

/// Host network facts the destination guard needs: every local address and
/// every directly attached subnet, plus the VM's own subnet once known.
struct HostFacts: Sendable, Equatable {
    var interfaceAddresses: [IPAddress]
    var onLinkSubnets: [IPNetwork]
    var vmSubnet: IPNetwork?

    init(interfaceAddresses: [IPAddress] = [], onLinkSubnets: [IPNetwork] = [], vmSubnet: IPNetwork? = nil) {
        self.interfaceAddresses = interfaceAddresses
        self.onLinkSubnets = onLinkSubnets
        self.vmSubnet = vmSubnet
    }

    /// Reads getifaddrs(3). Loopback is skipped because the guard always denies it.
    static func current() -> HostFacts {
        var facts = HostFacts()
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else {
            return facts
        }
        defer { freeifaddrs(head) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            guard let addressPointer = entry.pointee.ifa_addr,
                  let address = IPAddress(sockaddr: UnsafePointer(addressPointer)) else {
                continue
            }
            let name = String(cString: entry.pointee.ifa_name)
            if name.hasPrefix("lo") {
                continue
            }
            facts.interfaceAddresses.append(address)
            let pointToPoint = entry.pointee.ifa_flags & UInt32(IFF_POINTOPOINT) != 0
            let maskLength = entry.pointee.ifa_netmask
                .flatMap { IPAddress(sockaddr: UnsafePointer($0)) }
                .map { prefixLength(of: $0, family: address) }
            if let network = Self.onLinkNetwork(address: address, maskLength: maskLength, pointToPoint: pointToPoint) {
                facts.onLinkSubnets.append(network)
            }
        }
        return facts
    }

    /// A point-to-point (utun/VPN) interface has no attached LAN: only its own
    /// address is on-link, whatever netmask the VPN client set. Otherwise a /16
    /// on a VPN tunnel would mark every steered GitHub front as on-link.
    static func onLinkNetwork(address: IPAddress, maskLength: Int?, pointToPoint: Bool) -> IPNetwork? {
        if pointToPoint {
            return IPNetwork(address: address, prefixLength: address.isIPv4 ? 32 : 128)
        }
        guard let maskLength else { return nil }
        return IPNetwork(address: address, prefixLength: maskLength)
    }

    func withVMSubnet(_ subnet: IPNetwork?) -> HostFacts {
        var copy = self
        copy.vmSubnet = subnet
        return copy
    }

    private static func prefixLength(of mask: IPAddress, family: IPAddress) -> Int {
        switch mask {
        case let .v4(value):
            return value.nonzeroBitCount
        case let .v6(bytes):
            // getifaddrs can return a v6 mask shorter than 16 bytes worth of data; count set bits.
            return bytes.reduce(0) { $0 + $1.nonzeroBitCount }
        }
    }
}
