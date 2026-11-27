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
            if let maskPointer = entry.pointee.ifa_netmask,
               let mask = IPAddress(sockaddr: UnsafePointer(maskPointer)),
               let network = IPNetwork(address: address, prefixLength: prefixLength(of: mask, family: address)) {
                facts.onLinkSubnets.append(network)
            }
        }
        return facts
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
