import Darwin
import Foundation

/// A parsed IPv4 or IPv6 address. Parsing goes through inet_pton, so only
/// canonical numeric forms are accepted (no hostnames, no zone suffixes).
enum IPAddress: Hashable, Sendable, CustomStringConvertible {
    case v4(UInt32)
    case v6([UInt8])

    init?(_ string: String) {
        // inet_pton stops at the first NUL; refuse anything that is not printable
        // ASCII so "1.1.1.1\0..." can never parse as the address before the NUL.
        guard !string.isEmpty, string.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f }) else {
            return nil
        }
        var v4 = in_addr()
        if inet_pton(AF_INET, string, &v4) == 1 {
            self = .v4(UInt32(bigEndian: v4.s_addr))
            return
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, string, &v6) == 1 {
            self = .v6(withUnsafeBytes(of: &v6) { Array($0) })
            return
        }
        return nil
    }

    init(v4 a: UInt8, _ b: UInt8, _ c: UInt8, _ d: UInt8) {
        self = .v4(UInt32(a) << 24 | UInt32(b) << 16 | UInt32(c) << 8 | UInt32(d))
    }

    /// Builds an address from a sockaddr (as returned by getaddrinfo/getifaddrs).
    init?(sockaddr pointer: UnsafePointer<sockaddr>) {
        switch Int32(pointer.pointee.sa_family) {
        case AF_INET:
            let value = pointer.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr }
            self = .v4(UInt32(bigEndian: value))
        case AF_INET6:
            var address = pointer.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
            self = .v6(withUnsafeBytes(of: &address) { Array($0) })
        default:
            return nil
        }
    }

    var isIPv4: Bool {
        if case .v4 = self { return true }
        return false
    }

    /// 127/8 or ::1.
    var isLoopback: Bool {
        switch self {
        case let .v4(value): return value >> 24 == 127
        case let .v6(bytes): return bytes[0..<15].allSatisfy { $0 == 0 } && bytes[15] == 1
        }
    }

    /// fe80::/10.
    var isLinkLocalV6: Bool {
        guard case let .v6(bytes) = self else { return false }
        return bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80
    }

    /// getifaddrs on macOS embeds the interface index in bytes 2-3 of a
    /// link-local address (KAME); clear it so the address prints as fe80::...
    var withoutEmbeddedScope: IPAddress {
        guard isLinkLocalV6, case var .v6(bytes) = self else { return self }
        bytes[2] = 0
        bytes[3] = 0
        return .v6(bytes)
    }

    /// For an IPv4-mapped IPv6 address (::ffff:a.b.c.d) returns the IPv4 form.
    var unwrappedIPv4Mapped: IPAddress? {
        guard case let .v6(bytes) = self,
              bytes[0..<10].allSatisfy({ $0 == 0 }), bytes[10] == 0xff, bytes[11] == 0xff else {
            return nil
        }
        return .v4(UInt32(bytes[12]) << 24 | UInt32(bytes[13]) << 16 | UInt32(bytes[14]) << 8 | UInt32(bytes[15]))
    }

    var description: String {
        switch self {
        case let .v4(value):
            return "\(value >> 24 & 0xff).\(value >> 16 & 0xff).\(value >> 8 & 0xff).\(value & 0xff)"
        case let .v6(bytes):
            var address = in6_addr()
            withUnsafeMutableBytes(of: &address) { $0.copyBytes(from: bytes) }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &address, &buffer, socklen_t(buffer.count)) != nil else {
                return "::"
            }
            return String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        }
    }

    /// True for literal IPv4/IPv6 strings, including bracketed IPv6.
    static func isLiteral(_ string: String) -> Bool {
        var candidate = string
        if candidate.hasPrefix("["), candidate.hasSuffix("]") {
            candidate = String(candidate.dropFirst().dropLast())
        }
        return IPAddress(candidate) != nil
    }
}

/// An IPv4 or IPv6 prefix.
struct IPNetwork: Hashable, Sendable, CustomStringConvertible {
    let address: IPAddress
    let prefixLength: Int

    init?(address: IPAddress, prefixLength: Int) {
        switch address {
        case let .v4(value):
            guard (0...32).contains(prefixLength) else { return nil }
            self.address = .v4(value & Self.mask4(prefixLength))
        case let .v6(bytes):
            guard (0...128).contains(prefixLength) else { return nil }
            self.address = .v6(Self.masked6(bytes, prefixLength))
        }
        self.prefixLength = prefixLength
    }

    /// Parses "a.b.c.d/n" or "x::y/n". A bare address is a host prefix.
    init?(_ string: String) {
        let parts = string.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count <= 2, let address = IPAddress(String(parts[0])) else {
            return nil
        }
        let maxLength = address.isIPv4 ? 32 : 128
        let length: Int
        if parts.count == 2 {
            guard !parts[1].isEmpty, parts[1].allSatisfy({ $0.isASCII && $0.isNumber }), let value = Int(parts[1]) else {
                return nil
            }
            length = value
        } else {
            length = maxLength
        }
        self.init(address: address, prefixLength: length)
    }

    func contains(_ other: IPAddress) -> Bool {
        switch (address, other) {
        case let (.v4(network), .v4(value)):
            return value & Self.mask4(prefixLength) == network
        case let (.v6(network), .v6(value)):
            return Self.masked6(value, prefixLength) == network
        default:
            return false
        }
    }

    func overlaps(_ other: IPNetwork) -> Bool {
        guard address.isIPv4 == other.address.isIPv4 else { return false }
        let shorter = prefixLength <= other.prefixLength ? self : other
        let longer = prefixLength <= other.prefixLength ? other : self
        return shorter.contains(longer.address)
    }

    var description: String {
        "\(address)/\(prefixLength)"
    }

    static func mask4(_ length: Int) -> UInt32 {
        length == 0 ? 0 : UInt32.max << UInt32(32 - length)
    }

    private static func masked6(_ bytes: [UInt8], _ length: Int) -> [UInt8] {
        var result = bytes
        for index in 0..<16 {
            let bitsInByte = max(0, min(8, length - index * 8))
            let mask: UInt8 = bitsInByte == 0 ? 0 : UInt8(truncatingIfNeeded: 0xff << (8 - bitsInByte))
            result[index] &= mask
        }
        return result
    }
}
