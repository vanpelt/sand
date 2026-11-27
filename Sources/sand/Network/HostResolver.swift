import Darwin
import Foundation

enum HostResolverError: Error, CustomStringConvertible {
    case failed(String, String)

    var description: String {
        switch self {
        case let .failed(host, reason):
            return "resolve \(host): \(reason)"
        }
    }
}

protocol HostResolving: Sendable {
    func resolve(_ host: String) async throws -> [IPAddress]
}

/// getaddrinfo(3) through the host's system resolver, so VPN split-DNS
/// (e.g. BlastShield steering github.com to a private front) applies exactly
/// as it does for every other host process. No Sand-specific VPN code.
struct SystemHostResolver: HostResolving {
    func resolve(_ host: String) async throws -> [IPAddress] {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(with: Result { try Self.resolveBlocking(host) })
            }
        }
    }

    static func resolveBlocking(_ host: String) throws -> [IPAddress] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM
        hints.ai_flags = AI_ADDRCONFIG
        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, nil, &hints, &result)
        guard status == 0, let first = result else {
            throw HostResolverError.failed(host, String(cString: gai_strerror(status)))
        }
        defer { freeaddrinfo(result) }
        var addresses: [IPAddress] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let entry = cursor {
            if let pointer = entry.pointee.ai_addr, let address = IPAddress(sockaddr: UnsafePointer(pointer)), !addresses.contains(address) {
                addresses.append(address)
            }
            cursor = entry.pointee.ai_next
        }
        return addresses
    }
}

/// Deterministic resolver for tests.
struct StaticHostResolver: HostResolving {
    let table: [String: [IPAddress]]

    func resolve(_ host: String) async throws -> [IPAddress] {
        guard let addresses = table[DomainPattern.normalize(host)] else {
            throw HostResolverError.failed(host, "unknown host")
        }
        return addresses
    }
}
