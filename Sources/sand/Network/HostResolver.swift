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
        // Defence in depth: getaddrinfo(3) would silently truncate at a NUL.
        guard !host.isEmpty, host.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f }) else {
            throw HostResolverError.failed("<invalid>", "hostname contains control or non-ASCII bytes")
        }
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

/// The host's DNS servers, from `scutil --dns` (unprivileged). Used only as
/// adversarial verifier targets: a guest must not reach them by routing via the host.
enum HostDNSServers {
    static func parse(scutil output: String) -> [String] {
        var servers: [String] = []
        for line in output.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("nameserver["), let colon = trimmed.firstIndex(of: ":") else { continue }
            let value = trimmed[trimmed.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            guard let address = IPAddress(value), !address.isLoopback, !servers.contains(value) else { continue }
            servers.append(value)
        }
        return servers
    }

    static func current(processRunner: ProcessRunning) async -> [String] {
        let output = (try? await processRunner.run(executable: "scutil", arguments: ["--dns"], wait: true))?.stdout ?? ""
        return parse(scutil: output)
    }
}
