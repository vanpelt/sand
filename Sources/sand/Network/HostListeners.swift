import Darwin
import Foundation

enum HostListenerPatternError: Error, Equatable, CustomStringConvertible {
    case invalid(String)

    var description: String {
        switch self {
        case let .invalid(value):
            return "acceptedHostListeners entry '\(value)' must be tcp/PORT, udp/PORT, tcp/* or udp/*"
        }
    }
}

/// `tcp/7000`, `udp/5353`, `udp/*`: a host listener the operator accepts as
/// reachable from the guest under the hostOnly backend.
struct HostListenerPattern: Sendable, Hashable, CustomStringConvertible {
    let proto: SoftnetProto
    /// nil matches every port.
    let port: Int?

    static func parse(_ raw: String) throws -> HostListenerPattern {
        let parts = raw.lowercased().split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 2, let proto = SoftnetProto(rawValue: parts[0]) else {
            throw HostListenerPatternError.invalid(raw)
        }
        if parts[1] == "*" {
            return HostListenerPattern(proto: proto, port: nil)
        }
        guard let port = Int(parts[1]), (1...65_535).contains(port), String(port) == parts[1] else {
            throw HostListenerPatternError.invalid(raw)
        }
        return HostListenerPattern(proto: proto, port: port)
    }

    func matches(_ listener: HostListener) -> Bool {
        listener.proto == proto && (port == nil || port == listener.port)
    }

    var description: String {
        "\(proto.rawValue)/\(port.map(String.init) ?? "*")"
    }
}

/// One host socket a guest on the VM bridge can reach.
struct HostListener: Sendable, Hashable, Comparable, CustomStringConvertible {
    let proto: SoftnetProto
    let port: Int
    /// `*` (all interfaces) or the bridge address it is bound to.
    let boundTo: String
    /// `ControlCenter:1311` when netstat reports it.
    var process: String?

    var key: String { "\(proto.rawValue)/\(port)" }

    var description: String {
        var text = key
        if boundTo != "*" { text += "@\(boundTo)" }
        if let process { text += " (\(process))" }
        return text
    }

    static func < (lhs: HostListener, rhs: HostListener) -> Bool {
        (lhs.proto.rawValue, lhs.port, lhs.boundTo) < (rhs.proto.rawValue, rhs.port, rhs.boundTo)
    }
}

/// Finds host TCP listeners and unconnected UDP sockets that a guest on the
/// host-only bridge can reach: bound to all interfaces, or to any non-loopback
/// host address (`reachableAddresses`: the bridge plus, because macOS is
/// weak-host, the LAN/VPN/utun addresses a guest reaches by routing via the
/// bridge; the `bridgeAddresses` parameters below take that list). Loopback sockets (including Sand's own egress proxy) are
/// never reachable from the guest and are always ignored.
///
/// Sources, all unprivileged:
/// - `netstat -an` sees every user's sockets, but recent macOS releases hide
///   the Internet section from some callers;
/// - `lsof -nP -iTCP -sTCP:LISTEN -iUDP` sees this user's sockets and names the process;
/// - when netstat is blind, a TCP connect probe of the bridge address on
///   well-known service ports (sshd, screen sharing, file sharing, AirPlay,
///   dev servers...) finds other users' (root) listeners too. Root listeners on
///   other ports, and other users' UDP sockets, cannot be seen without root in
///   that case; the audit line names the method.
struct HostListenerInspector: Sendable {
    let processRunner: ProcessRunning
    var sweep: @Sendable ([IPAddress]) async -> [Int] = { addresses in await TCPConnectSweep.openPorts(on: addresses, ports: TCPConnectSweep.wellKnownPorts) }

    struct Result: Sendable, Equatable {
        var listeners: [HostListener]
        /// `netstat`, or `lsof+sweep` when netstat could not see Internet sockets.
        var method: String
    }

    func reachable(bridgeAddresses: [IPAddress]) async -> [HostListener] {
        await inspect(bridgeAddresses: bridgeAddresses).listeners
    }

    func inspect(bridgeAddresses: [IPAddress]) async -> Result {
        let plain = (try? await processRunner.run(executable: "netstat", arguments: ["-an"], wait: true))?.stdout ?? ""
        let lsof = (try? await processRunner.run(executable: "lsof", arguments: ["-nP", "-iTCP", "-sTCP:LISTEN", "-iUDP"], wait: true))?.stdout ?? ""
        let fromLsof = Self.parse(lsof: lsof, bridgeAddresses: bridgeAddresses)
        if Self.netstatSeesInternetSockets(plain) {
            let verbose = (try? await processRunner.run(executable: "netstat", arguments: ["-anv"], wait: true))?.stdout ?? ""
            let fromNetstat = Self.parse(netstat: plain, verbose: verbose, bridgeAddresses: bridgeAddresses)
            return Result(listeners: Self.dedupe(fromNetstat + fromLsof), method: "netstat")
        }
        let swept = await sweep(bridgeAddresses.filter(\.isIPv4)).map { HostListener(proto: .tcp, port: $0, boundTo: "*") }
        return Result(listeners: Self.dedupe(fromLsof + swept), method: "lsof+sweep")
    }

    static func netstatSeesInternetSockets(_ output: String) -> Bool {
        output.split(whereSeparator: \.isNewline).contains { $0.hasPrefix("tcp4") || $0.hasPrefix("tcp6") || $0.hasPrefix("udp4") || $0.hasPrefix("udp6") }
    }

    /// Every host address a guest can reach once it routes via the bridge: macOS
    /// is a weak-host system, so a socket bound to the LAN, VPN or utun address
    /// answers on the bridge too. Loopback is never reachable; another
    /// interface's IPv6 link-local address is unusable from the bridge.
    static func reachableAddresses(bridge: [IPAddress], host: [IPAddress]) -> [IPAddress] {
        var result: [IPAddress] = []
        for address in bridge.map(\.withoutEmbeddedScope) + host.filter({ !$0.isLinkLocalV6 }) where !address.isLoopback && !result.contains(address) {
            result.append(address)
        }
        return result
    }

    /// `lsof -F`-free parse of the default table: `COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME`,
    /// NAME like `*:5000 (LISTEN)`, `192.168.128.1:22 (LISTEN)`, `[::1]:631`, or a connected `a:1->b:2`.
    static func parse(lsof: String, bridgeAddresses: [IPAddress]) -> [HostListener] {
        var result: [HostListener] = []
        for line in lsof.split(whereSeparator: \.isNewline).dropFirst() {
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard fields.count >= 9 else { continue }
            guard let nodeIndex = fields.firstIndex(where: { $0 == "TCP" || $0 == "UDP" }), nodeIndex + 1 < fields.count else { continue }
            let proto: SoftnetProto = fields[nodeIndex] == "TCP" ? .tcp : .udp
            let name = fields[nodeIndex + 1]
            if proto == .tcp, !fields[(nodeIndex + 1)...].contains("(LISTEN)") { continue }
            guard !name.contains("->"), let colon = name.lastIndex(of: ":") else { continue }
            var host = String(name[..<colon])
            guard let port = Int(name[name.index(after: colon)...]), port > 0 else { continue }
            if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
            let boundTo: String
            if host == "*" {
                boundTo = "*"
            } else {
                let unscoped = host.split(separator: "%").first.map(String.init) ?? host
                guard let address = IPAddress(unscoped), bridgeAddresses.contains(address) else { continue }
                boundTo = unscoped
            }
            result.append(HostListener(proto: proto, port: port, boundTo: boundTo, process: "\(fields[0]):\(fields[1])"))
        }
        return result
    }

    /// Merges tcp4/tcp6/tcp46 duplicates of the same port and binding.
    static func dedupe(_ listeners: [HostListener]) -> [HostListener] {
        var seen: [String: HostListener] = [:]
        // A swept port (no binding detail) merges into a named wildcard entry.
        let named = Set(listeners.filter { $0.process != nil }.map(\.key))
        for listener in listeners where !(listener.process == nil && listener.boundTo == "*" && named.contains(listener.key)) {
            let id = "\(listener.key)@\(listener.boundTo)"
            if var existing = seen[id] {
                existing.process = existing.process ?? listener.process
                seen[id] = existing
            } else {
                seen[id] = listener
            }
        }
        return seen.values.sorted()
    }

    static func parse(netstat: String, verbose: String = "", bridgeAddresses: [IPAddress]) -> [HostListener] {
        let processes = processNames(verbose: verbose)
        var result: [HostListener] = []
        for line in netstat.split(whereSeparator: \.isNewline) {
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard fields.count >= 5 else { continue }
            let protoField = fields[0]
            let proto: SoftnetProto
            if protoField.hasPrefix("tcp") {
                guard fields.count >= 6, fields[5] == "LISTEN" else { continue }
                proto = .tcp
            } else if protoField.hasPrefix("udp") {
                // A connected UDP socket only accepts its peer; an unconnected one is a listener.
                guard fields[4] == "*.*" else { continue }
                proto = .udp
            } else {
                continue
            }
            guard let (host, port) = splitLocal(fields[3]), port > 0 else { continue }
            let boundTo: String
            if host == "*" {
                boundTo = "*"
            } else {
                let unscoped = host.split(separator: "%").first.map(String.init) ?? host
                guard let address = IPAddress(unscoped), bridgeAddresses.contains(address) else { continue }
                boundTo = unscoped
            }
            let process = processes["\(protoField) \(fields[3])"]
            result.append(HostListener(proto: proto, port: port, boundTo: boundTo, process: process))
        }
        return result
    }

    /// `*.5000` -> ("*", 5000); `192.168.128.1.22` -> ("192.168.128.1", 22);
    /// `fe80::1%bridge100.5353` -> ("fe80::1%bridge100", 5353).
    static func splitLocal(_ field: String) -> (String, Int)? {
        guard let dot = field.lastIndex(of: ".") else { return nil }
        let host = String(field[..<dot])
        guard let port = Int(field[field.index(after: dot)...]) else { return nil }
        return (host, port)
    }

    /// Maps `tcp4 *.5000` to `ControlCenter:1311` from `netstat -anv`. Verbose
    /// output truncates long addresses, so only exact matches are named.
    static func processNames(verbose: String) -> [String: String] {
        var names: [String: String] = [:]
        for line in verbose.split(whereSeparator: \.isNewline) {
            let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard fields.count > 8, fields[0].hasPrefix("tcp") || fields[0].hasPrefix("udp") else { continue }
            // The process column is `name:pid`; a name can contain spaces.
            guard let pidIndex = fields.indices.dropFirst(5).first(where: { index in
                let field = fields[index]
                guard let colon = field.lastIndex(of: ":"), colon != field.startIndex else { return false }
                return Int(field[field.index(after: colon)...]) != nil
            }) else { continue }
            var start = pidIndex
            while start - 1 > 4, Int(fields[start - 1]) == nil {
                start -= 1
            }
            names["\(fields[0]) \(fields[3])"] = fields[start...pidIndex].joined(separator: " ")
        }
        return names
    }

    /// Addresses on the host interface that carries `vmIP` (the vmnet bridge),
    /// including its IPv6 link-local address.
    static func bridgeAddresses(forVMIP vmIP: String) -> [IPAddress] {
        guard let vm = IPAddress(vmIP) else { return [] }
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var byInterface: [String: [IPAddress]] = [:]
        var candidates: [String] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            defer { cursor = entry.pointee.ifa_next }
            guard let pointer = entry.pointee.ifa_addr, let address = IPAddress(sockaddr: UnsafePointer(pointer)) else { continue }
            let name = String(cString: entry.pointee.ifa_name)
            byInterface[name, default: []].append(address)
            if let mask = entry.pointee.ifa_netmask.flatMap({ IPAddress(sockaddr: UnsafePointer($0)) }),
               case let .v4(bits) = mask,
               let network = IPNetwork(address: address, prefixLength: bits.nonzeroBitCount),
               address.isIPv4, network.contains(vm), address != vm {
                candidates.append(name)
            }
        }
        // Prefer the vmnet bridge: a VPN utun with a wide netmask can also "contain" the VM IP.
        return pickBridge(candidates).flatMap { byInterface[$0] } ?? []
    }

    static func pickBridge(_ candidates: [String]) -> String? {
        candidates.first { $0.hasPrefix("bridge") } ?? candidates.first { !$0.hasPrefix("utun") } ?? candidates.last
    }
}

/// The verdict on reachable host listeners for one VM.
struct HostListenerReport: Sendable, Equatable {
    let reachable: [HostListener]
    let accepted: [HostListener]
    let policy: NetworkConfig.HostListenerPolicy

    init(reachable: [HostListener], policy: NetworkConfig.HostListenerPolicy, accepted patterns: [HostListenerPattern]) {
        self.policy = policy
        self.accepted = reachable.filter { listener in patterns.contains { $0.matches(listener) } }
        self.reachable = reachable.filter { listener in !patterns.contains { $0.matches(listener) } }
    }

    var failed: Bool {
        policy == .deny && !reachable.isEmpty
    }
}

/// Unprivileged TCP connect probe of the host's own bridge address: what a
/// guest would reach on that address (wildcard or bridge-bound listeners).
/// Connections go to a local address and never leave the host.
enum TCPConnectSweep {
    /// Services macOS and common developer tools expose on all interfaces.
    static let wellKnownPorts = [
        21, 22, 23, 25, 53, 80, 88, 111, 139, 443, 445, 548, 631, 873, 993, 2049, 3000, 3283, 3306, 3689,
        4000, 4200, 5000, 5001, 5173, 5432, 5900, 6379, 7000, 7100, 8000, 8008, 8080, 8443, 8888, 9000,
        9090, 9200, 11434, 27017, 49152, 62078
    ]

    static func openPorts(on addresses: [IPAddress], ports: [Int], batch: Int = 128, timeoutMillis: Int32 = 300) async -> [Int] {
        var open = Set<Int>()
        for address in addresses {
            guard case let .v4(value) = address else { continue }
            open.formUnion(await Task.detached { sweep(ipv4: value, ports: ports, batch: batch, timeoutMillis: timeoutMillis) }.value)
        }
        return open.sorted()
    }

    private static func sweep(ipv4: UInt32, ports: [Int], batch: Int, timeoutMillis: Int32) -> [Int] {
        var open: [Int] = []
        var start = 0
        while start < ports.count {
            let end = min(start + batch, ports.count)
            var sockets: [(Int32, Int)] = []
            for port in ports[start..<end] {
                let fd = socket(AF_INET, SOCK_STREAM, 0)
                guard fd >= 0 else { continue }
                _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
                var address = sockaddr_in()
                address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                address.sin_family = sa_family_t(AF_INET)
                address.sin_port = in_port_t(UInt16(port).bigEndian)
                address.sin_addr = in_addr(s_addr: ipv4.bigEndian)
                let result = withUnsafePointer(to: &address) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
                }
                if result == 0 {
                    open.append(port)
                    close(fd)
                } else if errno == EINPROGRESS {
                    sockets.append((fd, port))
                } else {
                    close(fd)
                }
            }
            var pending = sockets.map { pollfd(fd: $0.0, events: Int16(POLLOUT), revents: 0) }
            if !pending.isEmpty {
                _ = poll(&pending, nfds_t(pending.count), timeoutMillis)
            }
            for (index, entry) in pending.enumerated() {
                var error: Int32 = 0
                var length = socklen_t(MemoryLayout<Int32>.size)
                if entry.revents & Int16(POLLOUT) != 0,
                   getsockopt(entry.fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0, error == 0 {
                    open.append(sockets[index].1)
                }
                close(entry.fd)
            }
            start = end
        }
        return open
    }
}
