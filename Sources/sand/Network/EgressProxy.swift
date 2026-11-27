import Foundation
import Network

enum EgressProxyError: Error, CustomStringConvertible {
    case listenerFailed(String)
    case notStarted

    var description: String {
        switch self {
        case let .listenerFailed(reason):
            return "egress proxy listener failed: \(reason)"
        case .notStarted:
            return "egress proxy is not running"
        }
    }
}

protocol EgressProxying: Sendable {
    /// Starts listening on 127.0.0.1 (port 0 picks a free one) and returns the bound port.
    func start(port: UInt16) async throws -> UInt16
    func stop()
    /// True once the listener failed or was stopped.
    var hasFailed: Bool { get }
}

/// Per-VM HTTPS CONNECT proxy bound to loopback only. It enforces the
/// hostname allowlist outside the guest, resolves with the host's system
/// resolver (inheriting VPN split DNS), runs every resolved address through
/// the destination guard, and requires the tunnel's first TLS record to be a
/// ClientHello whose SNI equals the CONNECT host.
final class EgressProxy: EgressProxying, @unchecked Sendable {
    struct Limits: Sendable {
        var maxTunnels = 256
        var maxHeaderBytes = 8 * 1024
        var headerTimeout: TimeInterval = 10
        var clientHelloTimeout: TimeInterval = 10
        var connectTimeout: TimeInterval = 15
        var idleTimeout: TimeInterval = 600
    }

    let policy: EgressPolicy
    let destinationGuard: DestinationGuard
    let resolver: HostResolving
    let audit: NetworkAudit
    let limits: Limits

    private let queue = DispatchQueue(label: "sand.egress-proxy")
    private var listener: NWListener?
    private var sessions: [ObjectIdentifier: ProxySession] = [:]
    private var failed = false
    private var stopped = false
    private var sweepTimer: DispatchSourceTimer?
    private var counters = Counters()

    struct Counters: Sendable, Equatable {
        var allowed = 0
        var denied = 0
        var bytesUp = 0
        var bytesDown = 0
        var deniedByHost: [String: Int] = [:]
    }

    init(policy: EgressPolicy, destinationGuard: DestinationGuard, resolver: HostResolving, audit: NetworkAudit, limits: Limits = Limits()) {
        self.policy = policy
        self.destinationGuard = destinationGuard
        self.resolver = resolver
        self.audit = audit
        self.limits = limits
    }

    var hasFailed: Bool {
        queue.sync { failed || stopped }
    }

    var activeTunnels: Int {
        queue.sync { sessions.count }
    }

    var summary: Counters {
        queue.sync { counters }
    }

    func start(port requestedPort: UInt16 = 0) async throws -> UInt16 {
        let parameters = NWParameters.tcp
        let bindPort = requestedPort == 0 ? NWEndpoint.Port.any : (NWEndpoint.Port(rawValue: requestedPort) ?? .any)
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: .ipv4(.loopback), port: bindPort)
        parameters.allowLocalEndpointReuse = false
        let listener = try NWListener(using: parameters)
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, Error>) in
            let once = ResumeOnce()
            listener.stateUpdateHandler = { [weak self] state in
                guard let self else { return }
                switch state {
                case .ready:
                    if let port = listener.port?.rawValue, once.claim() {
                        continuation.resume(returning: port)
                    }
                case let .failed(error):
                    self.failed = true
                    self.audit.emit("network.enforcement.lost", level: .error, ["component": "proxy", "reason": "\(error)"])
                    if once.claim() {
                        continuation.resume(throwing: EgressProxyError.listenerFailed("\(error)"))
                    }
                case .cancelled:
                    self.stopped = true
                    if once.claim() {
                        continuation.resume(throwing: EgressProxyError.listenerFailed("cancelled"))
                    }
                default:
                    break
                }
            }
            listener.newConnectionHandler = { [weak self] connection in
                self?.accept(connection)
            }
            queue.async {
                self.listener = listener
                self.startSweep()
                listener.start(queue: self.queue)
            }
        }
    }

    func stop() {
        queue.async {
            guard !self.stopped else { return }
            self.stopped = true
            self.sweepTimer?.cancel()
            self.listener?.cancel()
            for session in self.sessions.values {
                session.close(reason: "proxy-stopped")
            }
        }
    }

    /// Test hook: simulate a listener failure.
    func failForTesting() {
        queue.sync {
            failed = true
            listener?.cancel()
        }
    }

    // MARK: - Internals (all on `queue`)

    private func accept(_ connection: NWConnection) {
        guard Self.isLoopback(connection.endpoint) else {
            connection.cancel()
            return
        }
        let session = ProxySession(client: connection, proxy: self)
        let overLimit = sessions.count >= limits.maxTunnels
        // Always retained until it closes; the callbacks only hold it weakly.
        sessions[ObjectIdentifier(session)] = session
        if overLimit {
            session.reject(status: 503, reason: "tunnel-limit", host: nil, port: nil)
            return
        }
        session.start()
    }

    fileprivate func sessionEnded(_ session: ProxySession) {
        sessions.removeValue(forKey: ObjectIdentifier(session))
    }

    fileprivate func record(denied host: String?, _ fields: [String: String]) {
        counters.denied += 1
        if let host {
            counters.deniedByHost[host, default: 0] += 1
        }
        audit.emit("network.connect", level: .warning, fields.merging(["decision": "deny"]) { $1 })
    }

    fileprivate func record(allowed fields: [String: String], up: Int, down: Int) {
        counters.allowed += 1
        counters.bytesUp += up
        counters.bytesDown += down
        audit.emit("network.connect", level: .info, fields.merging(["decision": "allow"]) { $1 })
    }

    fileprivate var proxyQueue: DispatchQueue { queue }

    private func startSweep() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 30, repeating: 30)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            let now = Date()
            for session in self.sessions.values where now.timeIntervalSince(session.lastActivity) > self.limits.idleTimeout {
                session.close(reason: "idle-timeout")
            }
        }
        timer.resume()
        sweepTimer = timer
    }

    static func isLoopback(_ endpoint: NWEndpoint) -> Bool {
        guard case let .hostPort(host, _) = endpoint else { return false }
        switch host {
        case let .ipv4(address):
            return address.isLoopback
        case let .ipv6(address):
            return address.isLoopback || address.asIPv4?.isLoopback == true
        default:
            return false
        }
    }
}

/// Parsed `CONNECT host:port HTTP/1.1`.
struct ConnectRequest: Equatable, Sendable {
    let host: String
    let port: Int

    enum ParseError: Error, Equatable {
        case badRequest
        case methodNotAllowed
    }

    static func parse(header: String) throws -> ConnectRequest {
        guard let requestLine = header.components(separatedBy: "\r\n").first else { throw ParseError.badRequest }
        let parts = requestLine.split(separator: " ", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3, parts[2].hasPrefix("HTTP/1.") else { throw ParseError.badRequest }
        guard parts[0] == "CONNECT" else { throw ParseError.methodNotAllowed }
        let authority = parts[1]
        var host: String
        var portText: Substring
        if authority.hasPrefix("[") {
            guard let close = authority.firstIndex(of: "]") else { throw ParseError.badRequest }
            host = String(authority[authority.index(after: authority.startIndex)..<close])
            let rest = authority[authority.index(after: close)...]
            guard rest.hasPrefix(":") else { throw ParseError.badRequest }
            portText = rest.dropFirst()
        } else {
            guard let colon = authority.lastIndex(of: ":") else { throw ParseError.badRequest }
            host = String(authority[..<colon])
            portText = authority[authority.index(after: colon)...]
        }
        host = DomainPattern.normalize(host)
        guard !host.isEmpty, host.count <= 253, !portText.isEmpty, portText.allSatisfy({ $0.isASCII && $0.isNumber }),
              let port = Int(portText), (1...65_535).contains(port) else {
            throw ParseError.badRequest
        }
        return ConnectRequest(host: host, port: port)
    }
}

private final class ProxySession: @unchecked Sendable {
    let client: NWConnection
    unowned let proxy: EgressProxy
    var upstream: NWConnection?
    var buffer: [UInt8] = []
    var request: ConnectRequest?
    var chosenIP: IPAddress?
    var steered = false
    var bytesUp = 0
    var bytesDown = 0
    var lastActivity = Date()
    let started = Date()
    var phaseTimer: DispatchWorkItem?
    var clientDone = false
    var upstreamDone = false
    var closed = false
    var established = false

    init(client: NWConnection, proxy: EgressProxy) {
        self.client = client
        self.proxy = proxy
    }

    var queue: DispatchQueue { proxy.proxyQueue }

    func start() {
        client.stateUpdateHandler = { [weak self] state in
            switch state {
            case .failed, .cancelled:
                self?.close(reason: nil)
            default:
                break
            }
        }
        client.start(queue: queue)
        armTimer(proxy.limits.headerTimeout, reason: "header-timeout")
        readHeader()
    }

    func reject(status: Int, reason: String, host: String?, port: Int?) {
        var fields = ["reason": reason]
        if let host { fields["host"] = host }
        if let port { fields["port"] = String(port) }
        proxy.record(denied: host, fields)
        let text = Self.statusText(status)
        let response = "HTTP/1.1 \(status) \(text)\r\nX-Sand-Deny: \(NetworkAuditEvent.sanitize(reason))\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        if client.state == .setup {
            client.start(queue: queue)
        }
        client.send(content: Data(response.utf8), contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { [weak self] _ in
            self?.close(reason: nil)
        })
    }

    func close(reason: String?) {
        guard !closed else { return }
        closed = true
        phaseTimer?.cancel()
        client.cancel()
        upstream?.cancel()
        if established, let request {
            var fields = [
                "host": request.host,
                "port": String(request.port),
                "ip": chosenIP?.description ?? "",
                "steered": String(steered),
                "bytes_up": String(bytesUp),
                "bytes_down": String(bytesDown),
                "duration": String(format: "%.1f", Date().timeIntervalSince(started))
            ]
            if let reason { fields["closed"] = reason }
            proxy.record(allowed: fields, up: bytesUp, down: bytesDown)
        }
        proxy.sessionEnded(self)
    }

    private func armTimer(_ seconds: TimeInterval, reason: String) {
        phaseTimer?.cancel()
        let item = DispatchWorkItem { [weak self] in
            guard let self, !self.closed else { return }
            if self.established {
                self.established = false
                self.proxy.record(denied: self.request?.host, ["reason": reason, "host": self.request?.host ?? "", "port": self.request.map { String($0.port) } ?? ""])
                self.close(reason: reason)
            } else if self.request == nil {
                self.reject(status: 408, reason: reason, host: nil, port: nil)
            } else {
                self.reject(status: 504, reason: reason, host: self.request?.host, port: self.request?.port)
            }
        }
        phaseTimer = item
        queue.asyncAfter(deadline: .now() + seconds, execute: item)
    }

    private func readHeader() {
        client.receive(minimumIncompleteLength: 1, maximumLength: 4096) { [weak self] data, _, isComplete, error in
            guard let self, !self.closed else { return }
            if let data, !data.isEmpty {
                self.buffer.append(contentsOf: data)
            }
            if let end = Self.headerEnd(self.buffer) {
                guard end <= self.proxy.limits.maxHeaderBytes else {
                    self.reject(status: 400, reason: "header-too-large", host: nil, port: nil)
                    return
                }
                let header = String(decoding: self.buffer[0..<end], as: UTF8.self)
                self.buffer.removeFirst(end + 4)
                self.handle(header: header)
                return
            }
            if self.buffer.count > self.proxy.limits.maxHeaderBytes {
                self.reject(status: 400, reason: "header-too-large", host: nil, port: nil)
                return
            }
            if isComplete || error != nil {
                self.close(reason: nil)
                return
            }
            self.readHeader()
        }
    }

    private func handle(header: String) {
        let request: ConnectRequest
        do {
            request = try ConnectRequest.parse(header: header)
        } catch ConnectRequest.ParseError.methodNotAllowed {
            reject(status: 405, reason: "method-not-allowed", host: nil, port: nil)
            return
        } catch {
            reject(status: 400, reason: "bad-request", host: nil, port: nil)
            return
        }
        self.request = request
        let policy = proxy.policy
        if let literal = IPAddress(request.host) {
            guard policy.allowsLiteral(literal, port: request.port) else {
                reject(status: 403, reason: "ip-literal", host: request.host, port: request.port)
                return
            }
            connect(to: literal, steered: false)
            return
        }
        guard policy.allows(host: request.host, port: request.port) else {
            reject(status: 403, reason: "not-allowlisted", host: request.host, port: request.port)
            return
        }
        let resolver = proxy.resolver
        let guardrail = proxy.destinationGuard
        let steeredName = policy.isSteered(request.host)
        armTimer(proxy.limits.connectTimeout, reason: "resolve-timeout")
        Task { [weak self] in
            let result: Result<[IPAddress], Error> = await Result { try await resolver.resolve(request.host) }
            self?.queue.async { [weak self] in
                guard let self, !self.closed else { return }
                switch result {
                case let .failure(error):
                    self.reject(status: 502, reason: "resolve-failed:\(error)", host: request.host, port: request.port)
                case let .success(addresses):
                    switch guardrail.check(host: request.host, port: request.port, resolved: addresses, steeredName: steeredName) {
                    case let .deny(reason):
                        self.reject(status: 403, reason: reason, host: request.host, port: request.port)
                    case let .allow(address, steered):
                        self.connect(to: address, steered: steered)
                    }
                }
            }
        }
    }

    private func connect(to address: IPAddress, steered: Bool) {
        guard let request, let port = NWEndpoint.Port(rawValue: UInt16(request.port)) else { return }
        chosenIP = address
        self.steered = steered
        let host: NWEndpoint.Host
        switch address {
        case .v4:
            guard let value = IPv4Address(address.description) else { return }
            host = .ipv4(value)
        case .v6:
            guard let value = IPv6Address(address.description) else { return }
            host = .ipv6(value)
        }
        let parameters = NWParameters.tcp
        parameters.preferNoProxies = true
        let upstream = NWConnection(host: host, port: port, using: parameters)
        self.upstream = upstream
        armTimer(proxy.limits.connectTimeout, reason: "connect-timeout")
        upstream.stateUpdateHandler = { [weak self] state in
            guard let self, !self.closed else { return }
            switch state {
            case .ready:
                self.didConnect()
            case let .failed(error):
                if self.established {
                    self.close(reason: "upstream-failed")
                } else {
                    self.reject(status: 502, reason: "connect-failed:\(error)", host: request.host, port: request.port)
                }
            case let .waiting(error):
                if !self.established {
                    self.reject(status: 502, reason: "connect-failed:\(error)", host: request.host, port: request.port)
                }
            case .cancelled:
                if self.established { self.close(reason: nil) }
            default:
                break
            }
        }
        upstream.start(queue: queue)
    }

    private func didConnect() {
        guard !established else { return }
        established = true
        client.send(content: Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8), completion: .contentProcessed { _ in })
        armTimer(proxy.limits.clientHelloTimeout, reason: "client-hello-timeout")
        inspectClientHello()
    }

    private func inspectClientHello() {
        switch TLSClientHelloParser.parse(buffer) {
        case .needMoreData:
            guard buffer.count <= TLSClientHelloParser.maxRecordLength + 5 else {
                denyEstablished("client-hello-too-large")
                return
            }
            client.receive(minimumIncompleteLength: 1, maximumLength: 16_384) { [weak self] data, _, isComplete, error in
                guard let self, !self.closed else { return }
                if let data, !data.isEmpty {
                    self.buffer.append(contentsOf: data)
                    self.inspectClientHello()
                } else if isComplete || error != nil {
                    self.established = false
                    self.close(reason: nil)
                } else {
                    self.inspectClientHello()
                }
            }
        case .notTLS:
            denyEstablished("not-tls")
        case .malformed:
            denyEstablished("malformed-client-hello")
        case let .clientHello(hello):
            guard let request else { return }
            guard let name = hello.serverName else {
                denyEstablished(IPAddress(request.host) != nil ? "no-sni-literal" : "no-sni")
                return
            }
            // Literal targets (reviewed allowedCIDRs) carry no SNI expectation beyond presence.
            guard IPAddress(request.host) != nil || DomainPattern.normalize(name) == request.host else {
                denyEstablished("sni-mismatch")
                return
            }
            phaseTimer?.cancel()
            let first = Data(buffer)
            buffer = []
            bytesUp += first.count
            upstream?.send(content: first, completion: .contentProcessed { _ in })
            pumpClientToUpstream()
            pumpUpstreamToClient()
        }
    }

    private func denyEstablished(_ reason: String) {
        established = false
        proxy.record(denied: request?.host, ["reason": reason, "host": request?.host ?? "", "port": request.map { String($0.port) } ?? "", "ip": chosenIP?.description ?? ""])
        close(reason: reason)
    }

    private func pumpClientToUpstream() {
        client.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            guard let self, !self.closed, let upstream = self.upstream else { return }
            if let data, !data.isEmpty {
                self.bytesUp += data.count
                self.lastActivity = Date()
                upstream.send(content: data, completion: .contentProcessed { [weak self] sendError in
                    guard let self, !self.closed else { return }
                    if sendError != nil {
                        self.close(reason: "upstream-send-failed")
                    } else if isComplete {
                        self.finishClient()
                    } else {
                        self.pumpClientToUpstream()
                    }
                })
                return
            }
            if isComplete {
                self.finishClient()
            } else if error != nil {
                self.close(reason: "client-error")
            } else {
                self.pumpClientToUpstream()
            }
        }
    }

    private func pumpUpstreamToClient() {
        upstream?.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            guard let self, !self.closed else { return }
            if let data, !data.isEmpty {
                self.bytesDown += data.count
                self.lastActivity = Date()
                self.client.send(content: data, completion: .contentProcessed { [weak self] sendError in
                    guard let self, !self.closed else { return }
                    if sendError != nil {
                        self.close(reason: "client-send-failed")
                    } else if isComplete {
                        self.finishUpstream()
                    } else {
                        self.pumpUpstreamToClient()
                    }
                })
                return
            }
            if isComplete {
                self.finishUpstream()
            } else if error != nil {
                self.close(reason: "upstream-error")
            } else {
                self.pumpUpstreamToClient()
            }
        }
    }

    private func finishClient() {
        clientDone = true
        upstream?.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in })
        if upstreamDone { close(reason: nil) }
    }

    private func finishUpstream() {
        upstreamDone = true
        client.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in })
        if clientDone { close(reason: nil) }
    }

    static func headerEnd(_ bytes: [UInt8]) -> Int? {
        guard bytes.count >= 4 else { return nil }
        for index in 0...(bytes.count - 4) where bytes[index] == 13 && bytes[index + 1] == 10 && bytes[index + 2] == 13 && bytes[index + 3] == 10 {
            return index
        }
        return nil
    }

    static func statusText(_ status: Int) -> String {
        switch status {
        case 400: return "Bad Request"
        case 403: return "Forbidden"
        case 405: return "Method Not Allowed"
        case 408: return "Request Timeout"
        case 502: return "Bad Gateway"
        case 503: return "Service Unavailable"
        case 504: return "Gateway Timeout"
        default: return "Error"
        }
    }
}

/// Guards a continuation that several state callbacks may try to resume.
/// Only touched from the proxy's serial queue.
private final class ResumeOnce: @unchecked Sendable {
    private var done = false

    func claim() -> Bool {
        guard !done else { return false }
        done = true
        return true
    }
}
