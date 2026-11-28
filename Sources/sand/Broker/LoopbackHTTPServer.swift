import Foundation
import Network

struct HTTPRequest: Sendable, Equatable {
    let method: String
    /// Path without the query string.
    let path: String
    let query: String?
    /// Lowercased header names.
    let headers: [String: String]
    let body: Data

    func header(_ name: String) -> String? { headers[name.lowercased()] }
}

struct HTTPResponse: Sendable, Equatable {
    var status: Int
    var headers: [String: String] = [:]
    var body = Data()

    static func text(_ status: Int, _ text: String) -> HTTPResponse {
        HTTPResponse(status: status, headers: ["Content-Type": "text/plain; charset=utf-8"], body: Data(text.utf8))
    }

    static func json<T: Encodable>(_ status: Int, _ value: T, headers: [String: String] = [:]) -> HTTPResponse {
        var all = headers
        all["Content-Type"] = "application/json"
        return HTTPResponse(status: status, headers: all, body: (try? BrokerJSON.encoder().encode(value)) ?? Data("{}".utf8))
    }

    static func reasonPhrase(_ status: Int) -> String {
        switch status {
        case 200: return "OK"
        case 201: return "Created"
        case 202: return "Accepted"
        case 204: return "No Content"
        case 400: return "Bad Request"
        case 401: return "Unauthorized"
        case 403: return "Forbidden"
        case 404: return "Not Found"
        case 405: return "Method Not Allowed"
        case 408: return "Request Timeout"
        case 409: return "Conflict"
        case 411: return "Length Required"
        case 413: return "Payload Too Large"
        case 422: return "Unprocessable Content"
        case 429: return "Too Many Requests"
        case 501: return "Not Implemented"
        case 502: return "Bad Gateway"
        case 503: return "Service Unavailable"
        default: return "Status"
        }
    }

    func serialized() -> Data {
        var head = "HTTP/1.1 \(status) \(Self.reasonPhrase(status))\r\n"
        var all = headers
        all["Content-Length"] = String(body.count)
        all["Connection"] = "close"
        for key in all.keys.sorted() {
            head += "\(key): \(all[key] ?? "")\r\n"
        }
        head += "\r\n"
        return Data(head.utf8) + body
    }
}

enum LoopbackHTTPServerError: Error, CustomStringConvertible {
    case notLoopback(String)
    case listenerFailed(String)

    var description: String {
        switch self {
        case let .notLoopback(host): return "refusing to listen on non-loopback address \(host)"
        case let .listenerFailed(detail): return "listener failed: \(detail)"
        }
    }
}

/// A minimal HTTP/1.1 server bound to 127.0.0.1 only, shared by the per-VM
/// admission relay and the mock broker. One request per connection,
/// `Content-Length` bodies only (chunked is refused), a body cap and a read
/// timeout. Follows the `EgressProxy` NWListener pattern.
final class LoopbackHTTPServer: @unchecked Sendable {
    typealias Handler = @Sendable (HTTPRequest) async -> HTTPResponse

    let maxBodyBytes: Int
    let maxHeaderBytes: Int
    let readTimeout: TimeInterval
    private let handler: Handler
    private let queue = DispatchQueue(label: "sand.loopback-http")
    private var listener: NWListener?
    private var connections: [ObjectIdentifier: NWConnection] = [:]
    private var stopped = false

    init(maxBodyBytes: Int, maxHeaderBytes: Int = 8192, readTimeout: TimeInterval = 10, handler: @escaping Handler) {
        self.maxBodyBytes = maxBodyBytes
        self.maxHeaderBytes = maxHeaderBytes
        self.readTimeout = readTimeout
        self.handler = handler
    }

    static func isLoopbackHost(_ host: String) -> Bool {
        host == "127.0.0.1" || host == "localhost"
    }

    /// Starts listening on `host:port` (port 0 picks one) and returns the bound port.
    func start(host: String = "127.0.0.1", port: UInt16 = 0) async throws -> UInt16 {
        guard Self.isLoopbackHost(host) else {
            throw LoopbackHTTPServerError.notLoopback(host)
        }
        let parameters = NWParameters.tcp
        let bindPort = port == 0 ? NWEndpoint.Port.any : (NWEndpoint.Port(rawValue: port) ?? .any)
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: .ipv4(.loopback), port: bindPort)
        parameters.allowLocalEndpointReuse = false
        let listener = try NWListener(using: parameters)
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, Error>) in
            let once = ResumeOnce()
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if let port = listener.port?.rawValue, once.claim() {
                        continuation.resume(returning: port)
                    }
                case let .failed(error):
                    if once.claim() { continuation.resume(throwing: LoopbackHTTPServerError.listenerFailed("\(error)")) }
                case .cancelled:
                    if once.claim() { continuation.resume(throwing: LoopbackHTTPServerError.listenerFailed("cancelled")) }
                default:
                    break
                }
            }
            listener.newConnectionHandler = { [weak self] connection in
                self?.accept(connection)
            }
            queue.async {
                self.listener = listener
                listener.start(queue: self.queue)
            }
        }
    }

    func stop() {
        queue.async {
            guard !self.stopped else { return }
            self.stopped = true
            self.listener?.cancel()
            for connection in self.connections.values {
                connection.cancel()
            }
            self.connections = [:]
        }
    }

    // MARK: - Internals (on `queue`)

    private func accept(_ connection: NWConnection) {
        guard !stopped, Self.isLoopbackEndpoint(connection.endpoint) else {
            connection.cancel()
            return
        }
        let id = ObjectIdentifier(connection)
        connections[id] = connection
        connection.stateUpdateHandler = { [weak self] state in
            switch state {
            case .cancelled, .failed:
                self?.queue.async { self?.connections.removeValue(forKey: id) }
            default:
                break
            }
        }
        connection.start(queue: queue)
        let state = ConnectionState()
        let timeout = DispatchWorkItem { [weak self] in
            guard !state.responded else { return }
            self?.respond(connection, state: state, .text(408, "request timeout"))
        }
        state.timeout = timeout
        queue.asyncAfter(deadline: .now() + readTimeout, execute: timeout)
        receive(connection, state: state)
    }

    private func receive(_ connection: NWConnection, state: ConnectionState) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            guard let self, !state.responded else { return }
            if let data { state.buffer.append(data) }
            switch self.parse(state.buffer) {
            case let .complete(request):
                state.timeout?.cancel()
                state.handling = true
                let handler = self.handler
                Task {
                    let response = await handler(request)
                    self.queue.async { self.respond(connection, state: state, response) }
                }
            case let .reject(response):
                self.respond(connection, state: state, response)
            case .incomplete:
                if isComplete || error != nil {
                    state.timeout?.cancel()
                    state.responded = true
                    connection.cancel()
                } else {
                    self.receive(connection, state: state)
                }
            }
        }
    }

    private func respond(_ connection: NWConnection, state: ConnectionState, _ response: HTTPResponse) {
        guard !state.responded else { return }
        state.responded = true
        state.timeout?.cancel()
        connection.send(content: response.serialized(), completion: .contentProcessed { _ in
            connection.cancel()
        })
    }

    enum ParseResult {
        case incomplete
        case complete(HTTPRequest)
        case reject(HTTPResponse)
    }

    /// Parses one request from `buffer`. Pure; exposed for tests.
    func parse(_ buffer: Data) -> ParseResult {
        let separator = Data("\r\n\r\n".utf8)
        guard let range = buffer.range(of: separator) else {
            return buffer.count > maxHeaderBytes ? .reject(.text(400, "header too large")) : .incomplete
        }
        guard range.lowerBound <= maxHeaderBytes, let head = String(data: buffer[buffer.startIndex..<range.lowerBound], encoding: .utf8) else {
            return .reject(.text(400, "bad request"))
        }
        let lines = head.components(separatedBy: "\r\n")
        let requestLine = lines[0].split(separator: " ", omittingEmptySubsequences: false)
        guard requestLine.count == 3, requestLine[2].hasPrefix("HTTP/1.") else {
            return .reject(.text(400, "bad request"))
        }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":") else { return .reject(.text(400, "bad header")) }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            guard !name.isEmpty, headers[name] == nil else { return .reject(.text(400, "bad header")) }
            headers[name] = value
        }
        if headers["transfer-encoding"] != nil {
            return .reject(.text(501, "transfer-encoding not supported"))
        }
        var length = 0
        if let value = headers["content-length"] {
            guard let parsed = Int(value), parsed >= 0 else { return .reject(.text(400, "bad content-length")) }
            length = parsed
        }
        if length > maxBodyBytes {
            return .reject(.text(413, "body too large"))
        }
        let bodyStart = range.upperBound
        let available = buffer.distance(from: bodyStart, to: buffer.endIndex)
        if available < length {
            return .incomplete
        }
        if available > length {
            // One request per connection; no pipelining.
            return .reject(.text(400, "unexpected data after body"))
        }
        let target = String(requestLine[1])
        let parts = target.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
        return .complete(HTTPRequest(
            method: String(requestLine[0]),
            path: String(parts[0]),
            query: parts.count > 1 ? String(parts[1]) : nil,
            headers: headers,
            body: Data(buffer[bodyStart..<buffer.index(bodyStart, offsetBy: length)])
        ))
    }

    private static func isLoopbackEndpoint(_ endpoint: NWEndpoint) -> Bool {
        guard case let .hostPort(host, _) = endpoint else { return false }
        switch host {
        case let .ipv4(address): return address.isLoopback
        case let .ipv6(address): return address.isLoopback || "\(address)".hasPrefix("::ffff:127.")
        default: return false
        }
    }
}

private final class ConnectionState: @unchecked Sendable {
    var buffer = Data()
    var responded = false
    var handling = false
    var timeout: DispatchWorkItem?
}
