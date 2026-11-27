import Foundation
import Network
import Testing
@testable import sand

/// Loopback echo server standing in for an upstream TLS endpoint.
private final class EchoServer: @unchecked Sendable {
    let listener: NWListener
    let queue = DispatchQueue(label: "echo")
    var connections: [NWConnection] = []

    init() throws {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
        listener = try NWListener(using: parameters)
    }

    func start() async throws -> UInt16 {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, Error>) in
            listener.stateUpdateHandler = { [listener] state in
                if case .ready = state, let port = listener.port?.rawValue {
                    continuation.resume(returning: port)
                }
            }
            listener.newConnectionHandler = { [weak self] connection in
                guard let self else { return }
                self.connections.append(connection)
                connection.start(queue: self.queue)
                self.echo(connection)
            }
            listener.start(queue: queue)
        }
    }

    private func echo(_ connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, isComplete, error in
            if let data, !data.isEmpty {
                connection.send(content: data, completion: .contentProcessed { _ in self?.echo(connection) })
            } else if isComplete || error != nil {
                connection.cancel()
            } else {
                self?.echo(connection)
            }
        }
    }

    func stop() {
        listener.cancel()
        for connection in connections { connection.cancel() }
    }
}

private struct Harness {
    let proxy: EgressProxy
    let proxyPort: UInt16
    let echo: EchoServer
    let echoPort: UInt16
    let recorder: AuditRecorder

    static func make(maxTunnels: Int = 256) async throws -> Harness {
        let echo = try EchoServer()
        let echoPort = try await echo.start()
        let loopback = IPAddress("127.0.0.1")!
        let policy = EgressPolicy(
            rules: [
                DomainRule(pattern: DomainPattern(kind: .exact("echo.test")), port: Int(echoPort)),
                DomainRule(pattern: DomainPattern(kind: .exact("rebind.test")), port: Int(echoPort)),
                DomainRule(pattern: DomainPattern(kind: .exact("echo.test")), port: 22)
            ],
            steeredNames: [],
            verify: .basic,
            extraCIDRs: []
        )
        let resolver = StaticHostResolver(table: [
            "echo.test": [loopback],
            "rebind.test": [IPAddress("10.0.0.1")!]
        ])
        let recorder = AuditRecorder()
        var limits = EgressProxy.Limits()
        limits.maxTunnels = maxTunnels
        limits.headerTimeout = 3
        limits.clientHelloTimeout = 3
        let proxy = EgressProxy(
            policy: policy,
            destinationGuard: DestinationGuard(hostFacts: HostFacts(), testAllowance: [loopback]),
            resolver: resolver,
            audit: recorder.audit,
            limits: limits
        )
        let port = try await proxy.start(port: 0)
        return Harness(proxy: proxy, proxyPort: port, echo: echo, echoPort: echoPort, recorder: recorder)
    }

    func stop() {
        proxy.stop()
        echo.stop()
    }

    func client() throws -> LoopbackClient {
        try LoopbackClient(port: proxyPort, timeout: 5)
    }
}

private func background<T: Sendable>(_ work: @escaping @Sendable () throws -> T) async throws -> T {
    try await Task.detached { try work() }.value
}

@Suite(.serialized) struct EgressProxyTests {
    @Test func allowedConnectSplicesBytesAfterMatchingClientHello() async throws {
        let harness = try await Harness.make()
        defer { harness.stop() }
        let echoPort = harness.echoPort
        let (status, echoed, hello) = try await background {
            let client = try harness.client()
            try client.send("CONNECT echo.test:\(echoPort) HTTP/1.1\r\nHost: echo.test\r\n\r\n")
            let header = try client.readHeader()
            let hello = TLSClientHelloParser.makeClientHello(serverName: "echo.test") + Array("payload".utf8)
            try client.send(hello)
            return (LoopbackClient.statusCode(of: header), client.read(upTo: hello.count), hello)
        }
        #expect(status == 200)
        #expect(echoed == hello)
        try await Task.sleep(nanoseconds: 200_000_000)
        harness.proxy.stop()
        try await Task.sleep(nanoseconds: 200_000_000)
        let allow = harness.recorder.events.first { $0.fields["decision"] == "allow" }
        #expect(allow?.fields["host"] == "echo.test")
        #expect(Int(allow?.fields["bytes_up"] ?? "0") == hello.count)
    }

    @Test func deniedHostGets403AndAnAuditEvent() async throws {
        let harness = try await Harness.make()
        defer { harness.stop() }
        let status = try await background { LoopbackClient.connectStatus(port: harness.proxyPort, target: "example.com:443") }
        #expect(status == 403)
        #expect(harness.recorder.events.contains { $0.name == "network.connect" && $0.fields["decision"] == "deny" && $0.fields["reason"] == "not-allowlisted" && $0.fields["host"] == "example.com" })
    }

    @Test func ipLiteralIsDenied() async throws {
        let harness = try await Harness.make()
        defer { harness.stop() }
        let port = harness.echoPort
        #expect(try await background { LoopbackClient.connectStatus(port: harness.proxyPort, target: "127.0.0.1:\(port)") } == 403)
        #expect(try await background { LoopbackClient.connectStatus(port: harness.proxyPort, target: "[::1]:443") } == 403)
    }

    @Test func portMustMatchTheRule() async throws {
        let harness = try await Harness.make()
        defer { harness.stop() }
        // echo.test is only allowed on the echo port (and an explicit :22 rule in this policy).
        #expect(try await background { LoopbackClient.connectStatus(port: harness.proxyPort, target: "echo.test:443") } == 403)
    }

    @Test func rebindingToPrivateAddressIsDenied() async throws {
        let harness = try await Harness.make()
        defer { harness.stop() }
        let port = harness.echoPort
        #expect(try await background { LoopbackClient.connectStatus(port: harness.proxyPort, target: "rebind.test:\(port)") } == 403)
        #expect(harness.recorder.events.contains { $0.fields["reason"]?.contains("private") == true })
    }

    @Test func nonConnectMethodGets405() async throws {
        let harness = try await Harness.make()
        defer { harness.stop() }
        let status = try await background { () -> Int? in
            let client = try harness.client()
            try client.send("GET http://echo.test/ HTTP/1.1\r\nHost: echo.test\r\n\r\n")
            return LoopbackClient.statusCode(of: try client.readHeader())
        }
        #expect(status == 405)
    }

    @Test func oversizedHeaderGets400() async throws {
        let harness = try await Harness.make()
        defer { harness.stop() }
        let status = try await background { () -> Int? in
            let client = try harness.client()
            try? client.send("CONNECT echo.test:443 HTTP/1.1\r\nX-Pad: " + String(repeating: "a", count: 9_000) + "\r\n\r\n")
            return LoopbackClient.statusCode(of: try client.readHeader())
        }
        #expect(status == 400)
    }

    @Test func sniMismatchClosesTheTunnel() async throws {
        let harness = try await Harness.make()
        defer { harness.stop() }
        let port = harness.echoPort
        let closed = try await background { () -> Bool in
            let client = try harness.client()
            try client.send("CONNECT echo.test:\(port) HTTP/1.1\r\n\r\n")
            _ = try client.readHeader()
            try client.send(TLSClientHelloParser.makeClientHello(serverName: "evil.example.com"))
            return client.isClosedByPeer()
        }
        #expect(closed)
        #expect(harness.recorder.events.contains { $0.fields["reason"] == "sni-mismatch" })
    }

    @Test func nonTLSFirstByteClosesTheTunnel() async throws {
        let harness = try await Harness.make()
        defer { harness.stop() }
        let port = harness.echoPort
        let closed = try await background { () -> Bool in
            let client = try harness.client()
            try client.send("CONNECT echo.test:\(port) HTTP/1.1\r\n\r\n")
            _ = try client.readHeader()
            try client.send("GET / HTTP/1.1\r\n\r\n")
            return client.isClosedByPeer()
        }
        #expect(closed)
        #expect(harness.recorder.events.contains { $0.fields["reason"] == "not-tls" })
    }

    @Test func concurrentTunnelCapIsEnforced() async throws {
        let harness = try await Harness.make(maxTunnels: 2)
        defer { harness.stop() }
        let port = harness.proxyPort
        let status = try await background { () -> Int? in
            // Two idle clients hold both slots in the header phase.
            let first = try LoopbackClient(port: port, timeout: 5)
            let second = try LoopbackClient(port: port, timeout: 5)
            try first.send("C")
            try second.send("C")
            Thread.sleep(forTimeInterval: 0.3)
            let status = LoopbackClient.connectStatus(port: port, target: "example.com:443", timeout: 5)
            _ = (first, second)
            return status
        }
        #expect(status == 503)
        #expect(harness.recorder.events.contains { $0.fields["reason"] == "tunnel-limit" })
    }

    @Test func listenerFailureIsReported() async throws {
        let harness = try await Harness.make()
        defer { harness.stop() }
        #expect(!harness.proxy.hasFailed)
        harness.proxy.failForTesting()
        #expect(harness.proxy.hasFailed)
    }

    @Test func connectRequestParsing() throws {
        #expect(try ConnectRequest.parse(header: "CONNECT GitHub.com.:443 HTTP/1.1\r\nHost: x") == ConnectRequest(host: "github.com", port: 443))
        #expect(try ConnectRequest.parse(header: "CONNECT [2001:db8::1]:8443 HTTP/1.1") == ConnectRequest(host: "2001:db8::1", port: 8443))
        #expect(throws: ConnectRequest.ParseError.methodNotAllowed) { try ConnectRequest.parse(header: "GET / HTTP/1.1") }
        #expect(throws: ConnectRequest.ParseError.badRequest) { try ConnectRequest.parse(header: "CONNECT github.com HTTP/1.1") }
        #expect(throws: ConnectRequest.ParseError.badRequest) { try ConnectRequest.parse(header: "CONNECT github.com:0 HTTP/1.1") }
        #expect(throws: ConnectRequest.ParseError.badRequest) { try ConnectRequest.parse(header: "garbage") }
    }
}

@Suite struct TLSClientHelloParserTests {
    @Test func extractsSNI() {
        #expect(TLSClientHelloParser.parse(TLSClientHelloParser.makeClientHello(serverName: "GitHub.com")) == .clientHello(TLSClientHello(serverName: "github.com", hasEncryptedClientHello: false)))
    }

    @Test func helloWithoutSNI() {
        #expect(TLSClientHelloParser.parse(TLSClientHelloParser.makeClientHello(serverName: nil)) == .clientHello(TLSClientHello(serverName: nil, hasEncryptedClientHello: false)))
    }

    @Test func truncatedRecordNeedsMoreData() {
        let hello = TLSClientHelloParser.makeClientHello(serverName: "github.com")
        #expect(TLSClientHelloParser.parse(Array(hello.prefix(3))) == .needMoreData)
        #expect(TLSClientHelloParser.parse(Array(hello.dropLast(4))) == .needMoreData)
        #expect(TLSClientHelloParser.parse([]) == .needMoreData)
    }

    @Test func flagsEncryptedClientHello() {
        #expect(TLSClientHelloParser.parse(TLSClientHelloParser.makeClientHello(serverName: "public.example.com", ech: true)) == .clientHello(TLSClientHello(serverName: "public.example.com", hasEncryptedClientHello: true)))
    }

    @Test func rejectsNonTLSAndMalformedInput() {
        #expect(TLSClientHelloParser.parse(Array("GET / HTTP/1.1".utf8)) == .notTLS)
        #expect(TLSClientHelloParser.parse([0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00]) == .malformed)
        #expect(TLSClientHelloParser.parse([0x16, 0x03, 0x01, 0xff, 0xff]) == .malformed)
    }
}
