import Foundation
import Testing
@testable import sand

@Suite struct LoopbackHTTPServerTests {
    private func echoServer(cap: Int = 64, timeout: TimeInterval = 10) -> LoopbackHTTPServer {
        LoopbackHTTPServer(maxBodyBytes: cap, readTimeout: timeout) { request in
            .text(200, "\(request.method) \(request.path) \(request.body.count) \(String(decoding: request.body, as: UTF8.self))")
        }
    }

    private func exchange(_ port: UInt16, _ raw: String) async throws -> String {
        try await Task.detached {
            let client = try LoopbackClient(port: port, timeout: 5)
            try client.send(raw)
            return String(decoding: client.read(upTo: 65_536), as: UTF8.self)
        }.value
    }

    @Test func refusesNonLoopbackBind() async {
        let server = echoServer()
        await #expect(throws: LoopbackHTTPServerError.self) { _ = try await server.start(host: "0.0.0.0") }
        await #expect(throws: LoopbackHTTPServerError.self) { _ = try await server.start(host: "192.168.1.10") }
    }

    @Test func parsesContentLengthBody() async throws {
        let server = echoServer()
        let port = try await server.start()
        defer { server.stop() }
        let reply = try await exchange(port, "POST /v1/admission HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello")
        #expect(reply.hasPrefix("HTTP/1.1 200 OK"))
        #expect(reply.hasSuffix("POST /v1/admission 5 hello"))
    }

    @Test func bodyArrivingInPiecesIsAssembled() async throws {
        let server = echoServer()
        let port = try await server.start()
        defer { server.stop() }
        let reply = try await Task.detached { () -> String in
            let client = try LoopbackClient(port: port, timeout: 5)
            try client.send("POST /x HTTP/1.1\r\nContent-Length: 6\r\n\r\nabc")
            usleep(100_000)
            try client.send("def")
            return String(decoding: client.read(upTo: 65_536), as: UTF8.self)
        }.value
        #expect(reply.hasSuffix("POST /x 6 abcdef"))
    }

    @Test func oversizedBodyIs413() async throws {
        let server = echoServer(cap: 8)
        let port = try await server.start()
        defer { server.stop() }
        let reply = try await exchange(port, "POST /x HTTP/1.1\r\nContent-Length: 9\r\n\r\n123456789")
        #expect(reply.hasPrefix("HTTP/1.1 413"))
    }

    @Test func chunkedEncodingIsRejected() async throws {
        let server = echoServer()
        let port = try await server.start()
        defer { server.stop() }
        let reply = try await exchange(port, "POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
        #expect(reply.hasPrefix("HTTP/1.1 501"))
    }

    @Test func incompleteRequestTimesOut() async throws {
        let server = echoServer(timeout: 0.3)
        let port = try await server.start()
        defer { server.stop() }
        let reply = try await exchange(port, "POST /x HTTP/1.1\r\nContent-Length: 10\r\n\r\nabc")
        #expect(reply.hasPrefix("HTTP/1.1 408"))
    }

    @Test func parserSplitsQueryAndLowercasesHeaders() {
        let server = echoServer()
        guard case let .complete(request) = server.parse(Data("GET /v1/health?x=1 HTTP/1.1\r\nSand-Request-Id: abc\r\n\r\n".utf8)) else {
            Issue.record("expected a complete request")
            return
        }
        #expect(request.path == "/v1/health")
        #expect(request.query == "x=1")
        #expect(request.header("sand-request-id") == "abc")
    }
}
