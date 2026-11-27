import Darwin
import Foundation

enum LoopbackClientError: Error {
    case socket(Int32)
    case connect(Int32)
    case timeout
}

/// A tiny blocking TCP client for 127.0.0.1, used by the proxy self-test and
/// unit tests. Call from a background task, never from the proxy's queue.
final class LoopbackClient: @unchecked Sendable {
    private let descriptor: Int32

    init(port: UInt16, timeout: TimeInterval = 10) throws {
        descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw LoopbackClientError.socket(errno) }
        var value = timeval(tv_sec: Int(timeout), tv_usec: Int32((timeout - floor(timeout)) * 1_000_000))
        setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &value, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &value, socklen_t(MemoryLayout<timeval>.size))
        var noSigPipe: Int32 = 1
        setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard result == 0 else {
            let code = errno
            Darwin.close(descriptor)
            throw LoopbackClientError.connect(code)
        }
    }

    deinit {
        Darwin.close(descriptor)
    }

    func send(_ bytes: [UInt8]) throws {
        var offset = 0
        while offset < bytes.count {
            let written = bytes[offset...].withUnsafeBytes { Darwin.send(descriptor, $0.baseAddress, $0.count, 0) }
            guard written > 0 else { throw LoopbackClientError.socket(errno) }
            offset += written
        }
    }

    func send(_ text: String) throws {
        try send(Array(text.utf8))
    }

    /// Reads until `\r\n\r\n` and returns the header text.
    func readHeader(limit: Int = 16_384) throws -> String {
        var collected: [UInt8] = []
        var byte: UInt8 = 0
        while collected.count < limit {
            let count = recv(descriptor, &byte, 1, 0)
            guard count == 1 else {
                if collected.isEmpty { throw LoopbackClientError.timeout }
                break
            }
            collected.append(byte)
            if collected.suffix(4) == [13, 10, 13, 10] { break }
        }
        return String(decoding: collected, as: UTF8.self)
    }

    /// Reads until `count` bytes arrived, EOF, or the receive timeout.
    func read(upTo count: Int) -> [UInt8] {
        var collected: [UInt8] = []
        var buffer = [UInt8](repeating: 0, count: 65_536)
        while collected.count < count {
            let received = buffer.withUnsafeMutableBytes { recv(descriptor, $0.baseAddress, min($0.count, count - collected.count), 0) }
            guard received > 0 else { break }
            collected.append(contentsOf: buffer[0..<received])
        }
        return collected
    }

    /// True once the peer closed the connection (or the timeout elapsed with no data).
    func isClosedByPeer() -> Bool {
        var byte: UInt8 = 0
        return recv(descriptor, &byte, 1, 0) <= 0
    }

    /// Status code from `HTTP/1.1 NNN ...`.
    static func statusCode(of header: String) -> Int? {
        let parts = header.split(separator: " ", maxSplits: 2)
        guard parts.count >= 2 else { return nil }
        return Int(parts[1])
    }

    /// Sends `CONNECT target` and returns the response status (nil if none).
    static func connectStatus(port: UInt16, target: String, timeout: TimeInterval = 20) -> Int? {
        guard let client = try? LoopbackClient(port: port, timeout: timeout),
              (try? client.send("CONNECT \(target) HTTP/1.1\r\nHost: \(target)\r\n\r\n")) != nil,
              let header = try? client.readHeader() else {
            return nil
        }
        return statusCode(of: header)
    }
}
