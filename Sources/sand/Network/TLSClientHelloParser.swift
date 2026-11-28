import Foundation

struct TLSClientHello: Equatable, Sendable {
    let serverName: String?
    /// Encrypted Client Hello present: the visible SNI is only the outer
    /// (public) name. Residual risk: the proxy cannot see the inner name.
    let hasEncryptedClientHello: Bool
}

/// A small, bounded parser for the first TLS record a client sends. The proxy
/// requires that record to be a ClientHello whose SNI equals the CONNECT host.
enum TLSClientHelloParser {
    enum Result: Equatable, Sendable {
        case needMoreData
        case notTLS
        case malformed
        case clientHello(TLSClientHello)
    }

    static let maxRecordLength = 16_384 + 2_048

    static func parse(_ bytes: [UInt8]) -> Result {
        guard let first = bytes.first else { return .needMoreData }
        // Handshake record, TLS major version 3.
        guard first == 0x16 else { return .notTLS }
        guard bytes.count >= 5 else { return .needMoreData }
        guard bytes[1] == 0x03 else { return .notTLS }
        let recordLength = Int(bytes[3]) << 8 | Int(bytes[4])
        guard recordLength > 0, recordLength <= maxRecordLength else { return .malformed }
        guard bytes.count >= 5 + recordLength else { return .needMoreData }
        var reader = Reader(bytes: Array(bytes[5..<(5 + recordLength)]))
        guard let handshakeType = reader.u8(), handshakeType == 0x01 else { return .malformed }
        guard reader.u24() != nil else { return .malformed }
        // A ClientHello fragmented across records is parsed as far as the first
        // record goes; if SNI is not in it, the result has no server name.
        guard reader.skip(2 + 32) else { return .malformed } // legacy_version, random
        guard let sessionLength = reader.u8(), reader.skip(Int(sessionLength)) else { return .malformed }
        guard let suitesLength = reader.u16(), suitesLength % 2 == 0, reader.skip(Int(suitesLength)) else { return .malformed }
        guard let compressionLength = reader.u8(), reader.skip(Int(compressionLength)) else { return .malformed }
        guard let extensionsLength = reader.u16() else {
            return .clientHello(TLSClientHello(serverName: nil, hasEncryptedClientHello: false))
        }
        var extensions = Reader(bytes: reader.take(min(Int(extensionsLength), reader.remaining)) ?? [])
        var serverName: String?
        var hasECH = false
        while extensions.remaining >= 4 {
            guard let type = extensions.u16(), let length = extensions.u16(),
                  let body = extensions.take(Int(length)) else {
                break
            }
            switch type {
            case 0x0000:
                guard let name = parseServerName(body) else { return .malformed }
                serverName = name
            case 0xfe0d:
                hasECH = true
            default:
                break
            }
        }
        return .clientHello(TLSClientHello(serverName: serverName, hasEncryptedClientHello: hasECH))
    }

    private static func parseServerName(_ body: [UInt8]) -> String? {
        var reader = Reader(bytes: body)
        guard let listLength = reader.u16(), Int(listLength) <= reader.remaining else { return nil }
        var list = Reader(bytes: reader.take(Int(listLength)) ?? [])
        while list.remaining >= 3 {
            guard let nameType = list.u8(), let nameLength = list.u16(), let name = list.take(Int(nameLength)) else {
                return nil
            }
            if nameType == 0 {
                guard !name.isEmpty, name.allSatisfy({ $0 >= 0x21 && $0 < 0x7f }) else { return nil }
                return String(decoding: name, as: UTF8.self).lowercased()
            }
        }
        return nil
    }

    private struct Reader {
        let bytes: [UInt8]
        var offset = 0

        var remaining: Int { bytes.count - offset }

        mutating func u8() -> UInt8? {
            guard remaining >= 1 else { return nil }
            defer { offset += 1 }
            return bytes[offset]
        }

        mutating func u16() -> UInt16? {
            guard remaining >= 2 else { return nil }
            defer { offset += 2 }
            return UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
        }

        mutating func u24() -> Int? {
            guard remaining >= 3 else { return nil }
            defer { offset += 3 }
            return Int(bytes[offset]) << 16 | Int(bytes[offset + 1]) << 8 | Int(bytes[offset + 2])
        }

        mutating func skip(_ count: Int) -> Bool {
            guard count >= 0, remaining >= count else { return false }
            offset += count
            return true
        }

        mutating func take(_ count: Int) -> [UInt8]? {
            guard count >= 0, remaining >= count else { return nil }
            defer { offset += count }
            return Array(bytes[offset..<(offset + count)])
        }
    }

    /// Builds a minimal ClientHello record (tests and the proxy self-test).
    static func makeClientHello(serverName: String?, ech: Bool = false) -> [UInt8] {
        var extensions: [UInt8] = []
        if let serverName {
            let name = Array(serverName.utf8)
            let entry: [UInt8] = [0x00] + be16(name.count) + name
            let list = be16(entry.count) + entry
            extensions += [0x00, 0x00] + be16(list.count) + list
        }
        if ech {
            extensions += [0xfe, 0x0d] + be16(4) + [0, 1, 2, 3]
        }
        var body: [UInt8] = [0x03, 0x03] + [UInt8](repeating: 0x11, count: 32)
        body += [0x00]                       // session id
        body += be16(2) + [0x13, 0x01]       // one cipher suite
        body += [0x01, 0x00]                 // null compression
        body += be16(extensions.count) + extensions
        let handshake: [UInt8] = [0x01, UInt8(body.count >> 16 & 0xff), UInt8(body.count >> 8 & 0xff), UInt8(body.count & 0xff)] + body
        return [0x16, 0x03, 0x01] + be16(handshake.count) + handshake
    }

    private static func be16(_ value: Int) -> [UInt8] {
        [UInt8(value >> 8 & 0xff), UInt8(value & 0xff)]
    }
}
