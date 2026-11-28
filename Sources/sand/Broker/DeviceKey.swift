import CryptoKit
import Foundation

enum DeviceKeyError: Error, CustomStringConvertible {
    case unreadable(String)
    case invalidPEM(String)
    case insecurePermissions(String)
    case exists(String)

    var description: String {
        switch self {
        case let .unreadable(path): return "device key \(path) is not readable"
        case let .invalidPEM(path): return "device key \(path) is not a P-256 PEM key"
        case let .insecurePermissions(path): return "device key \(path) must have mode 0600"
        case let .exists(path): return "refusing to overwrite existing device key \(path)"
        }
    }
}

/// The device's P-256 signing key for broker challenge/response
/// (`docs/broker-api.md` §2.1). Development keys live in a 0600 PEM file;
/// Phase 2 moves to `SecureEnclave.P256.Signing`.
struct DeviceKey: Sendable {
    let privateKey: P256.Signing.PrivateKey

    var publicKey: P256.Signing.PublicKey { privateKey.publicKey }

    /// Hex SHA-256 of the SubjectPublicKeyInfo DER.
    var keyId: String { Self.keyId(for: publicKey) }

    static func keyId(for publicKey: P256.Signing.PublicKey) -> String {
        SHA256.hash(data: publicKey.derRepresentation).map { String(format: "%02x", $0) }.joined()
    }

    static func generate() -> DeviceKey {
        DeviceKey(privateKey: P256.Signing.PrivateKey())
    }

    static func load(path: String) throws -> DeviceKey {
        let expanded = Config.expandPath(path)
        guard let text = try? String(contentsOfFile: expanded, encoding: .utf8) else {
            throw DeviceKeyError.unreadable(expanded)
        }
        if let mode = (try? FileManager.default.attributesOfItem(atPath: expanded))?[.posixPermissions] as? Int, mode & 0o077 != 0 {
            throw DeviceKeyError.insecurePermissions(expanded)
        }
        do {
            return DeviceKey(privateKey: try P256.Signing.PrivateKey(pemRepresentation: text))
        } catch {
            throw DeviceKeyError.invalidPEM(expanded)
        }
    }

    static func loadPublicKey(path: String) throws -> P256.Signing.PublicKey {
        let expanded = Config.expandPath(path)
        guard let text = try? String(contentsOfFile: expanded, encoding: .utf8) else {
            throw DeviceKeyError.unreadable(expanded)
        }
        do {
            return try P256.Signing.PublicKey(pemRepresentation: text)
        } catch {
            throw DeviceKeyError.invalidPEM(expanded)
        }
    }

    /// Writes `<dir>/<deviceId>.key.pem` (0600) and `<dir>/<deviceId>.pub.pem` (0644).
    @discardableResult
    func save(directory: String, deviceId: String) throws -> (privatePath: String, publicPath: String) {
        let dir = Config.expandPath(directory)
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let privatePath = (dir as NSString).appendingPathComponent("\(deviceId).key.pem")
        let publicPath = (dir as NSString).appendingPathComponent("\(deviceId).pub.pem")
        guard !FileManager.default.fileExists(atPath: privatePath) else {
            throw DeviceKeyError.exists(privatePath)
        }
        // Created with 0600 from the start: the key is never world-readable, even briefly.
        guard FileManager.default.createFile(atPath: privatePath, contents: Data(privateKey.pemRepresentation.utf8), attributes: [.posixPermissions: 0o600]) else {
            throw DeviceKeyError.unreadable(privatePath)
        }
        try Data((publicKey.pemRepresentation + "\n").utf8).write(to: URL(fileURLWithPath: publicPath))
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: publicPath)
        return (privatePath, publicPath)
    }

    /// Exactly the bytes the device signs; no trailing newline after the challenge.
    static func signingMessage(deviceId: String, challengeId: String, challenge: String) -> Data {
        Data("sand-broker-v1\ndevice-session\n\(deviceId)\n\(challengeId)\n\(challenge)".utf8)
    }

    /// Raw 64-byte `r||s`, base64url.
    func sign(deviceId: String, challengeId: String, challenge: String) throws -> String {
        let message = Self.signingMessage(deviceId: deviceId, challengeId: challengeId, challenge: challenge)
        return Base64URL.encode(try privateKey.signature(for: message).rawRepresentation)
    }

    static func verify(signature: String, publicKey: P256.Signing.PublicKey, deviceId: String, challengeId: String, challenge: String) -> Bool {
        guard let raw = Base64URL.decode(signature), let parsed = try? P256.Signing.ECDSASignature(rawRepresentation: raw) else {
            return false
        }
        return publicKey.isValidSignature(parsed, for: signingMessage(deviceId: deviceId, challengeId: challengeId, challenge: challenge))
    }
}
