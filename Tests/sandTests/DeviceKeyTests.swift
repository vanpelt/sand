import CryptoKit
import Foundation
import Testing
@testable import sand

@Suite struct DeviceKeyTests {
    @Test func signingMessageIsExact() {
        let message = DeviceKey.signingMessage(deviceId: "dev-laptop", challengeId: "chl_01JDQ7Z6S8V4N3K2M1P0R9T8W7", challenge: "AAAA")
        #expect(String(decoding: message, as: UTF8.self) == "sand-broker-v1\ndevice-session\ndev-laptop\nchl_01JDQ7Z6S8V4N3K2M1P0R9T8W7\nAAAA")
        #expect(message.last != UInt8(ascii: "\n"))
    }

    @Test func keygenWritesMode0600AndReloads() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        let key = DeviceKey.generate()
        let paths = try key.save(directory: dir, deviceId: "dev-laptop")
        let mode = try FileManager.default.attributesOfItem(atPath: paths.privatePath)[.posixPermissions] as? Int
        #expect(mode == 0o600)
        let loaded = try DeviceKey.load(path: paths.privatePath)
        #expect(loaded.keyId == key.keyId)
        #expect(DeviceKey.keyId(for: try DeviceKey.loadPublicKey(path: paths.publicPath)) == key.keyId)
        #expect(throws: DeviceKeyError.self) { try key.save(directory: dir, deviceId: "dev-laptop") }
    }

    @Test func groupReadableKeyIsRefused() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        let paths = try DeviceKey.generate().save(directory: dir, deviceId: "dev")
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: paths.privatePath)
        #expect(throws: DeviceKeyError.self) { _ = try DeviceKey.load(path: paths.privatePath) }
    }

    @Test func signVerifyRoundTripsAndRejectsTampering() throws {
        let key = DeviceKey.generate()
        let signature = try key.sign(deviceId: "dev", challengeId: "chl_1", challenge: "abc")
        #expect(Base64URL.decode(signature)?.count == 64)
        #expect(DeviceKey.verify(signature: signature, publicKey: key.publicKey, deviceId: "dev", challengeId: "chl_1", challenge: "abc"))
        #expect(!DeviceKey.verify(signature: signature, publicKey: key.publicKey, deviceId: "dev", challengeId: "chl_1", challenge: "abd"))
        #expect(!DeviceKey.verify(signature: signature, publicKey: key.publicKey, deviceId: "other", challengeId: "chl_1", challenge: "abc"))
        #expect(!DeviceKey.verify(signature: signature, publicKey: DeviceKey.generate().publicKey, deviceId: "dev", challengeId: "chl_1", challenge: "abc"))
        #expect(!DeviceKey.verify(signature: "not base64url!", publicKey: key.publicKey, deviceId: "dev", challengeId: "chl_1", challenge: "abc"))
    }

    @Test func keyIdIsStableHexSHA256OfSPKI() {
        let key = DeviceKey.generate()
        #expect(key.keyId == key.keyId)
        #expect(key.keyId.count == 64)
        let expected = SHA256.hash(data: key.publicKey.derRepresentation).map { String(format: "%02x", $0) }.joined()
        #expect(key.keyId == expected)
    }
}
