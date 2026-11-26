import Foundation
import Security
import XCTest
@testable import sand

final class KeychainSigningTests: XCTestCase {
    func testSignsGitHubAppJWTWithKeychainRSAKey() throws {
        let label = "sand-test-\(UUID().uuidString)"
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrLabel as String: label
            ]
        ]

        var creationError: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &creationError) else {
            if let creationError {
                throw creationError.takeRetainedValue() as Error
            }
            XCTFail("Could not generate a temporary RSA key")
            return
        }

        defer {
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrLabel as String: label
            ]
            _ = SecItemDelete(query as CFDictionary)
        }

        let auth = try GitHubAuth(appId: 123, privateKeyKeychainLabel: label)
        let jwt = try auth.token(now: Date(timeIntervalSince1970: 1000))
        let parts = jwt.split(separator: ".", omittingEmptySubsequences: false)
        XCTAssertEqual(parts.count, 3)
        guard parts.count == 3 else { return }

        let claims = try decodeJWTClaims(jwt)
        XCTAssertEqual(claims["iss"] as? String, "123")
        XCTAssertEqual((claims["iat"] as? NSNumber)?.intValue, 990)
        XCTAssertEqual((claims["exp"] as? NSNumber)?.intValue, 1060)

        let signature = try base64URLDecode(String(parts[2]))
        let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(privateKey))
        var verificationError: Unmanaged<CFError>?
        let verified = SecKeyVerifySignature(
            publicKey,
            .rsaSignatureMessagePKCS1v15SHA256,
            signingInput as CFData,
            signature as CFData,
            &verificationError
        )
        XCTAssertTrue(verified, "The signature must verify against the generated public key")
    }

    func testMissingKeyFailsRatherThanFallingBackToPEM() throws {
        let auth = try GitHubAuth(appId: 123, privateKeyKeychainLabel: "sand-missing-\(UUID().uuidString)")
        XCTAssertThrowsError(try auth.token())
    }

    func testAuthRequiresExactlyOneKeySource() {
        XCTAssertThrowsError(try GitHubAuth(appId: 123))
        XCTAssertThrowsError(try GitHubAuth(
            appId: 123,
            privateKeyPath: "/tmp/key.pem",
            privateKeyKeychainLabel: "sand-key"
        ))
    }
}
