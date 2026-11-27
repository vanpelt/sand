import Foundation
import Security

enum KeychainSigningError: LocalizedError {
    case lookupFailed(label: String, status: OSStatus)
    case unsupportedRSAKey(label: String)
    case signingFailed(label: String)

    var errorDescription: String? {
        switch self {
        case .lookupFailed(let label, let status):
            let message = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
            return "Could not find or access RSA private key '\(label)' in the Keychain: \(message)"
        case .unsupportedRSAKey(let label):
            return "Keychain key '\(label)' does not support RSA PKCS#1 v1.5 SHA-256 signing."
        case .signingFailed(let label):
            return "Keychain could not sign a GitHub App JWT using key '\(label)'."
        }
    }
}

/// Resolves the private key on each request, rather than retaining a non-Sendable
/// SecKey reference. The RSA key never needs to be exported to the application.
enum KeychainRS256 {
    static func sign(_ message: Data, keyLabel: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrLabel as String: keyLabel,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecReturnRef as String: true
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let result else {
            throw KeychainSigningError.lookupFailed(label: keyLabel, status: status)
        }

        let key = result as! SecKey
        let algorithm: SecKeyAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
        guard SecKeyIsAlgorithmSupported(key, .sign, algorithm) else {
            throw KeychainSigningError.unsupportedRSAKey(label: keyLabel)
        }

        var signingError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(key, algorithm, message as CFData, &signingError) else {
            if let signingError {
                throw signingError.takeRetainedValue() as Error
            }
            throw KeychainSigningError.signingFailed(label: keyLabel)
        }
        return signature as Data
    }
}
