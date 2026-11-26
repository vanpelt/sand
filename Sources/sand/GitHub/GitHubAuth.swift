import Foundation
import SwiftJWT

struct GitHubClaims: Claims, Sendable {
    let iss: String
    let iat: Date
    let exp: Date

    func encode() throws -> String {
        let jsonEncoder = JSONEncoder()
        jsonEncoder.dateEncodingStrategy = .custom { date, encoder in
            var container = encoder.singleValueContainer()
            try container.encode(Int(date.timeIntervalSince1970))
        }
        let data = try jsonEncoder.encode(self)
        return JWTEncoder.base64urlEncodedString(data: data)
    }
}

protocol GitHubAuthenticating: Sendable {
    func token(now: Date) throws -> String
}

enum GitHubAuthError: Error {
    case exactlyOnePrivateKeySourceRequired
}

struct GitHubAuth: GitHubAuthenticating, Sendable {
    private enum KeySource: Sendable {
        case pem(Data)
        case keychain(label: String)
    }

    let appId: Int
    private let keySource: KeySource

    init(
        appId: Int,
        privateKeyPath: String? = nil,
        privateKeyKeychainLabel: String? = nil
    ) throws {
        self.appId = appId
        if let path = privateKeyPath, privateKeyKeychainLabel == nil {
            self.keySource = .pem(try Data(contentsOf: URL(fileURLWithPath: path)))
        } else if let label = privateKeyKeychainLabel, privateKeyPath == nil {
            self.keySource = .keychain(label: label)
        } else {
            throw GitHubAuthError.exactlyOnePrivateKeySourceRequired
        }
    }

    func token(now: Date = Date()) throws -> String {
        let issuedAt = now.addingTimeInterval(-10)
        let expiresAt = now.addingTimeInterval(60)
        let claims = GitHubClaims(iss: String(appId), iat: issuedAt, exp: expiresAt)

        switch keySource {
        case .pem(let key):
            var jwt = JWT(claims: claims)
            return try jwt.sign(using: JWTSigner.rs256(privateKey: key))
        case .keychain(let label):
            // RS256 signs the JWS signing input, not the JWT payload alone.
            // Security.framework performs the SHA-256 hashing and RSA signing.
            let header = Data(#"{"alg":"RS256","typ":"JWT"}"#.utf8)
            let signingInput = JWTEncoder.base64urlEncodedString(data: header)
                + "." + (try claims.encode())
            let signature = try KeychainRS256.sign(Data(signingInput.utf8), keyLabel: label)
            return signingInput + "." + JWTEncoder.base64urlEncodedString(data: signature)
        }
    }
}
