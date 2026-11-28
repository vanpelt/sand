import Foundation

/// `provisioner.config.broker`: register through the Sand broker instead of a
/// local GitHub App key. Sand then holds no App key; it authenticates as a
/// device and every job passes the admission gate (ADR 0001).
struct BrokerConfig: Decodable, Sendable, Equatable {
    let url: String
    let deviceId: String
    let deviceKeyPath: String

    static func isValidDeviceId(_ id: String) -> Bool {
        id.range(of: "^[a-z0-9][a-z0-9-]{0,62}$", options: .regularExpression) != nil
    }

    /// HTTPS, or plain HTTP to a loopback host (the local mock only).
    static func urlProblem(_ value: String) -> String? {
        guard let components = URLComponents(string: value), let scheme = components.scheme?.lowercased(), let host = components.host, !host.isEmpty else {
            return "provisioner.config.broker.url must be an absolute http(s) URL."
        }
        if components.user != nil || components.password != nil || components.query != nil || components.fragment != nil {
            return "provisioner.config.broker.url must not contain credentials, a query or a fragment."
        }
        switch scheme {
        case "https":
            return nil
        case "http":
            return ["127.0.0.1", "::1", "localhost"].contains(host.lowercased()) ? nil : "provisioner.config.broker.url must use https unless the host is loopback (the local mock)."
        default:
            return "provisioner.config.broker.url must use https."
        }
    }
}
