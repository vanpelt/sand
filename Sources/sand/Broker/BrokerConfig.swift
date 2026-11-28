import Foundation

/// `provisioner.config.broker`: register through the Sand broker instead of a
/// local GitHub App key. Sand then holds no App key; it authenticates as a
/// device and every job passes the admission gate (ADR 0001).
struct BrokerConfig: Decodable, Sendable, Equatable {
    let url: String
    let deviceId: String
    let deviceKeyPath: String
    /// Required (true) for a plain-http loopback broker: the local mock is
    /// unauthenticated, so any same-user process on that port could answer
    /// as an always-allow broker. Never set it on an enterprise device.
    var allowDevelopmentBroker: Bool?

    var isDevelopmentBroker: Bool {
        URLComponents(string: url)?.scheme?.lowercased() == "http"
    }

    static func isValidDeviceId(_ id: String) -> Bool {
        id.range(of: #"^[a-z0-9][a-z0-9-]{0,49}\z"#, options: .regularExpression) != nil
    }

    /// HTTPS, or plain HTTP to a loopback host (the local mock only).
    static func urlProblem(_ value: String, allowDevelopmentBroker: Bool = false) -> String? {
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
            guard ["127.0.0.1", "::1", "localhost"].contains(host.lowercased()) else {
                return "provisioner.config.broker.url must use https unless the host is loopback (the local mock)."
            }
            return allowDevelopmentBroker ? nil : "provisioner.config.broker.url uses plain http (the local mock broker); set provisioner.config.broker.allowDevelopmentBroker: true to accept an unauthenticated development broker."
        default:
            return "provisioner.config.broker.url must use https."
        }
    }
}
