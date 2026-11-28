import Foundation
import Yams

/// `sand broker mock --config <yml>`. Development only: the mock holds a GitHub
/// App key on the developer's own Mac and must never front enterprise endpoints.
struct MockBrokerConfig: Decodable, Sendable {
    struct Listen: Decodable, Sendable {
        var host = "127.0.0.1"
        var port = 8787
    }

    struct GitHub: Decodable, Sendable {
        let appId: Int
        var privateKeyPath: String?
        var privateKeyKeychainLabel: String?
        let owner: String
        let repository: String
    }

    struct Device: Decodable, Sendable {
        struct Owner: Decodable, Sendable {
            let login: String
            let id: Int
        }

        let id: String
        let publicKeyPath: String
        let owner: Owner
        var revoked: Bool?
    }

    struct Limits: Decodable, Sendable {
        var allocationsPerHour: Int? = 30
        var deniesPerHourBeforeCircuitOpen: Int? = 6
        var circuitOpenSeconds: Int? = 3600

        var allocationsLimit: Int { allocationsPerHour ?? 30 }
        var denialLimit: Int { deniesPerHourBeforeCircuitOpen ?? 6 }
        var circuitSeconds: Int { circuitOpenSeconds ?? 3600 }
    }

    var listen = Listen()
    let github: GitHub
    let devices: [Device]
    let policy: AdmissionPolicy
    var limits = Limits()

    private enum CodingKeys: String, CodingKey {
        case listen, github, devices, policy, limits
    }

    init(listen: Listen = Listen(), github: GitHub, devices: [Device], policy: AdmissionPolicy, limits: Limits = Limits()) {
        self.listen = listen
        self.github = github
        self.devices = devices
        self.policy = policy
        self.limits = limits
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        listen = try container.decodeIfPresent(Listen.self, forKey: .listen) ?? Listen()
        github = try container.decode(GitHub.self, forKey: .github)
        devices = try container.decode([Device].self, forKey: .devices)
        policy = try container.decode(AdmissionPolicy.self, forKey: .policy)
        limits = try container.decodeIfPresent(Limits.self, forKey: .limits) ?? Limits()
    }

    static func load(path: String) throws -> MockBrokerConfig {
        let contents = try String(contentsOfFile: Config.expandPath(path), encoding: .utf8)
        return try YAMLDecoder().decode(MockBrokerConfig.self, from: contents)
    }

    /// Problems that stop the mock from starting.
    func validationErrors() -> [String] {
        var errors: [String] = []
        if !LoopbackHTTPServer.isLoopbackHost(listen.host) {
            errors.append("listen.host must be 127.0.0.1 or localhost; the mock broker is development only")
        }
        if !(1...65535).contains(listen.port) {
            errors.append("listen.port must be 1-65535")
        }
        if github.appId <= 0 {
            errors.append("github.appId must be greater than 0")
        }
        if (github.privateKeyPath == nil) == (github.privateKeyKeychainLabel == nil) {
            errors.append("github requires exactly one of privateKeyPath or privateKeyKeychainLabel")
        }
        if devices.isEmpty {
            errors.append("devices must list at least one device")
        }
        for device in devices where !BrokerConfig.isValidDeviceId(device.id) {
            errors.append("device id \(device.id) must match ^[a-z0-9][a-z0-9-]{0,49}$")
        }
        if !(1...AdmissionTimeouts.maxBrokerWaitSeconds).contains(policy.waitSeconds) {
            errors.append("policy.admissionWaitSeconds must be 1-\(AdmissionTimeouts.maxBrokerWaitSeconds) (below the relay's \(Int(AdmissionTimeouts.relaySeconds)) s timeout)")
        }
        if TimeInterval(policy.deadlineSeconds) < AdmissionTimeouts.minimumVerifierDeadline {
            errors.append("policy.admissionDeadlineSeconds must be at least \(Int(AdmissionTimeouts.minimumVerifierDeadline)) (above the hook and relay timeouts)")
        }
        if let mode = policy.tierAPreconditions, !["enforce", "warn"].contains(mode) {
            errors.append("policy.tierAPreconditions must be enforce or warn")
        }
        if policy.labels.isEmpty || policy.workflows.isEmpty || policy.branches.isEmpty {
            errors.append("policy.labels, policy.workflows and policy.branches must not be empty")
        }
        return errors
    }
}
