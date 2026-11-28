import Foundation

/// `vm.run.network`: either a profile (secure defaults, the proxy-based egress
/// allowlist) or a legacy explicit softnet mode.
///
/// Profiles are enforced by a backend: `auto` (the default: softnet when a
/// safely installed privileged softnet exists, otherwise hostOnly), `hostOnly`
/// (tart `--net-host`, no root) or `softnet` (needs a privileged softnet binary).
///
/// An omitted `network` key means `profile: github`. Unrestricted shared NAT is
/// only available by writing `mode: shared` explicitly.
struct NetworkConfig: Decodable, Sendable, Equatable {
    enum Profile: String, Sendable, CaseIterable {
        /// No direct guest egress plus the host-side allowlisting CONNECT proxy.
        case github
        /// No direct guest egress and no proxy: host SSH only.
        case offline
    }

    /// Which enforcement backend a profile asks for.
    enum BackendChoice: String, Sendable, CaseIterable {
        /// Tart's host-only network (`--net-host`): no root, no route off the host.
        case hostOnly
        /// Softnet deny-all with a host-SSH allow: needs softnet to be setuid root or allowed by passwordless sudo.
        case softnet
        /// Softnet when the host has a privileged softnet, otherwise hostOnly.
        case auto
    }

    /// Host services reachable on the VM bridge under hostOnly.
    enum HostListenerPolicy: String, Sendable, CaseIterable {
        /// Report them (log + audit) and continue.
        case warn
        /// Refuse to register a runner while any unaccepted listener is reachable.
        case deny
    }

    /// Host IP forwarding under hostOnly. With forwarding on, a guest with root
    /// can route through the host's bridge address and reach whatever the host
    /// forwards to with a return path (a tailnet resolver, a NATing VPN, pf NAT,
    /// Internet Sharing), outside the proxy, the allowlist and the audit log.
    enum IPForwardingPolicy: String, Sendable, CaseIterable {
        /// Fail preflight (and stop a running VM) while forwarding is on.
        case deny
        /// Run anyway; every VM logs and audits the exposure.
        case accept
    }

    /// What to do when the host's upstream TLS to allowlisted hosts is intercepted
    /// (for example by an endpoint agent such as Netskope).
    enum TLSInspectionMode: String, Sendable, CaseIterable {
        /// Detect and fail closed (the default).
        case fail
        /// Install the host's intercepting CA certificate(s) (public part only) in the guest.
        case trustHostCA
    }

    enum Mode: String, Sendable, CaseIterable {
        /// Tart shared NAT: unrestricted host/LAN/VPN/corporate reach.
        case shared
        /// Softnet's built-in host/private-network isolation; public IPv4 remains reachable.
        case softnet
        /// Deny all forwarded IPv4 egress except explicitly allowed narrow CIDRs.
        case restricted
    }

    enum Selection: Sendable, Equatable {
        case profile(Profile)
        case mode(Mode)
    }

    enum Transport: String, Sendable, CaseIterable {
        /// The guest reaches the proxy through an SSH reverse tunnel on its loopback.
        case tunnel
        /// Reserved: a proxy listening on the softnet gateway. Not implemented.
        case gateway
    }

    let selection: Selection
    let presets: [String]
    let allowedDomains: [String]
    let allowedCIDRs: [DirectCIDRAllow]
    /// Legacy `mode: restricted` CIDRs.
    let allowCIDRs: [String]
    let verify: VerifyLevel?
    let allowGitHubSSH: Bool
    let transport: Transport
    /// nil means the default (`auto`) for profiles; modes always use softnet.
    let backend: BackendChoice?
    /// Explicit softnet binary (absolute). nil: the managed location, then PATH.
    let softnetPath: String?
    /// Expected SHA-256 of the softnet binary, checked before every VM.
    let softnetSHA256: String?
    let hostListeners: HostListenerPolicy?
    /// `tcp/7000`, `udp/5353`, `udp/*`: host listeners accepted under `hostListeners: deny`.
    let acceptedHostListeners: [String]
    let tlsInspection: TLSInspectionMode?
    /// nil means deny.
    let ipForwarding: IPForwardingPolicy?
    /// Consecutive network enforcement failures before `sand run` exits 78.
    let maxEnforcementFailures: Int?

    static let defaultMaxEnforcementFailures = 3

    static let secureDefault = NetworkConfig(selection: .profile(.github))

    init(
        selection: Selection,
        presets: [String] = [],
        allowedDomains: [String] = [],
        allowedCIDRs: [DirectCIDRAllow] = [],
        allowCIDRs: [String] = [],
        verify: VerifyLevel? = nil,
        allowGitHubSSH: Bool = false,
        transport: Transport = .tunnel,
        backend: BackendChoice? = nil,
        softnetPath: String? = nil,
        softnetSHA256: String? = nil,
        hostListeners: HostListenerPolicy? = nil,
        acceptedHostListeners: [String] = [],
        tlsInspection: TLSInspectionMode? = nil,
        ipForwarding: IPForwardingPolicy? = nil,
        maxEnforcementFailures: Int? = nil
    ) {
        self.selection = selection
        self.presets = presets
        self.allowedDomains = allowedDomains
        self.allowedCIDRs = allowedCIDRs
        self.allowCIDRs = allowCIDRs
        self.verify = verify
        self.allowGitHubSSH = allowGitHubSSH
        self.transport = transport
        self.backend = backend
        self.softnetPath = softnetPath
        self.softnetSHA256 = softnetSHA256
        self.hostListeners = hostListeners
        self.acceptedHostListeners = acceptedHostListeners
        self.tlsInspection = tlsInspection
        self.ipForwarding = ipForwarding
        self.maxEnforcementFailures = maxEnforcementFailures
    }

    /// Legacy convenience used by the softnet prototype and its tests.
    init(mode: Mode, allowCIDRs: [String] = []) {
        self.init(selection: .mode(mode), allowCIDRs: allowCIDRs)
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let profileName = try container.decodeIfPresent(String.self, forKey: .profile)
        let modeName = try container.decodeIfPresent(String.self, forKey: .mode)
        switch (profileName, modeName) {
        case (.some, .some):
            throw DecodingError.dataCorruptedError(
                forKey: .mode, in: container,
                debugDescription: "vm.run.network: set either profile or mode, not both"
            )
        case (nil, nil):
            // An explicit network block must say what it wants; never silently
            // fall back to anything because a key was misspelled or omitted.
            throw DecodingError.dataCorruptedError(
                forKey: .profile, in: container,
                debugDescription: "vm.run.network: an explicit network block must specify profile (\(Profile.allCases.map(\.rawValue).joined(separator: "|"))) or mode (\(Mode.allCases.map(\.rawValue).joined(separator: "|")))"
            )
        case let (profile?, nil):
            guard let value = Profile(rawValue: profile) else {
                throw DecodingError.dataCorruptedError(
                    forKey: .profile, in: container,
                    debugDescription: "vm.run.network.profile: unknown profile '\(profile)' (expected \(Profile.allCases.map(\.rawValue).joined(separator: ", ")))"
                )
            }
            selection = .profile(value)
        case let (nil, mode?):
            guard let value = Mode(rawValue: mode) else {
                throw DecodingError.dataCorruptedError(
                    forKey: .mode, in: container,
                    debugDescription: "vm.run.network.mode: unknown mode '\(mode)' (expected \(Mode.allCases.map(\.rawValue).joined(separator: ", ")))"
                )
            }
            selection = .mode(value)
        }
        presets = try container.decodeIfPresent([String].self, forKey: .presets) ?? []
        for preset in presets where EgressPreset(rawValue: preset) == nil {
            throw DecodingError.dataCorruptedError(
                forKey: .presets, in: container,
                debugDescription: "vm.run.network.presets: unknown preset '\(preset)' (expected \(EgressPreset.allCases.map(\.rawValue).joined(separator: ", ")))"
            )
        }
        allowedDomains = try container.decodeIfPresent([String].self, forKey: .allowedDomains) ?? []
        allowedCIDRs = try container.decodeIfPresent([DirectCIDRAllow].self, forKey: .allowedCIDRs) ?? []
        allowCIDRs = try container.decodeIfPresent([String].self, forKey: .allowCIDRs) ?? []
        verify = try container.decodeIfPresent(VerifyLevel.self, forKey: .verify)
        allowGitHubSSH = try container.decodeIfPresent(Bool.self, forKey: .allowGitHubSSH) ?? false
        if let transport = try container.decodeIfPresent(String.self, forKey: .transport) {
            guard let value = Transport(rawValue: transport) else {
                throw DecodingError.dataCorruptedError(
                    forKey: .transport, in: container,
                    debugDescription: "vm.run.network.transport: unknown transport '\(transport)'"
                )
            }
            self.transport = value
        } else {
            self.transport = .tunnel
        }
        backend = try Self.decodeEnum(BackendChoice.self, key: .backend, in: container)
        softnetPath = try container.decodeIfPresent(String.self, forKey: .softnetPath)
        softnetSHA256 = try container.decodeIfPresent(String.self, forKey: .softnetSHA256)?.lowercased()
        hostListeners = try Self.decodeEnum(HostListenerPolicy.self, key: .hostListeners, in: container)
        acceptedHostListeners = try container.decodeIfPresent([String].self, forKey: .acceptedHostListeners) ?? []
        tlsInspection = try Self.decodeEnum(TLSInspectionMode.self, key: .tlsInspection, in: container)
        ipForwarding = try Self.decodeEnum(IPForwardingPolicy.self, key: .ipForwarding, in: container)
        maxEnforcementFailures = try container.decodeIfPresent(Int.self, forKey: .maxEnforcementFailures)
    }

    private static func decodeEnum<T: RawRepresentable & CaseIterable>(_ type: T.Type, key: CodingKeys, in container: KeyedDecodingContainer<CodingKeys>) throws -> T? where T.RawValue == String {
        guard let raw = try container.decodeIfPresent(String.self, forKey: key) else { return nil }
        guard let value = T(rawValue: raw) else {
            throw DecodingError.dataCorruptedError(
                forKey: key, in: container,
                debugDescription: "vm.run.network.\(key.stringValue): unknown value '\(raw)' (expected \(T.allCases.map(\.rawValue).joined(separator: ", ")))"
            )
        }
        return value
    }

    private enum CodingKeys: String, CodingKey {
        case profile, mode, presets, allowedDomains, allowedCIDRs, allowCIDRs, verify, allowGitHubSSH, transport
        case backend, softnetPath, softnetSHA256, hostListeners, acceptedHostListeners, tlsInspection, ipForwarding, maxEnforcementFailures
    }

    var profile: Profile? {
        if case let .profile(value) = selection { return value }
        return nil
    }

    var mode: Mode? {
        if case let .mode(value) = selection { return value }
        return nil
    }

    /// True for every selection that confines the guest (hostOnly or softnet).
    var isIsolated: Bool {
        mode != .shared
    }

    /// The backend a profile asks for, before `auto` is resolved on the host.
    var backendChoice: BackendChoice {
        switch selection {
        case .profile:
            return backend ?? .auto
        case .mode:
            return .softnet
        }
    }

    var effectiveMaxEnforcementFailures: Int {
        maxEnforcementFailures ?? Self.defaultMaxEnforcementFailures
    }

    var effectiveVerify: VerifyLevel {
        verify ?? .basic
    }

    var label: String {
        switch selection {
        case let .profile(value):
            return "profile=\(value.rawValue)"
        case let .mode(value):
            return "mode=\(value.rawValue)"
        }
    }

    /// Compiles the declarative config into the enforced policy. Throws on any
    /// rule the validator would reject, so an invalid policy can never boot a VM.
    ///
    /// `autoBackend` is what `backend: auto` resolved to on this host (see
    /// `NetworkPreflight.resolveBackend`); without it, auto means hostOnly
    /// (the root-free backend), which is what host-independent callers get.
    func compile(sshPort: Int = 22, autoBackend: EnforcementBackend = .hostOnly) throws -> NetworkPolicy {
        let ssh = SoftnetRule.sshFromHost(port: sshPort)
        let backend: EnforcementBackend
        switch backendChoice {
        case .hostOnly: backend = .hostOnly
        case .softnet: backend = .softnet
        case .auto: backend = autoBackend
        }
        let options = NetworkPolicy.Options(
            hostListeners: hostListeners ?? .warn,
            acceptedHostListeners: try acceptedHostListeners.map(HostListenerPattern.parse),
            tlsInspection: tlsInspection ?? .fail,
            ipForwarding: ipForwarding ?? .deny,
            maxEnforcementFailures: effectiveMaxEnforcementFailures
        )
        switch selection {
        case .mode(.shared):
            return NetworkPolicy(kind: .shared, softnet: nil)
        case .mode(.softnet):
            return NetworkPolicy(kind: .softnet, softnet: nil, backend: .softnet, options: options)
        case .mode(.restricted):
            for cidr in allowCIDRs where !NetworkPolicy.isAllowedCIDR(cidr) {
                throw SoftnetRuleError.invalidCIDR(cidr)
            }
            let rules = [ssh] + allowCIDRs.map { SoftnetRule(direction: .outbound, proto: nil, target: .cidr($0), port: nil) }
            return NetworkPolicy(kind: .restricted(allowCIDRs), softnet: try .denyAll(allowing: rules), backend: .softnet, options: options)
        case .profile(.offline):
            return NetworkPolicy(
                kind: .offline,
                softnet: backend == .softnet ? try .denyAll(allowing: [ssh]) : nil,
                verify: effectiveVerify, backend: backend, options: options
            )
        case .profile(.github):
            if backend == .hostOnly, !allowedCIDRs.isEmpty {
                throw DirectCIDRError.requiresSoftnet
            }
            var rules = Set<DomainRule>()
            var presetNames = Set(presets.compactMap(EgressPreset.init(rawValue:)))
            presetNames.insert(.github)
            for preset in presetNames {
                for domain in preset.domains {
                    rules.insert(try DomainRule.parse(domain))
                }
            }
            for domain in allowedDomains {
                rules.insert(try DomainRule.parse(domain))
            }
            for allow in allowedCIDRs {
                try Self.checkDirectCIDR(allow)
            }
            let direct = allowedCIDRs.map {
                SoftnetRule(direction: .outbound, proto: $0.proto, target: .cidr($0.cidr), port: $0.port)
            }
            let egress = EgressPolicy(
                rules: rules.sorted(),
                steeredNames: EgressPreset.steeredNames,
                verify: effectiveVerify,
                extraCIDRs: allowedCIDRs
            )
            return NetworkPolicy(
                kind: .egressProxy(egress),
                softnet: backend == .softnet ? try .denyAll(allowing: [ssh] + direct) : nil,
                verify: effectiveVerify, backend: backend, options: options
            )
        }
    }

    /// Address ranges a direct allow may never cover without `allowPrivate`.
    static let protectedRanges: [IPNetwork] = [
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4"
    ].compactMap(IPNetwork.init)

    static func checkDirectCIDR(_ allow: DirectCIDRAllow) throws {
        guard NetworkPolicy.isAllowedCIDR(allow.cidr), let network = IPNetwork(allow.cidr) else {
            throw SoftnetRuleError.invalidCIDR(allow.cidr)
        }
        guard (1...65_535).contains(allow.port) else {
            throw DomainPatternError.invalidPort("\(allow.cidr) port \(allow.port)")
        }
        if hardDeniedRanges.contains(where: { $0.overlaps(network) }) {
            throw DirectCIDRError.hostLocalRange(allow.cidr)
        }
        if !allow.allowPrivate, protectedRanges.contains(where: { $0.overlaps(network) }) {
            throw DirectCIDRError.privateRange(allow.cidr)
        }
    }

    /// Ranges no direct allow may touch, even with `allowPrivate`: the softnet
    /// allow would let the guest reach host loopback, link-local/metadata or
    /// multicast directly.
    static let hardDeniedRanges: [IPNetwork] = ["0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4"].compactMap(IPNetwork.init)

    /// `allowedCIDRs` entries that overlap a host interface address or an
    /// attached subnet (the LAN, a VPN's point-to-point address, the vmnet
    /// bridge). Checked at preflight because it depends on the host.
    static func hostOverlaps(_ allows: [DirectCIDRAllow], facts: HostFacts) -> [(DirectCIDRAllow, String)] {
        allows.compactMap { allow in
            guard let network = IPNetwork(allow.cidr) else { return nil }
            if let address = facts.interfaceAddresses.first(where: { network.contains($0) }) {
                return (allow, "contains host address \(address)")
            }
            if let subnet = facts.onLinkSubnets.first(where: { $0.overlaps(network) }) {
                return (allow, "overlaps on-link subnet \(subnet)")
            }
            return nil
        }
    }
}

enum DirectCIDRError: Error, Equatable, CustomStringConvertible {
    case privateRange(String)
    case hostLocalRange(String)
    case requiresSoftnet

    var description: String {
        switch self {
        case .requiresSoftnet:
            return "allowedCIDRs needs backend: softnet; the hostOnly backend has no direct route off the host"
        case let .hostLocalRange(cidr):
            return "allowedCIDRs entry \(cidr) overlaps loopback, link-local/metadata, multicast or reserved space; this is refused even with allowPrivate: true"
        case let .privateRange(cidr):
            return "allowedCIDRs entry \(cidr) overlaps a private, loopback, link-local, CGNAT or multicast range; set allowPrivate: true only after review"
        }
    }
}
