import CryptoKit
import Foundation

enum SandBuildInfo {
    static let version = "0.0.0-dev"
}

/// How the guest's direct egress is removed.
enum EnforcementBackend: String, Sendable, Equatable, CaseIterable {
    /// `tart run --net-host`: a host-only vmnet network. Needs no root. The guest
    /// gets no default gateway, but a guest with root can route via the host's
    /// bridge address, so host IP forwarding must be off (preflight P11). Host
    /// services bound to any non-loopback host address stay reachable.
    case hostOnly
    /// Softnet deny-all plus a host-SSH allow. Needs a privileged softnet; adds
    /// host-service and peer-VM isolation.
    case softnet
}

/// The compiled, enforced network policy for one VM. Produced only by
/// `NetworkConfig.compile`, so every softnet rule it carries was validated.
struct NetworkPolicy: Sendable, Equatable {
    struct Options: Sendable, Equatable {
        var hostListeners: NetworkConfig.HostListenerPolicy = .warn
        var acceptedHostListeners: [HostListenerPattern] = []
        var tlsInspection: NetworkConfig.TLSInspectionMode = .fail
        var ipForwarding: NetworkConfig.IPForwardingPolicy = .deny
        var maxEnforcementFailures: Int = NetworkConfig.defaultMaxEnforcementFailures
    }

    enum Kind: Sendable, Equatable {
        case shared
        case softnet
        case restricted([String])
        case egressProxy(EgressPolicy)
        case offline
    }

    /// How this policy is bound to this host. Set by `NetworkPreflight.compile`;
    /// not part of `policyHash`, which depends on the config alone.
    struct HostBinding: Sendable, Equatable {
        /// The softnet tart must exec (backend softnet only).
        var softnet: SoftnetLocation?
        /// `vm.run.network.softnetPath` / `softnetSHA256`, for the per-VM checks.
        var softnetPath: String?
        var softnetSHA256: String?
        /// Why `backend: auto` did not choose softnet on this host.
        var autoFallback: AutoFallback?
    }

    struct AutoFallback: Sendable, Equatable {
        let reason: String
        /// A softnet was installed but rejected (for example setuid root in a
        /// user-writable directory): warn loudly and audit, not just note it.
        let loud: Bool
    }

    /// Port the guest sees the egress proxy on (forwarded by the SSH reverse tunnel).
    static let guestProxyPort = 3128

    let kind: Kind
    let softnet: SoftnetRuleSet?
    /// Guest egress verification before registration (profiles only).
    let verify: VerifyLevel
    /// nil only for shared NAT.
    let backend: EnforcementBackend?
    let options: Options
    var host = HostBinding()

    init(kind: Kind, softnet: SoftnetRuleSet?, verify: VerifyLevel = .off, backend: EnforcementBackend? = nil, options: Options = Options()) {
        self.kind = kind
        self.softnet = softnet
        self.verify = verify
        self.options = options
        if kind == .shared {
            self.backend = nil
        } else {
            self.backend = backend ?? (softnet != nil || kind == .softnet ? .softnet : .hostOnly)
        }
    }

    static let shared = NetworkPolicy(kind: .shared, softnet: nil)

    var tartArguments: [String] {
        switch kind {
        case .shared:
            return []
        case .softnet:
            return ["--net-softnet"]
        case .restricted, .egressProxy, .offline:
            if backend == .hostOnly {
                return ["--net-host"]
            }
            return softnet?.tartArguments ?? ["--net-softnet", "--net-softnet-block=0.0.0.0/0"]
        }
    }

    /// Every policy except shared NAT confines the guest and is enforced.
    var isIsolated: Bool {
        kind != .shared
    }

    /// Needs a privileged softnet binary (preflight P2/P3, watchdog softnet check).
    var usesSoftnet: Bool {
        backend == .softnet
    }

    var isHostOnly: Bool {
        backend == .hostOnly
    }

    var egress: EgressPolicy? {
        if case let .egressProxy(policy) = kind { return policy }
        return nil
    }

    var name: String {
        switch kind {
        case .shared:
            return "mode=shared"
        case .softnet:
            return "mode=softnet"
        case .restricted:
            return "mode=restricted"
        case .egressProxy:
            return "profile=github"
        case .offline:
            return "profile=offline"
        }
    }

    /// `profile=github backend=hostOnly`, for logs.
    var label: String {
        backend.map { "\(name) backend=\($0.rawValue)" } ?? name
    }

    /// SHA-256 over a canonical encoding of everything that determines
    /// enforcement: tart arguments, domain rules, steered names, verify level,
    /// preset version and the sand version.
    var policyHash: String {
        var canonical: [String: [String]] = [
            "kind": [name],
            "tartArguments": tartArguments,
            "policyVersion": [EgressPreset.policyVersion],
            "sandVersion": [SandBuildInfo.version]
        ]
        if let egress {
            canonical["domains"] = egress.rules.map(\.description).sorted()
            canonical["steered"] = egress.steeredNames.sorted()
            canonical["verify"] = [egress.verify.rawValue]
            canonical["tlsInspection"] = [options.tlsInspection.rawValue]
        }
        if let backend {
            canonical["backend"] = [backend.rawValue]
        }
        if backend == .hostOnly {
            canonical["hostListeners"] = [options.hostListeners.rawValue] + options.acceptedHostListeners.map(\.description).sorted()
            canonical["ipForwarding"] = [options.ipForwarding.rawValue]
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = (try? encoder.encode(canonical)) ?? Data()
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// Human-readable summary for `sand network explain` and dry runs.
    func explain() -> [String] {
        var lines = [
            "network policy: \(name)",
            "policy hash: \(policyHash)",
            "policy version: \(EgressPreset.policyVersion)",
            "tart arguments: \(tartArguments.isEmpty ? "(none: shared NAT)" : tartArguments.joined(separator: " "))"
        ]
        switch backend {
        case .hostOnly:
            lines.append("enforcement backend: hostOnly (tart --net-host; no root; no route off the host while host IP forwarding is off)")
            lines.append("host IP forwarding: \(options.ipForwarding.rawValue)" + (options.ipForwarding == .accept ? " (WARNING: a guest with root can route through the host to whatever the host forwards to)" : " (preflight fails and running VMs stop while it is on)"))
            lines.append("host listeners on the VM bridge: \(options.hostListeners.rawValue)" + (options.acceptedHostListeners.isEmpty ? "" : " (accepted: \(options.acceptedHostListeners.map(\.description).joined(separator: ", ")))"))
            lines.append("note: hostOnly does not guarantee peer-VM isolation; VMs that share a host-only bridge can reach each other (use backend: softnet for that)")
        case .softnet:
            lines.append("enforcement backend: softnet (privileged softnet binary required)")
            if let softnet = host.softnet {
                lines.append("softnet binary: \(softnet.summary) (tart is launched with \(softnet.directory) first on PATH)")
            }
        case nil:
            break
        }
        if let fallback = host.autoFallback {
            lines.append("backend auto chose hostOnly: \(fallback.reason)")
        }
        if isIsolated {
            lines.append("max consecutive enforcement failures before exit 78: \(options.maxEnforcementFailures)")
        }
        switch kind {
        case .shared:
            lines.append("WARNING: VM has unrestricted host/LAN/VPN/corporate network reach")
        case .softnet:
            lines.append("softnet built-in isolation: private ranges blocked, public IPv4 reachable")
        case let .restricted(cidrs):
            lines.append("direct IPv4 allows: \(cidrs.joined(separator: ", "))")
        case .offline:
            lines.append("guest egress: none (host SSH only)")
        case let .egressProxy(egress):
            lines.append("guest egress: HTTPS CONNECT proxy at 127.0.0.1:\(Self.guestProxyPort) in the guest (SSH reverse tunnel)")
            lines.append("verify: \(egress.verify.rawValue)")
            lines.append("TLS inspection: \(options.tlsInspection.rawValue)" + (options.tlsInspection == .trustHostCA ? " (an intercepting host CA, if detected, is trusted in the guest)" : " (detected interception fails preflight)"))
            lines.append("steered names (VPN split-DNS fronts allowed): \(egress.steeredNames.sorted().joined(separator: ", "))")
            lines.append("allowed destinations (\(egress.rules.count)):")
            lines.append(contentsOf: egress.rules.map { "  - \($0)" })
            if !egress.extraCIDRs.isEmpty {
                lines.append("direct CIDR allows (bypass the proxy):")
                lines.append(contentsOf: egress.extraCIDRs.map { "  - \($0.proto.rawValue) \($0.cidr) port \($0.port)" })
            }
        }
        return lines
    }

    /// Require narrow, explicitly spelled IPv4 prefixes. In particular this
    /// rejects @host, 0.0.0.0/0, hostnames, IPv6 and oversized IP ranges.
    /// It intentionally allows private /32 proxies; administrators must ensure
    /// those endpoints are not the host or reachable corporate services.
    static func isAllowedCIDR(_ cidr: String) -> Bool {
        let parts = cidr.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let prefix = Int(parts[1]), (24...32).contains(prefix) else {
            return false
        }
        let octets = parts[0].split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4 else { return false }
        return octets.allSatisfy { octet in
            guard !octet.isEmpty,
                  (octet.count == 1 || octet.first != "0"),
                  octet.allSatisfy({ $0.isASCII && $0.isNumber }),
                  let number = Int(octet), (0...255).contains(number) else {
                return false
            }
            return true
        }
    }
}
