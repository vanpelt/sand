import Foundation

/// Proves, from inside a freshly booted guest and before any runner is
/// registered, that direct egress is closed and the proxy path works.
/// The guest is trusted at this point (nothing untrusted has run yet).
struct GuestEgressVerifier: Sendable {
    enum Expectation: Sendable, Equatable {
        /// A direct path that must not connect.
        case closed
        /// A UDP/DNS probe: inconclusive (no tool) is accepted.
        case closedUDP
        /// The proxied positive probe.
        case proxyWorks
        /// A host service on the VM bridge (hostOnly only): OPEN is reported, and
        /// fails only under `hostListeners: deny` for an unaccepted port.
        case hostService(port: Int)
        /// hostOnly, adversarial: the guest first adds a host route via the host's
        /// bridge address (what a job with root can do). Must stay closed unless
        /// host IP forwarding was explicitly accepted, in which case OPEN is reported.
        case routedClosed
    }

    /// hostOnly: targets probed again after the guest routes them via the host.
    struct RoutedTargets: Sendable, Equatable {
        /// The host's IPv6 link-local address on the bridge, for an IPv6 route.
        var hostGatewayV6: String?
        /// The host's DNS servers (scutil --dns), e.g. a VPN or tailnet resolver.
        var resolvers: [String] = []
        /// First address of every VPN (utun) route.
        var tunnelTargets: [String] = []
        /// `ipForwarding: accept`: routed OPEN results are reported, not failed.
        var forwardingAccepted = false
    }

    struct Probe: Sendable, Equatable {
        let id: String
        let expectation: Expectation
        let summary: String
        let command: String
    }

    struct ProbeResult: Sendable, Equatable {
        let id: String
        let outcome: String
        let detail: String
        let passed: Bool
    }

    struct StrictTargets: Sendable, Equatable {
        var lanGateway: String?
        var hostLANAddress: String?
        var tunnelTargets: [String] = []

        /// Host-derived strict targets: the LAN gateway, the host's own LAN
        /// address, and the first address of every VPN (utun) route.
        static func derive(facts: HostFacts, routes: RouteInspector) -> StrictTargets {
            var targets = StrictTargets()
            if let gateway = routes.defaultGateways.first, let gatewayIP = IPAddress(gateway) {
                targets.lanGateway = gateway
                if let subnet = facts.onLinkSubnets.first(where: { $0.contains(gatewayIP) }) {
                    targets.hostLANAddress = facts.interfaceAddresses.first { subnet.contains($0) && $0 != gatewayIP }?.description
                }
            }
            let multicast = IPNetwork("224.0.0.0/3")!
            var seen = Set<String>()
            targets.tunnelTargets = routes.tunnelSubnets.compactMap { network, _ in
                guard case let .v4(base) = network.address, !multicast.contains(network.address) else { return nil }
                let target = IPAddress.v4(base + 1).description
                return seen.insert(target).inserted ? target : nil
            }
            return targets
        }
    }

    static let marker = "SANDPROBE"

    let level: VerifyLevel
    /// A GitHub address the host resolved (a VPN front when steered); the guest must not reach it directly.
    let directGitHubAddress: String
    let strictTargets: StrictTargets
    let proxyPort: Int
    /// False for profile offline: there is no proxy, so only negative probes run.
    let expectsProxy: Bool
    /// hostOnly: the gateway is the host's bridge address, so host services bound
    /// to all interfaces answer there. Those are reported, not egress.
    let backend: EnforcementBackend
    let hostListenerPolicy: NetworkConfig.HostListenerPolicy
    let acceptedHostListeners: [HostListenerPattern]
    /// Host TCP listeners found on the bridge; probed from the guest as evidence (hostOnly).
    let hostServicePorts: [Int]
    /// The host's address on the VM network, used when the guest has no default
    /// route (host-only networks have none): gateway probes then target the host.
    let hostGateway: String?
    /// nil: no adversarial routed probes (softnet, or hostOnly without a known bridge address).
    let routed: RoutedTargets?

    init(
        level: VerifyLevel,
        directGitHubAddress: String,
        strictTargets: StrictTargets = StrictTargets(),
        proxyPort: Int = NetworkPolicy.guestProxyPort,
        expectsProxy: Bool = true,
        backend: EnforcementBackend = .softnet,
        hostListenerPolicy: NetworkConfig.HostListenerPolicy = .warn,
        acceptedHostListeners: [HostListenerPattern] = [],
        hostServicePorts: [Int] = [],
        hostGateway: String? = nil,
        routed: RoutedTargets? = nil
    ) {
        self.level = level
        self.directGitHubAddress = directGitHubAddress
        self.strictTargets = strictTargets
        self.proxyPort = proxyPort
        self.expectsProxy = expectsProxy
        self.backend = backend
        self.hostListenerPolicy = hostListenerPolicy
        self.acceptedHostListeners = acceptedHostListeners
        self.hostServicePorts = hostServicePorts
        self.hostGateway = hostGateway.flatMap { IPAddress($0) != nil ? $0 : nil }
        if backend == .hostOnly, var routed {
            routed.hostGatewayV6 = routed.hostGatewayV6.flatMap { IPAddress($0)?.isIPv4 == false ? $0 : nil }
            routed.resolvers = routed.resolvers.filter { IPAddress($0)?.isIPv4 == true }
            routed.tunnelTargets = routed.tunnelTargets.filter { IPAddress($0)?.isIPv4 == true }
            self.routed = routed
        } else {
            self.routed = nil
        }
    }

    /// The tailnet (MagicDNS) resolver: a host with forwarding on answers it for the guest.
    static let tailnetResolver = "100.100.100.100"

    /// Under softnet every host port is blocked; under hostOnly a host service is reported.
    private func gatewayExpectation(port: Int) -> Expectation {
        backend == .hostOnly ? .hostService(port: port) : .closed
    }

    var probes: [Probe] {
        guard level != .off else { return [] }
        let proxy = "http://127.0.0.1:\(proxyPort)"
        var probes: [Probe] = [
            Probe(id: "N1", expectation: .closed, summary: "arbitrary internet 1.1.1.1:443", command: "tcp N1 1.1.1.1 443"),
            Probe(id: "N2", expectation: .closed, summary: "direct GitHub/VPN front :443", command: "tcp N2 \(Self.quote(directGitHubAddress)) 443"),
            Probe(id: "N3a", expectation: gatewayExpectation(port: 5000), summary: "host gateway :5000", command: "tcp N3a \"$GW\" 5000"),
            // DNS to the host is an egress path (a recursive resolver), never just a host service.
            Probe(id: "N3b", expectation: .closed, summary: "host gateway :53/tcp", command: "tcp N3b \"$GW\" 53"),
            Probe(id: "N3c", expectation: gatewayExpectation(port: 22), summary: "host gateway :22", command: "tcp N3c \"$GW\" 22"),
            Probe(id: "N4a", expectation: .closedUDP, summary: "DNS via gateway", command: "dnsq N4a \"$GW\""),
            Probe(id: "N4b", expectation: .closedUDP, summary: "DNS via 8.8.8.8", command: "dnsq N4b 8.8.8.8"),
            Probe(id: "N5", expectation: .closed, summary: "IPv6 internet", command: "v6 N5"),
        ]
        if expectsProxy {
            probes.append(Probe(id: "P1", expectation: .proxyWorks, summary: "api.github.com via proxy", command: "proxied P1 \(proxy) https://api.github.com/zen"))
        }
        if backend == .hostOnly {
            let fixed: Set<Int> = [5000, 22, 53]
            for (index, port) in hostServicePorts.filter({ !fixed.contains($0) }).prefix(8).enumerated() {
                probes.append(Probe(id: "H\(index + 1)", expectation: .hostService(port: port), summary: "host service on the bridge :\(port)", command: "tcp H\(index + 1) \"$GW\" \(port)"))
            }
        }
        if let routed {
            probes.append(contentsOf: routedProbes(routed))
        }
        guard level == .strict else { return probes }
        if let gateway = strictTargets.lanGateway {
            probes.append(Probe(id: "S1", expectation: .closed, summary: "host LAN gateway :80", command: "tcp S1 \(Self.quote(gateway)) 80"))
        }
        probes.append(Probe(id: "S2", expectation: .closed, summary: "tailnet resolver 100.100.100.100:53", command: "tcp S2 100.100.100.100 53"))
        probes.append(Probe(id: "S3", expectation: .closedUDP, summary: "corporate resolver 172.16.0.1", command: "dnsq S3 172.16.0.1"))
        probes.append(Probe(id: "S4", expectation: .closed, summary: "metadata 169.254.169.254:80", command: "tcp S4 169.254.169.254 80"))
        if let address = strictTargets.hostLANAddress {
            probes.append(Probe(id: "S5", expectation: .closed, summary: "host LAN address :7000", command: "tcp S5 \(Self.quote(address)) 7000"))
        }
        probes.append(Probe(id: "S6", expectation: .closedUDP, summary: "DNS via 1.1.1.1", command: "dnsq S6 1.1.1.1"))
        if expectsProxy {
            probes.append(Probe(id: "S7", expectation: .closed, summary: "non-allowlisted host via proxy", command: "denied S7 \(proxy) https://example.com"))
        }
        for (index, target) in strictTargets.tunnelTargets.prefix(8).enumerated() {
            probes.append(Probe(id: "T\(index + 1)", expectation: .closed, summary: "VPN route :443", command: "tcp T\(index + 1) \(Self.quote(target)) 443"))
        }
        return probes
    }

    /// The direct probes again, each after `route add -host <target> <bridge>`.
    private func routedProbes(_ routed: RoutedTargets) -> [Probe] {
        var probes: [Probe] = [
            Probe(id: "R1", expectation: .routedClosed, summary: "routed via host: 1.1.1.1:443", command: "routed R1 tcp 1.1.1.1 443"),
            Probe(id: "R2", expectation: .routedClosed, summary: "routed via host: direct GitHub/VPN front :443", command: "routed R2 tcp \(Self.quote(directGitHubAddress)) 443"),
            Probe(id: "R3", expectation: .routedClosed, summary: "routed via host: DNS 8.8.8.8", command: "routed R3 dnsq 8.8.8.8"),
            Probe(id: "R4", expectation: .routedClosed, summary: "routed via host: tailnet DNS \(Self.tailnetResolver)", command: "routed R4 dnsq \(Self.tailnetResolver)"),
            Probe(id: "R5", expectation: .routedClosed, summary: "routed via host: \(Self.tailnetResolver):53/tcp", command: "routed R5 tcp \(Self.tailnetResolver) 53"),
        ]
        var seen: Set<String> = ["8.8.8.8", Self.tailnetResolver]
        for resolver in routed.resolvers where seen.insert(resolver).inserted && probes.count < 11 {
            let id = "RD\(probes.count - 4)"
            probes.append(Probe(id: id, expectation: .routedClosed, summary: "routed via host: host DNS server \(resolver)", command: "routed \(id) dnsq \(Self.quote(resolver))"))
        }
        for (index, target) in routed.tunnelTargets.filter({ !seen.contains($0) }).prefix(6).enumerated() {
            probes.append(Probe(id: "RT\(index + 1)", expectation: .routedClosed, summary: "routed via host: VPN route \(target):443", command: "routed RT\(index + 1) tcp \(Self.quote(target)) 443"))
        }
        if let v6 = routed.hostGatewayV6 {
            probes.append(Probe(id: "R6", expectation: .routedClosed, summary: "routed via host: IPv6 internet", command: "routed6 R6 \(Self.quote(v6))"))
        }
        return probes
    }

    /// Guest-side helpers for the routed probes. Routes are host routes (never the
    /// default route) and are removed after each probe and on exit.
    private static let routedPrelude = #"""
    SAND_ROUTED=
    if [ "$(uname -s)" = Darwin ]; then
      radd() { sudo -n /sbin/route -n add -host "$1" "$HGW" >/dev/null 2>&1; }
      rdel() { sudo -n /sbin/route -n delete -host "$1" >/dev/null 2>&1; }
      gwif() { route -n get "$HGW" 2>/dev/null | awk '/interface:/{print $2; exit}'; }
      radd6() { sudo -n /sbin/route -n add -inet6 -host "$1" "$2%$(gwif)" >/dev/null 2>&1; }
      rdel6() { sudo -n /sbin/route -n delete -inet6 -host "$1" >/dev/null 2>&1; }
    else
      radd() { sudo -n ip route replace "$1/32" via "$HGW" >/dev/null 2>&1; }
      rdel() { sudo -n ip route del "$1/32" >/dev/null 2>&1; }
      gwif() { ip route get "$HGW" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'; }
      radd6() { sudo -n ip -6 route replace "$1/128" via "$2" dev "$(gwif)" >/dev/null 2>&1; }
      rdel6() { sudo -n ip -6 route del "$1/128" >/dev/null 2>&1; }
    fi
    sand_unroute() { if [ -n "$SAND_ROUTED" ]; then rdel "$SAND_ROUTED"; fi; rdel6 2606:4700:4700::1111; }
    trap sand_unroute EXIT
    routed() {
      rid=$1; kind=$2; target=$3; shift 3
      if [ -z "$HGW" ] || [ -z "$target" ]; then echo "SANDPROBE $rid NOTARGET empty-target"; return; fi
      if ! sudo -n true >/dev/null 2>&1; then echo "SANDPROBE $rid INCONCLUSIVE no-guest-root"; return; fi
      if ! radd "$target"; then echo "SANDPROBE $rid INCONCLUSIVE route-add-failed"; return; fi
      SAND_ROUTED=$target
      "$kind" "$rid" "$target" "$@"
      rdel "$target"; SAND_ROUTED=
    }
    routed6() {
      if ! sudo -n true >/dev/null 2>&1; then echo "SANDPROBE $1 INCONCLUSIVE no-guest-root"; return; fi
      if ! radd6 2606:4700:4700::1111 "$2"; then echo "SANDPROBE $1 INCONCLUSIVE route-add-failed"; return; fi
      v6 "$1"
      rdel6 2606:4700:4700::1111
    }
    """#

    /// The bash script run over `ssh exec`. Every negative probe runs with the
    /// proxy variables unset so it tests the direct path.
    var script: String {
        let prelude = #"""
        set +e
        unset https_proxy http_proxy HTTPS_PROXY HTTP_PROXY all_proxy ALL_PROXY
        if [ "$(uname -s)" = Darwin ]; then
          ncz() { nc -z -G 3 -w 3 "$1" "$2" >/dev/null 2>&1; }
          GW=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2; exit}')
        else
          ncz() { nc -z -w 3 "$1" "$2" >/dev/null 2>&1; }
          GW=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
        fi
        tcp() {
          if [ -z "$2" ]; then echo "SANDPROBE $1 NOTARGET empty-target"; return; fi
          if ! command -v nc >/dev/null 2>&1; then echo "SANDPROBE $1 INCONCLUSIVE no-nc"; return; fi
          if ncz "$2" "$3"; then echo "SANDPROBE $1 OPEN $2:$3"; else echo "SANDPROBE $1 CLOSED $2:$3"; fi
        }
        dnsq() {
          if [ -z "$2" ]; then echo "SANDPROBE $1 NOTARGET empty-target"; return; fi
          if ! command -v dig >/dev/null 2>&1; then echo "SANDPROBE $1 INCONCLUSIVE no-dig"; return; fi
          if dig +time=2 +tries=1 +short @"$2" github.com A 2>/dev/null | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
            echo "SANDPROBE $1 OPEN $2"; else echo "SANDPROBE $1 CLOSED $2"; fi
        }
        v6() {
          code=$(curl -6 -s -o /dev/null -m 4 -w '%{http_code}' 'https://[2606:4700:4700::1111]/' 2>/dev/null); rc=$?
          case "$rc" in 0|35|51|52|56|58|60) echo "SANDPROBE $1 OPEN rc=$rc";; *) echo "SANDPROBE $1 CLOSED rc=$rc";; esac
        }
        proxied() {
          code=$(curl -s -o /dev/null -m 20 -w '%{http_code}' --proxy "$2" "$3" 2>/dev/null)
          case "$code" in 2??|3??|4??) echo "SANDPROBE $1 OK http=$code";; *) echo "SANDPROBE $1 FAIL http=$code";; esac
        }
        denied() {
          connect=$(curl -s -o /dev/null -m 10 -w '%{http_connect}' --proxy "$2" "$3" 2>/dev/null)
          if [ "$connect" = 403 ]; then echo "SANDPROBE $1 CLOSED connect=403"; else echo "SANDPROBE $1 OPEN connect=$connect"; fi
        }
        """#
        // No default route (host-only): probe the host's bridge address instead.
        let fallback = hostGateway.map { [#"[ -n "$GW" ] || GW=\#(Self.quote($0))"#] } ?? []
        // Routed probes always go via the host's own bridge address, never the guest's idea of a gateway.
        let routedSetup = routed == nil ? [] : ["HGW=\(hostGateway.map(Self.quote) ?? "''")", Self.routedPrelude]
        return ([prelude] + fallback + routedSetup + probes.map(\.command) + ["exit 0"]).joined(separator: "\n")
    }

    func evaluate(_ output: String) -> [ProbeResult] {
        let seen = Self.parse(output)
        return probes.map { probe in
            guard let (outcome, detail) = seen[probe.id] else {
                return ProbeResult(id: probe.id, outcome: "MISSING", detail: probe.summary, passed: false)
            }
            let passed: Bool
            switch probe.expectation {
            case .closed:
                passed = outcome == "CLOSED"
            case .closedUDP:
                passed = outcome == "CLOSED" || outcome == "INCONCLUSIVE"
            case .proxyWorks:
                passed = outcome == "OK"
            case let .hostService(port):
                let accepted = hostListenerPolicy == .warn
                    || acceptedHostListeners.contains { $0.matches(HostListener(proto: .tcp, port: port, boundTo: "*")) }
                passed = outcome == "CLOSED" || (outcome == "OPEN" && accepted)
            case .routedClosed:
                passed = outcome == "CLOSED" || outcome == "INCONCLUSIVE" || (outcome == "OPEN" && routed?.forwardingAccepted == true)
            }
            return ProbeResult(id: probe.id, outcome: outcome, detail: "\(probe.summary): \(detail)", passed: passed)
        }
    }

    /// hostOnly host services the guest actually reached (OPEN), for the audit log.
    func reachableHostServices(_ results: [ProbeResult]) -> [String] {
        let byID = Dictionary(uniqueKeysWithValues: probes.map { ($0.id, $0) })
        return results.compactMap { result in
            guard result.outcome == "OPEN", case let .hostService(port)? = byID[result.id]?.expectation else { return nil }
            return "tcp/\(port)"
        }
    }

    /// Routed probes that connected (only possible to pass under `ipForwarding: accept`).
    func routedReachable(_ results: [ProbeResult]) -> [String] {
        let byID = Dictionary(uniqueKeysWithValues: probes.map { ($0.id, $0) })
        return results.compactMap { result in
            guard result.outcome == "OPEN", byID[result.id]?.expectation == .routedClosed else { return nil }
            return result.id
        }
    }

    static func parse(_ output: String) -> [String: (String, String)] {
        var results: [String: (String, String)] = [:]
        for line in output.split(whereSeparator: \.isNewline) {
            let fields = line.split(separator: " ", maxSplits: 3).map(String.init)
            guard fields.count >= 3, fields[0] == marker else { continue }
            // A probe reported twice is suspicious; keep the worst (OPEN/FAIL) outcome.
            if let existing = results[fields[1]], existing.0 == "OPEN" || existing.0 == "FAIL" {
                continue
            }
            results[fields[1]] = (fields[2], fields.count > 3 ? fields[3] : "")
        }
        return results
    }

    private static func quote(_ value: String) -> String {
        GitHubProvisioner.shellQuote(value)
    }
}
