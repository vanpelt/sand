import Foundation
import Testing
@testable import sand

private func ip(_ value: String) -> IPAddress {
    IPAddress(value)!
}

private let facts = HostFacts(
    interfaceAddresses: [ip("10.0.0.152"), ip("172.16.140.106"), ip("100.101.102.103")],
    onLinkSubnets: [IPNetwork("10.0.0.0/24")!, IPNetwork("172.16.140.106/32")!, IPNetwork("192.168.64.0/24")!],
    vmSubnet: IPNetwork("192.168.64.8/29")
)

@Suite struct DestinationGuardTests {
    let guardrail = DestinationGuard(hostFacts: facts)

    @Test func steeredGitHubFrontIsAllowed() {
        #expect(guardrail.check(host: "github.com", port: 443, resolved: [ip("172.16.7.60")], steeredName: true) == .allow(ip("172.16.7.60"), steered: true))
    }

    @Test func nonSteeredNameRebindingToCorporateIsDenied() {
        guard case .deny = guardrail.check(host: "registry.npmjs.org", port: 443, resolved: [ip("172.16.7.60")], steeredName: false) else {
            Issue.record("expected deny")
            return
        }
    }

    @Test func steeredNameOnLinkIsDenied() {
        guard case let .deny(reason) = guardrail.check(host: "github.com", port: 443, resolved: [ip("10.0.0.5")], steeredName: true) else {
            Issue.record("expected deny")
            return
        }
        #expect(reason.contains("on-link"))
    }

    @Test(arguments: ["100.100.100.100", "169.254.169.254", "127.0.0.1", "::1", "fe80::1", "fd00::1", "::ffff:10.0.0.1", "0.0.0.0", "224.0.0.251", "64:ff9b::1.1.1.1"])
    func reservedAddressesAreDenied(address: String) {
        guard case .deny = guardrail.classify(ip(address), steeredName: true) else {
            Issue.record("\(address) should be denied")
            return
        }
    }

    @Test func hostOwnUtunAddressIsDeniedEvenForSteeredNames() {
        #expect(guardrail.classify(ip("172.16.140.106"), steeredName: true) == .deny("host-address"))
    }

    @Test func addressInsideTheVMSubnetIsDenied() {
        #expect(guardrail.classify(ip("192.168.64.10"), steeredName: true) == .deny("vm-subnet"))
    }

    @Test func publicAddressesAreAllowedAndPreferredOverDeniedOnes() {
        #expect(guardrail.check(host: "github.com", port: 443, resolved: [ip("140.82.112.3")], steeredName: true) == .allow(ip("140.82.112.3"), steered: false))
        #expect(guardrail.check(host: "x.example", port: 443, resolved: [ip("10.1.1.1"), ip("2606:4700::1")], steeredName: false) == .allow(ip("2606:4700::1"), steered: false))
        #expect(guardrail.check(host: "x.example", port: 443, resolved: [], steeredName: false) == .deny("no-address"))
    }

    @Test func mappedPublicIPv4IsAllowed() {
        #expect(guardrail.classify(ip("::ffff:140.82.112.3"), steeredName: false) == .allow(ip("::ffff:140.82.112.3"), steered: false))
    }

    @Test(arguments: ["192.0.2.1", "198.51.100.7", "203.0.113.9", "192.88.99.1", "64:ff9b:1::a00:1", "2002:a00:1::1",
                      "::10.0.0.1", "100::1", "2001:db8::1", "fec0::1", "2001:0:4136:e378::1"])
    func additionalReservedRangesAreDenied(address: String) {
        guard case .deny = guardrail.classify(ip(address), steeredName: false) else {
            Issue.record("\(address) should be denied")
            return
        }
    }

    @Test(arguments: ["127.0.0.1", "169.254.169.254", "0.0.0.1", "224.0.0.1", "::1", "fe80::1", "::ffff:127.0.0.1"])
    func literalHardFloorIgnoresAllowPrivate(address: String) {
        guard case .deny = guardrail.checkLiteral(ip(address), allowPrivate: true) else {
            Issue.record("\(address) must be denied even with allowPrivate")
            return
        }
    }

    @Test func literalToHostAddressOrLANIsDeniedEvenWithAllowPrivate() {
        #expect(guardrail.checkLiteral(ip("10.0.0.152"), allowPrivate: true) == .deny("host-address"))
        #expect(guardrail.checkLiteral(ip("10.0.0.1"), allowPrivate: true) == .deny("on-link"))
        #expect(guardrail.checkLiteral(ip("192.168.64.10"), allowPrivate: true) == .deny("vm-subnet"))
    }

    @Test func literalPrivateNeedsAllowPrivate() {
        #expect(guardrail.checkLiteral(ip("172.20.1.1"), allowPrivate: false) == .deny("private"))
        #expect(guardrail.checkLiteral(ip("172.20.1.1"), allowPrivate: true) == .allow(ip("172.20.1.1"), steered: false))
        #expect(guardrail.checkLiteral(ip("140.82.112.3"), allowPrivate: false) == .allow(ip("140.82.112.3"), steered: false))
    }

    @Test func steeredAnswerMustUseTheLearnedVPNInterface() async {
        let routes = RouteInspector(netstatOutput: """
        default            10.0.0.1           UGScg                en12
        172.16             link#30            UCS                 utun8
        192.168.68         link#25            UCS                 utun4
        10.201/20          link#25            UCS                 utun4
        """)
        let resolver = StaticHostResolver(table: ["github.com": [ip("172.16.7.60")], "api.github.com": [ip("140.82.114.5")]])
        let learned = await DestinationGuard.learnSteeredInterfaces(names: ["github.com", "api.github.com"], resolver: resolver, routes: routes)
        #expect(learned == ["utun8"])
        let bound = DestinationGuard(hostFacts: facts, routes: routes, steeredInterfaces: learned)
        #expect(bound.classify(ip("172.16.7.60"), steeredName: true) == .allow(ip("172.16.7.60"), steered: true))
        // A hostile resolver pointing github.com into the tailnet is denied.
        #expect(bound.classify(ip("192.168.68.5"), steeredName: true) == .deny("steered-route-mismatch"))
        #expect(bound.classify(ip("10.201.0.9"), steeredName: true) == .deny("steered-route-mismatch"))
        // Or at a private address only the default route would carry.
        #expect(bound.classify(ip("10.9.9.9"), steeredName: true) == .deny("steered-route-mismatch"))
        // An empty route table learns nothing and allows no steered answer.
        let empty = DestinationGuard(hostFacts: facts, routes: RouteInspector(routes: []), steeredInterfaces: [])
        #expect(empty.classify(ip("172.16.7.60"), steeredName: true) == .deny("steered-route-mismatch"))
    }

    @Test func pointToPointInterfaceIsOnlyItsOwnAddress() {
        // A VPN utun with a /16 mask must not make the whole VPN range on-link.
        let utun = HostFacts.onLinkNetwork(address: ip("172.16.140.106"), maskLength: 16, pointToPoint: true)
        #expect(utun == IPNetwork("172.16.140.106/32"))
        let lan = HostFacts.onLinkNetwork(address: ip("10.0.0.152"), maskLength: 24, pointToPoint: false)
        #expect(lan == IPNetwork("10.0.0.0/24"))
        let wideVPN = DestinationGuard(hostFacts: HostFacts(interfaceAddresses: [ip("172.16.140.106")], onLinkSubnets: [utun!]))
        #expect(wideVPN.check(host: "github.com", port: 443, resolved: [ip("172.16.7.60")], steeredName: true) == .allow(ip("172.16.7.60"), steered: true))
    }

    @Test func hostFactsReadsLocalInterfaces() {
        let current = HostFacts.current()
        #expect(!current.interfaceAddresses.contains(ip("127.0.0.1")))
    }
}

@Suite struct IPAddressTests {
    @Test func rejectsEmbeddedNULAndControlBytes() {
        #expect(IPAddress("1.1.1.1\u{0}.example.com") == nil)
        #expect(IPAddress("::1\u{0}") == nil)
        #expect(IPAddress(" 1.1.1.1") == nil)
        #expect(IPAddress("") == nil)
        #expect(IPAddress("1.1.1.1") != nil)
    }

    @Test func parsesAndPrints() {
        #expect(ip("10.1.2.3").description == "10.1.2.3")
        #expect(ip("2606:4700:4700::1111").description == "2606:4700:4700::1111")
        #expect(IPAddress("github.com") == nil)
        #expect(IPNetwork("172.16.0.0/12")!.contains(ip("172.31.255.255")))
        #expect(!IPNetwork("172.16.0.0/12")!.contains(ip("172.32.0.0")))
        #expect(IPNetwork("fc00::/7")!.contains(ip("fdff::1")))
        #expect(IPNetwork("172.16.0.0/16")!.overlaps(IPNetwork("172.16.7.56/29")!))
    }
}

/// Anonymised `netstat -rn -f inet` from a Mac with a LAN, a tailnet and a
/// split-tunnel corporate VPN.
private let netstatFixture = """
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            10.0.0.1           UGScg                en12
default            link#25            UCSIg               utun4
default            link#29            UCSIg               utun8
10/24              link#13            UCS                  en12      !
10.0.0.1/32        link#13            UCS                  en12      !
10.0.0.1           aa:bb:cc:dd:ee:ff  UHLWIir              en12   1198
10.201/20          link#25            UCS                 utun4
100.64/10          link#25            UCS                 utun4
127                127.0.0.1          UCS                   lo0
127.0.0.1          127.0.0.1          UH                    lo0
169.254            link#13            UCS                  en12      !
172.16             link#29            UCS                 utun8
172.16.140.106     172.16.140.106     UH                  utun8
192.168.64         link#30            UC              bridge100      !
192.168.68/24      link#25            UCS                 utun4
224.0.0/4          link#13            UmCS                 en12      !
255.255.255.255/32 link#13            UCS                  en12      !
"""

@Suite struct RouteInspectorTests {
    let inspector = RouteInspector(netstatOutput: netstatFixture)

    @Test func parsesAbbreviatedDestinations() {
        #expect(RouteInspector.parseDestination("10/24") == IPNetwork("10.0.0.0/24"))
        #expect(RouteInspector.parseDestination("172.16") == IPNetwork("172.16.0.0/16"))
        #expect(RouteInspector.parseDestination("127") == IPNetwork("127.0.0.0/8"))
        #expect(RouteInspector.parseDestination("10.0.0.1") == IPNetwork("10.0.0.1/32"))
        #expect(inspector.routes.filter(\.isDefault).count == 3)
        #expect(inspector.defaultGateways == ["10.0.0.1"])
    }

    @Test func vmSubnetInsideVPNRouteOverlapsAndShadowsTheFront() throws {
        let subnet = try #require(RouteInspector.vmSubnet(for: "172.16.7.58"))
        #expect(subnet == IPNetwork("172.16.7.56/29"))
        let overlaps = inspector.overlaps(subnet)
        #expect(overlaps.contains { $0.interface == "utun8" })
        #expect(subnet.contains(ip("172.16.7.60")))
    }

    @Test func vmnetBridgeSubnetDoesNotOverlap() throws {
        let subnet = try #require(RouteInspector.vmSubnet(for: "192.168.64.3"))
        #expect(inspector.overlaps(subnet).isEmpty)
    }

    @Test func tunnelSubnetsListVPNRoutes() {
        let names = inspector.tunnelSubnets.map { "\($0.0)@\($0.1)" }
        #expect(names.contains("172.16.0.0/16@utun8"))
        #expect(names.contains("100.64.0.0/10@utun4"))
    }
}
