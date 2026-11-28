import Foundation

enum SoftnetRuleError: Error, Equatable, CustomStringConvertible {
    case containsComma(String)
    case portfulAllowTooWide(String)
    case invalidCIDR(String)

    var description: String {
        switch self {
        case let .containsComma(rule):
            return "softnet rule '\(rule)' contains a comma"
        case let .portfulAllowTooWide(rule):
            return "softnet rule '\(rule)' allows a port on a prefix wider than /24; port-scoped rules beat the default block"
        case let .invalidCIDR(value):
            return "'\(value)' is not an IPv4 CIDR"
        }
    }
}

/// One softnet `--allow` rule. Rendered in softnet's stateful-rule grammar:
/// `in|out [proto P] [TARGET] [port N]`.
struct SoftnetRule: Hashable, Sendable {
    enum Direction: String, Sendable {
        case inbound = "in"
        case outbound = "out"
    }

    enum Target: Hashable, Sendable {
        case host
        case cidr(String)
    }

    let direction: Direction
    let proto: SoftnetProto?
    let target: Target
    let port: Int?

    static func sshFromHost(port: Int) -> SoftnetRule {
        SoftnetRule(direction: .inbound, proto: .tcp, target: .host, port: port)
    }

    func render() -> String {
        var parts = [direction.rawValue]
        if let proto {
            parts.append("proto \(proto.rawValue)")
        }
        switch target {
        case .host:
            parts.append("@host")
        case let .cidr(value):
            parts.append(value)
        }
        if let port {
            parts.append("port \(port)")
        }
        return parts.joined(separator: " ")
    }
}

/// A validated softnet rule set. The builder is the only way to produce Tart
/// arguments for softnet, so its checks cannot be bypassed.
struct SoftnetRuleSet: Hashable, Sendable {
    let blocks: [String]
    let allows: [SoftnetRule]

    /// Default-deny: block 0.0.0.0/0 and allow exactly `allows`.
    static func denyAll(allowing allows: [SoftnetRule]) throws -> SoftnetRuleSet {
        try SoftnetRuleSet(blocks: ["0.0.0.0/0"], allows: allows)
    }

    init(blocks: [String], allows: [SoftnetRule]) throws {
        for rule in allows {
            let rendered = rule.render()
            guard !rendered.contains(",") else { throw SoftnetRuleError.containsComma(rendered) }
            if case let .cidr(value) = rule.target {
                guard let network = IPNetwork(value), network.address.isIPv4, value.contains("/") else {
                    throw SoftnetRuleError.invalidCIDR(value)
                }
                // Softnet prefers port-scoped rules over the longest prefix, so a
                // portful allow on a wide prefix would punch through the block.
                if rule.port != nil, network.prefixLength < 24 {
                    throw SoftnetRuleError.portfulAllowTooWide(rendered)
                }
            }
        }
        for block in blocks {
            guard !block.contains(","), IPNetwork(block)?.address.isIPv4 == true else {
                throw SoftnetRuleError.invalidCIDR(block)
            }
        }
        self.blocks = blocks
        self.allows = allows
    }

    /// Never emits `--net-softnet-expose`.
    var tartArguments: [String] {
        var args = ["--net-softnet"]
        if !blocks.isEmpty {
            args.append("--net-softnet-block=" + blocks.joined(separator: ","))
        }
        if !allows.isEmpty {
            args.append("--net-softnet-allow=" + allows.map { $0.render() }.joined(separator: ","))
        }
        return args
    }
}
