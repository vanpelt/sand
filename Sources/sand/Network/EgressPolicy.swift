import Foundation

enum DomainPatternError: Error, Equatable, CustomStringConvertible {
    case empty
    case ipLiteral(String)
    case bareWildcard
    case wildcardTooBroad(String)
    case misplacedWildcard(String)
    case invalidLabel(String)
    case invalidPort(String)
    case tooLong(String)

    var description: String {
        switch self {
        case .empty:
            return "domain must not be empty"
        case let .ipLiteral(value):
            return "'\(value)' is an IP literal; use allowedCIDRs for addresses"
        case .bareWildcard:
            return "'*' would allow every destination"
        case let .wildcardTooBroad(value):
            return "'\(value)' is too broad; a wildcard needs at least two labels after it (e.g. *.example.com)"
        case let .misplacedWildcard(value):
            return "'\(value)' may only use a leading '*.' or one '*' inside the first label"
        case let .invalidLabel(value):
            return "'\(value)' is not a valid hostname (letters, digits and '-' only; use punycode for IDN)"
        case let .invalidPort(value):
            return "'\(value)' has a port outside 1-65535"
        case let .tooLong(value):
            return "'\(value)' is longer than 253 characters"
        }
    }
}

/// A hostname pattern matched by the egress proxy. Matching is case- and
/// trailing-dot-insensitive and never crosses label boundaries.
struct DomainPattern: Hashable, Sendable, Comparable, CustomStringConvertible {
    enum Kind: Hashable, Sendable {
        /// `github.com`
        case exact(String)
        /// `*.actions.githubusercontent.com` stores `actions.githubusercontent.com`;
        /// matches one or more labels in front of it, never the apex itself.
        case suffix(String)
        /// `productionresultssa*.blob.core.windows.net`: the first label must
        /// start with `prefix` and end with `suffix`; the remaining labels match exactly.
        case firstLabelGlob(prefix: String, suffix: String, rest: String)
    }

    let kind: Kind

    init(kind: Kind) {
        self.kind = kind
    }

    static func parse(_ raw: String) throws -> DomainPattern {
        let value = normalize(raw)
        guard !value.isEmpty else { throw DomainPatternError.empty }
        guard value.count <= 253 else { throw DomainPatternError.tooLong(raw) }
        if value == "*" { throw DomainPatternError.bareWildcard }
        if IPAddress.isLiteral(value) || value.contains(":") || value.contains("[") {
            throw DomainPatternError.ipLiteral(raw)
        }
        let labels = value.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard labels.count >= 2 else { throw DomainPatternError.invalidLabel(raw) }
        let first = labels[0]
        let rest = Array(labels.dropFirst())
        if rest.contains(where: { $0.contains("*") }) {
            throw DomainPatternError.misplacedWildcard(raw)
        }
        try validateLabels(rest, raw: raw)
        if rest.last.map(isAllDigits) == true {
            throw DomainPatternError.ipLiteral(raw)
        }
        let restJoined = rest.joined(separator: ".")
        if first == "*" {
            guard rest.count >= 2 else { throw DomainPatternError.wildcardTooBroad(raw) }
            return DomainPattern(kind: .suffix(restJoined))
        }
        if first.contains("*") {
            let pieces = first.split(separator: "*", omittingEmptySubsequences: false).map(String.init)
            guard pieces.count == 2 else { throw DomainPatternError.misplacedWildcard(raw) }
            guard rest.count >= 2 else { throw DomainPatternError.wildcardTooBroad(raw) }
            guard !(pieces[0].isEmpty && pieces[1].isEmpty) else { throw DomainPatternError.misplacedWildcard(raw) }
            for piece in pieces where !piece.isEmpty {
                guard piece.allSatisfy(isLDH) else { throw DomainPatternError.invalidLabel(raw) }
            }
            if pieces[0].hasPrefix("-") || pieces[1].hasSuffix("-") {
                throw DomainPatternError.invalidLabel(raw)
            }
            return DomainPattern(kind: .firstLabelGlob(prefix: pieces[0], suffix: pieces[1], rest: restJoined))
        }
        try validateLabels([first], raw: raw)
        return DomainPattern(kind: .exact(value))
    }

    func matches(_ host: String) -> Bool {
        let candidate = Self.normalize(host)
        guard !candidate.isEmpty, !IPAddress.isLiteral(candidate) else { return false }
        switch kind {
        case let .exact(name):
            return candidate == name
        case let .suffix(apex):
            guard candidate.hasSuffix("." + apex) else { return false }
            let head = candidate.dropLast(apex.count + 1)
            return !head.isEmpty && head.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { !$0.isEmpty }
        case let .firstLabelGlob(prefix, suffix, rest):
            guard candidate.hasSuffix("." + rest) else { return false }
            let label = String(candidate.dropLast(rest.count + 1))
            guard !label.contains("."), label.count >= prefix.count + suffix.count else { return false }
            return label.hasPrefix(prefix) && label.hasSuffix(suffix) && !label.isEmpty && label.allSatisfy(Self.isLDH)
        }
    }

    var description: String {
        switch kind {
        case let .exact(name):
            return name
        case let .suffix(apex):
            return "*." + apex
        case let .firstLabelGlob(prefix, suffix, rest):
            return "\(prefix)*\(suffix).\(rest)"
        }
    }

    static func < (lhs: DomainPattern, rhs: DomainPattern) -> Bool {
        lhs.description < rhs.description
    }

    static func normalize(_ host: String) -> String {
        var value = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        while value.hasSuffix(".") {
            value.removeLast()
        }
        return value
    }

    private static func validateLabels(_ labels: [String], raw: String) throws {
        for label in labels {
            guard !label.isEmpty, label.count <= 63, label.allSatisfy(isLDH),
                  !label.hasPrefix("-"), !label.hasSuffix("-") else {
                throw DomainPatternError.invalidLabel(raw)
            }
        }
    }

    private static func isLDH(_ character: Character) -> Bool {
        character.isASCII && (character.isLetter || character.isNumber || character == "-")
    }

    private static func isAllDigits(_ label: String) -> Bool {
        !label.isEmpty && label.allSatisfy { $0.isASCII && $0.isNumber }
    }
}

/// A hostname pattern plus the TCP port it may be reached on.
struct DomainRule: Hashable, Sendable, Comparable, CustomStringConvertible {
    static let defaultPort = 443

    let pattern: DomainPattern
    let port: Int

    /// Parses `host`, `*.host`, or `host:port`. The port defaults to 443.
    static func parse(_ raw: String) throws -> DomainRule {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        var host = trimmed
        var port = defaultPort
        if let colon = trimmed.lastIndex(of: ":"), !trimmed.contains("["), trimmed.filter({ $0 == ":" }).count == 1 {
            let portText = trimmed[trimmed.index(after: colon)...]
            guard !portText.isEmpty, portText.allSatisfy({ $0.isASCII && $0.isNumber }),
                  let value = Int(portText), (1...65_535).contains(value) else {
                throw DomainPatternError.invalidPort(raw)
            }
            host = String(trimmed[..<colon])
            port = value
        }
        return DomainRule(pattern: try DomainPattern.parse(host), port: port)
    }

    func matches(host: String, port: Int) -> Bool {
        self.port == port && pattern.matches(host)
    }

    var description: String {
        port == Self.defaultPort ? pattern.description : "\(pattern):\(port)"
    }

    static func < (lhs: DomainRule, rhs: DomainRule) -> Bool {
        (lhs.pattern.description, lhs.port) < (rhs.pattern.description, rhs.port)
    }
}

/// Built-in, versioned destination bundles. Bump `policyVersion` whenever a
/// list changes so the policy hash in audit logs changes with it.
enum EgressPreset: String, CaseIterable, Sendable {
    case github
    case githubAttestations = "github-attestations"
    case npm
    case pypi
    case homebrew
    case rubygems
    case cocoapods
    case swiftpm

    static let policyVersion = "2026-11-27.1"

    var domains: [String] {
        switch self {
        case .github:
            return [
                "github.com", "www.github.com", "gist.github.com", "api.github.com",
                "codeload.github.com", "uploads.github.com", "lfs.github.com",
                "raw.githubusercontent.com", "objects.githubusercontent.com",
                "objects-origin.githubusercontent.com", "release-assets.githubusercontent.com",
                "github-releases.githubusercontent.com", "github-registry-files.githubusercontent.com",
                "github-cloud.githubusercontent.com", "pkg-containers.githubusercontent.com",
                "github-cloud.s3.amazonaws.com",
                "ghcr.io",
                "*.actions.githubusercontent.com",
                "*.pkg.github.com",
                "productionresultssa*.blob.core.windows.net"
            ]
        case .githubAttestations:
            return ["fulcio.githubapp.com", "timestamp.githubapp.com", "tuf-repo.github.com"]
        case .npm:
            return ["registry.npmjs.org"]
        case .pypi:
            return ["pypi.org", "files.pythonhosted.org"]
        case .homebrew:
            return ["formulae.brew.sh", "ghcr.io"]
        case .rubygems:
            return ["rubygems.org", "index.rubygems.org"]
        case .cocoapods:
            return ["cdn.cocoapods.org"]
        case .swiftpm:
            // Swift packages are fetched from github.com, which the github preset covers.
            return []
        }
    }

    /// The only names whose resolved private (VPN-steered) addresses may be used.
    /// On a host with split DNS (e.g. BlastShield) these resolve to private fronts.
    static let steeredNames: Set<String> = [
        "github.com", "www.github.com", "gist.github.com", "api.github.com",
        "codeload.github.com", "lfs.github.com"
    ]
}

enum VerifyLevel: String, Decodable, Sendable, CaseIterable {
    case basic
    case strict
    case off
}

enum SoftnetProto: String, Decodable, Sendable {
    case tcp
    case udp
}

/// An expert escape hatch: a direct softnet allow that bypasses the proxy.
struct DirectCIDRAllow: Decodable, Sendable, Hashable {
    let cidr: String
    let port: Int
    let proto: SoftnetProto
    let allowPrivate: Bool

    init(cidr: String, port: Int, proto: SoftnetProto = .tcp, allowPrivate: Bool = false) {
        self.cidr = cidr
        self.port = port
        self.proto = proto
        self.allowPrivate = allowPrivate
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        cidr = try container.decode(String.self, forKey: .cidr)
        port = try container.decode(Int.self, forKey: .port)
        proto = try container.decodeIfPresent(SoftnetProto.self, forKey: .proto) ?? .tcp
        allowPrivate = try container.decodeIfPresent(Bool.self, forKey: .allowPrivate) ?? false
    }

    private enum CodingKeys: String, CodingKey {
        case cidr, port, proto, allowPrivate
    }
}

/// The compiled hostname allowlist enforced by the host-side CONNECT proxy.
struct EgressPolicy: Sendable, Equatable {
    let rules: [DomainRule]
    let steeredNames: Set<String>
    let verify: VerifyLevel
    let extraCIDRs: [DirectCIDRAllow]

    func allows(host: String, port: Int) -> Bool {
        rules.contains { $0.matches(host: host, port: port) }
    }

    func isSteered(_ host: String) -> Bool {
        steeredNames.contains(DomainPattern.normalize(host))
    }

    /// IP-literal CONNECT targets are only allowed when an extra CIDR covers them.
    func allowsLiteral(_ address: IPAddress, port: Int) -> Bool {
        extraCIDRs.contains { allow in
            allow.proto == .tcp && allow.port == port && (IPNetwork(allow.cidr)?.contains(address) ?? false)
        }
    }
}
