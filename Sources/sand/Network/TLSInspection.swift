import CryptoKit
import Foundation
import Network
import Security

/// The certificate chain the host's TLS stack built for one upstream host,
/// leaf first, anchor last (DER).
struct TLSChainObservation: Sendable, Equatable {
    let host: String
    let certificates: [Data]
    /// The host itself trusts the chain (system roots plus admin trust settings).
    let trusted: Bool
}

protocol TLSChainObserving: Sendable {
    func observe(host: String, port: UInt16, timeout: TimeInterval) async -> Result<TLSChainObservation, HostEgressProbeError>
}

/// Host certificate stores, read through `security(1)`; injectable for tests.
protocol HostTrustStore: Sendable {
    /// SHA-256 (uppercase hex) of every Apple-shipped root.
    func systemRootFingerprints() async -> Set<String>
    /// SHA-256 -> PEM for every certificate in /Library/Keychains/System.keychain.
    func systemKeychainCertificates() async -> [String: String]
    /// SHA-1 (uppercase hex) of every certificate that has a private key on the host.
    func identityFingerprints() async -> Set<String>
}

/// A host CA that intercepts upstream TLS, exported (public certificate only)
/// from the host System keychain so it can be trusted in the guest.
struct InspectionCA: Sendable, Equatable, Hashable {
    let sha256: String
    let subject: String
    let pem: String
    /// Self-signed root of the chain (trusted as a root in the guest); otherwise an intermediate.
    let isRoot: Bool
}

struct TLSInspectionReport: Sendable, Equatable {
    /// Hosts whose chain ends in a root Apple does not ship, with that chain's CA fingerprints.
    var intercepted: [String: [String]] = [:]
    /// Every intercepting CA, deduplicated, roots first.
    var authorities: [InspectionCA] = []
    /// Hosts the host could not complete a handshake with (not evidence of interception).
    var unreachable: [String: String] = [:]
    /// Reasons an intercepting CA cannot be trusted in the guest.
    var problems: [String] = []
    var probed: [String] = []

    var isIntercepted: Bool { !intercepted.isEmpty }

    var interceptedHosts: [String] { intercepted.keys.sorted() }

    /// `ca.example.com sha256=AA77...` for messages and audit lines.
    var authoritySummary: String {
        authorities.map { "\($0.subject) sha256=\($0.sha256)" }.joined(separator: "; ")
    }
}

/// Detects TLS interception of the host proxy's upstream connections.
///
/// Generic rule: the host completes a handshake to each representative
/// allowlisted host and builds the chain with its own trust settings. A chain
/// that ends in a root Apple does not ship (not in SystemRootCertificates)
/// was re-signed by a locally trusted CA: an endpoint agent (Netskope,
/// Zscaler...) or a corporate proxy. The guest does not trust that CA, so
/// jobs fail TLS. Nothing is hardcoded about any vendor or certificate.
struct TLSInspectionDetector: Sendable {
    let observer: TLSChainObserving
    let store: HostTrustStore
    var timeout: TimeInterval = 8

    static func live(processRunner: ProcessRunning) -> TLSInspectionDetector {
        TLSInspectionDetector(observer: SystemTLSChainObserver(), store: SecurityCLITrustStore(processRunner: processRunner))
    }

    /// Concrete names behind the GitHub preset's wildcards, plus hosts that are
    /// commonly inspected. Only names the policy allows are probed.
    static let representativeHosts = [
        "github.com", "api.github.com", "codeload.github.com",
        "objects.githubusercontent.com", "raw.githubusercontent.com", "release-assets.githubusercontent.com",
        "pipelines.actions.githubusercontent.com", "results-receiver.actions.githubusercontent.com",
        "productionresultssa0.blob.core.windows.net", "ghcr.io", "pkg-containers.githubusercontent.com"
    ]

    /// Representative GitHub hosts plus up to eight other exact allowlisted names.
    static func probeHosts(for egress: EgressPolicy) -> [String] {
        var hosts = representativeHosts.filter { egress.allows(host: $0, port: 443) }
        let extra = egress.rules.compactMap { rule -> String? in
            guard rule.port == 443, case let .exact(name) = rule.pattern.kind else { return nil }
            return name
        }
        .filter { !hosts.contains($0) && !$0.hasPrefix("productionresultssa") && !EgressPreset.github.domains.contains($0) }
        .sorted()
        hosts.append(contentsOf: extra.prefix(8))
        return hosts
    }

    func detect(hosts: [String]) async -> TLSInspectionReport {
        let observations = await withTaskGroup(of: (String, Result<TLSChainObservation, HostEgressProbeError>).self) { group in
            for host in hosts {
                group.addTask { (host, await observer.observe(host: host, port: 443, timeout: timeout)) }
            }
            var all: [(String, Result<TLSChainObservation, HostEgressProbeError>)] = []
            for await item in group {
                all.append(item)
            }
            return all.sorted { $0.0 < $1.0 }
        }
        return await classify(observations, probed: hosts)
    }

    func classify(_ observations: [(String, Result<TLSChainObservation, HostEgressProbeError>)], probed: [String]) async -> TLSInspectionReport {
        var report = TLSInspectionReport(probed: probed)
        let roots = await store.systemRootFingerprints()
        var interceptingDER: [String: Data] = [:]
        var rootFingerprints = Set<String>()
        for (host, result) in observations {
            switch result {
            case let .failure(error):
                report.unreachable[host] = error.description
            case let .success(observation):
                guard let anchor = observation.certificates.last else {
                    report.unreachable[host] = "empty certificate chain"
                    continue
                }
                if !observation.trusted {
                    report.unreachable[host] = "the host does not trust the chain"
                    continue
                }
                let anchorFingerprint = Self.sha256(anchor)
                guard !roots.contains(anchorFingerprint) else { continue }
                // Every CA in the chain that Apple does not ship (the leaf is the server's own).
                let authorities = observation.certificates.dropFirst().filter { !roots.contains(Self.sha256($0)) }
                guard !authorities.isEmpty else {
                    report.intercepted[host] = [anchorFingerprint]
                    report.problems.append("\(host): the chain is a single self-signed certificate; refusing to trust a leaf")
                    continue
                }
                report.intercepted[host] = authorities.map(Self.sha256)
                for der in authorities {
                    interceptingDER[Self.sha256(der)] = der
                }
                rootFingerprints.insert(anchorFingerprint)
            }
        }
        guard !interceptingDER.isEmpty else {
            report.problems = Array(Set(report.problems)).sorted()
            return report
        }
        let keychain = await store.systemKeychainCertificates()
        let identities = await store.identityFingerprints()
        for (fingerprint, der) in interceptingDER.sorted(by: { $0.key < $1.key }) {
            let subject = Self.subject(der) ?? "unknown"
            guard let pem = keychain[fingerprint] else {
                report.problems.append("intercepting CA '\(subject)' (sha256 \(fingerprint)) is not in /Library/Keychains/System.keychain")
                continue
            }
            guard Self.derFromPEM(pem).map(Self.sha256) == fingerprint else {
                report.problems.append("intercepting CA '\(subject)' (sha256 \(fingerprint)): exported PEM does not match the observed certificate")
                continue
            }
            if identities.contains(Self.sha1(der)) {
                report.problems.append("intercepting CA '\(subject)' (sha256 \(fingerprint)) has a private key on this host; refusing to trust a host-signable CA in the guest")
                continue
            }
            report.authorities.append(InspectionCA(sha256: fingerprint, subject: subject, pem: pem, isRoot: rootFingerprints.contains(fingerprint)))
        }
        report.authorities.sort { ($0.isRoot ? 0 : 1, $0.sha256) < ($1.isRoot ? 0 : 1, $1.sha256) }
        report.problems = Array(Set(report.problems)).sorted()
        return report
    }

    static func sha256(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02X", $0) }.joined()
    }

    static func sha1(_ data: Data) -> String {
        Insecure.SHA1.hash(data: data).map { String(format: "%02X", $0) }.joined()
    }

    static func subject(_ der: Data) -> String? {
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else { return nil }
        return SecCertificateCopySubjectSummary(certificate) as String?
    }

    static func derFromPEM(_ pem: String) -> Data? {
        let body = pem.split(whereSeparator: \.isNewline)
            .filter { !$0.hasPrefix("-----") }
            .joined()
        return Data(base64Encoded: body)
    }

    /// Splits `security find-certificate -a -Z -p` output into SHA-256 -> PEM.
    static func parseKeychainDump(_ output: String) -> [String: String] {
        var result: [String: String] = [:]
        var fingerprint: String?
        var pem: [String] = []
        var inPEM = false
        for rawLine in output.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("SHA-256 hash:") {
                fingerprint = line.dropFirst("SHA-256 hash:".count).trimmingCharacters(in: .whitespaces).uppercased()
            } else if line == "-----BEGIN CERTIFICATE-----" {
                inPEM = true
                pem = [line]
            } else if line == "-----END CERTIFICATE-----", inPEM {
                pem.append(line)
                inPEM = false
                if let fingerprint {
                    result[fingerprint] = pem.joined(separator: "\n") + "\n"
                }
                fingerprint = nil
            } else if inPEM {
                pem.append(line)
            }
        }
        return result
    }

    /// SHA-256 values from `security find-certificate -a -Z`.
    static func parseFingerprints(_ output: String) -> Set<String> {
        Set(output.split(whereSeparator: \.isNewline).compactMap { line -> String? in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("SHA-256 hash:") else { return nil }
            return trimmed.dropFirst("SHA-256 hash:".count).trimmingCharacters(in: .whitespaces).uppercased()
        })
    }

    /// 40-hex SHA-1 values from `security find-identity`.
    static func parseIdentities(_ output: String) -> Set<String> {
        Set(output.split(whereSeparator: { $0.isWhitespace }).compactMap { token -> String? in
            let value = String(token)
            guard value.count == 40, value.allSatisfy(\.isHexDigit) else { return nil }
            return value.uppercased()
        })
    }
}

struct SecurityCLITrustStore: HostTrustStore {
    let processRunner: ProcessRunning
    static let systemRoots = "/System/Library/Keychains/SystemRootCertificates.keychain"
    static let systemKeychain = "/Library/Keychains/System.keychain"

    private func output(_ arguments: [String]) async -> String {
        (try? await processRunner.run(executable: "security", arguments: arguments, wait: true))?.stdout ?? ""
    }

    func systemRootFingerprints() async -> Set<String> {
        TLSInspectionDetector.parseFingerprints(await output(["find-certificate", "-a", "-Z", Self.systemRoots]))
    }

    func systemKeychainCertificates() async -> [String: String] {
        TLSInspectionDetector.parseKeychainDump(await output(["find-certificate", "-a", "-Z", "-p", Self.systemKeychain]))
    }

    func identityFingerprints() async -> Set<String> {
        let all = await output(["find-identity"])
        let system = await output(["find-identity", Self.systemKeychain])
        return TLSInspectionDetector.parseIdentities(all + "\n" + system)
    }
}

/// Captures the chain the host builds, using the host's trust settings, then
/// aborts the handshake (no application data is sent).
struct SystemTLSChainObserver: TLSChainObserving {
    func observe(host: String, port: UInt16, timeout: TimeInterval) async -> Result<TLSChainObservation, HostEgressProbeError> {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return .failure(.failed("bad port")) }
        let queue = DispatchQueue(label: "sand.tls-inspection")
        let capture = ChainCapture()
        let options = NWProtocolTLS.Options()
        sec_protocol_options_set_tls_server_name(options.securityProtocolOptions, host)
        sec_protocol_options_set_verify_block(options.securityProtocolOptions, { _, trust, complete in
            let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
            var error: CFError?
            let trusted = SecTrustEvaluateWithError(secTrust, &error)
            let chain = (SecTrustCopyCertificateChain(secTrust) as? [SecCertificate]) ?? []
            capture.set(TLSChainObservation(host: host, certificates: chain.map { SecCertificateCopyData($0) as Data }, trusted: trusted))
            complete(false)
        }, queue)
        let parameters = NWParameters(tls: options)
        // Same path as the egress proxy's upstream sockets (getaddrinfo + connect),
        // which never use a system proxy or PAC file.
        parameters.preferNoProxies = true
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: parameters)
        let once = ChainOnce()
        let failure: HostEgressProbeError? = await withCheckedContinuation { continuation in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready, .cancelled:
                    if once.claim() { connection.cancel(); continuation.resume(returning: nil) }
                case let .failed(error), let .waiting(error):
                    if once.claim() { connection.cancel(); continuation.resume(returning: .failed("\(error)")) }
                default:
                    break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + timeout) {
                if once.claim() { connection.cancel(); continuation.resume(returning: .timeout) }
            }
        }
        // The verify block rejects on purpose, so a captured chain wins over the resulting failure.
        if let observation = capture.value {
            return .success(observation)
        }
        return .failure(failure ?? .failed("no certificate chain"))
    }
}

private final class ChainCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var observation: TLSChainObservation?
    var value: TLSChainObservation? { lock.withLock { observation } }
    func set(_ value: TLSChainObservation) { lock.withLock { observation = value } }
}

private final class ChainOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    func claim() -> Bool {
        lock.withLock {
            guard !done else { return false }
            done = true
            return true
        }
    }
}

/// Guest-side installation of the intercepting CA(s): public certificates only.
enum GuestInspectionTrust {
    static let directory = "$HOME/.sand"
    static let bundlePath = "$HOME/.sand/ca-bundle.pem"
    static let extraPath = "$HOME/.sand/inspection-ca.pem"
    static let okMarker = "SAND_CA_OK"

    /// Writes the CA file and a combined bundle (guest default bundle + CA, never
    /// replacing the default), trusts the root(s) in the macOS System keychain or
    /// the Linux CA store. Fails (non-zero, no marker) only when the bundle
    /// cannot be built; keychain trust is best effort with a WARN line.
    static func installCommand(_ authorities: [InspectionCA]) -> String {
        var lines = [
            "set -e",
            "d=\"$HOME/.sand\"; mkdir -p \"$d\"; chmod 700 \"$d\"",
            ": > \"$d/inspection-ca.pem\""
        ]
        for (index, ca) in authorities.enumerated() {
            let file = "\"$d/inspection-ca-\(index).pem\""
            lines.append("printf '%s' \(GitHubProvisioner.shellQuote(ca.pem)) > \(file)")
            lines.append("cat \(file) >> \"$d/inspection-ca.pem\"")
        }
        lines += [
            "base=''",
            "for f in /etc/ssl/cert.pem /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem; do if [ -s \"$f\" ]; then base=\"$f\"; break; fi; done",
            "if [ -z \"$base\" ] && [ \"$(uname -s)\" = Darwin ]; then security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain > \"$d/system-roots.pem\"; base=\"$d/system-roots.pem\"; fi",
            "if [ -z \"$base\" ]; then echo 'ERROR: no default CA bundle found in the guest'; exit 1; fi",
            "cat \"$base\" \"$d/inspection-ca.pem\" > \"$d/ca-bundle.pem.tmp\" && mv \"$d/ca-bundle.pem.tmp\" \"$d/ca-bundle.pem\"",
            "set +e"
        ]
        for (index, ca) in authorities.enumerated() {
            let file = "\"$d/inspection-ca-\(index).pem\""
            let darwin = ca.isRoot
                // Trusted for TLS server authentication only (-p ssl, plus the basic
                // X.509 policy it builds on), never for code signing, S/MIME, etc.
                ? "sudo -n security add-trusted-cert -d -r trustRoot -p ssl -p basic -k /Library/Keychains/System.keychain \(file)"
                : "sudo -n security add-certificates -k /Library/Keychains/System.keychain \(file)"
            lines.append("if [ \"$(uname -s)\" = Darwin ]; then \(darwin) >/dev/null 2>&1 || echo 'WARN: could not add inspection CA \(index) to the guest System keychain'; "
                + "elif command -v update-ca-certificates >/dev/null 2>&1; then sudo -n cp \(file) /usr/local/share/ca-certificates/sand-inspection-ca-\(index).crt && sudo -n update-ca-certificates >/dev/null 2>&1 || echo 'WARN: could not add inspection CA \(index) to the guest CA store'; fi")
        }
        lines.append("echo \(okMarker)")
        return lines.joined(separator: "\n")
    }
}
