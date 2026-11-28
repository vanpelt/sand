import Foundation

/// Resolves a steered GitHub name and rides out a brief "steering flip".
///
/// Observed on a BlastShield Mac: `api.github.com` resolved to its public
/// address (140.82.114.6) ~20 s after the VM's proxy started, although it had
/// resolved to the private front (172.16.0.150) when the proxy started and did
/// again ~20 s later. The likely cause is the VM's vmnet interface coming up
/// and macOS re-evaluating its resolver configuration, during which the VPN's
/// supplemental (split-DNS) resolver is briefly not consulted.
///
/// For a name that is expected to be steered (it resolved to a private front
/// when the proxy started, or earlier in this VM session, or the policy sets
/// `requireSteering`), a public-only answer or a resolver error is retried with
/// a short backoff, and the first steered answer wins.
struct SteeringResolver: Sendable {
    struct Outcome: Sendable, Equatable {
        /// The answer to use: the first steered answer, or the last one seen.
        let addresses: [IPAddress]
        /// The first answer (empty when the first resolution failed).
        let firstAnswer: [IPAddress]
        /// Resolutions made, including the first.
        let attempts: Int
        /// Seconds spent between the first and the last resolution.
        let waited: TimeInterval

        /// True when the answer had to be retried.
        var flipped: Bool { attempts > 1 }

        /// True when the final answer contains a steerable (RFC1918) address.
        var steered: Bool { SteeringResolver.hasSteerable(addresses) }
    }

    /// ~5 s in total: long enough for a resolver reconfiguration to settle,
    /// short enough to stay well inside the proxy's connect timeout.
    static let defaultRetryDelays: [TimeInterval] = [0.25, 0.5, 0.75, 1.0, 1.25, 1.25]

    let resolver: HostResolving
    let retryDelays: [TimeInterval]
    let sleep: @Sendable (TimeInterval) async -> Void

    init(
        resolver: HostResolving,
        retryDelays: [TimeInterval] = SteeringResolver.defaultRetryDelays,
        sleep: @escaping @Sendable (TimeInterval) async -> Void = { seconds in
            try? await Task.sleep(nanoseconds: UInt64(max(0, seconds) * 1_000_000_000))
        }
    ) {
        self.resolver = resolver
        self.retryDelays = retryDelays
        self.sleep = sleep
    }

    static func hasSteerable(_ addresses: [IPAddress]) -> Bool {
        addresses.contains { address in
            let v4 = address.unwrappedIPv4Mapped ?? address
            return DestinationGuard.steerableRanges.contains { $0.contains(v4) }
        }
    }

    /// Steerable addresses first, keeping the resolver's order otherwise, so a
    /// mixed answer for a steered name uses the VPN front.
    static func preferSteered(_ addresses: [IPAddress]) -> [IPAddress] {
        let steerable = addresses.filter { hasSteerable([$0]) }
        return steerable + addresses.filter { !hasSteerable([$0]) }
    }

    /// With `expectSteered` false this is a single resolution.
    func resolve(_ host: String, expectSteered: Bool) async throws -> Outcome {
        let start = Date()
        var latest: [IPAddress]?
        var lastError: Error?
        do {
            latest = try await resolver.resolve(host)
        } catch {
            lastError = error
        }
        let firstAnswer = latest ?? []
        var attempts = 1
        func outcome(_ addresses: [IPAddress]) -> Outcome {
            Outcome(addresses: addresses, firstAnswer: firstAnswer, attempts: attempts, waited: Date().timeIntervalSince(start))
        }
        if let first = latest, !expectSteered || Self.hasSteerable(first) {
            return outcome(first)
        }
        guard expectSteered else {
            throw lastError ?? HostResolverError.failed(host, "no answer")
        }
        for delay in retryDelays {
            await sleep(delay)
            attempts += 1
            do {
                let next = try await resolver.resolve(host)
                latest = next
                if Self.hasSteerable(next) {
                    return outcome(next)
                }
            } catch {
                lastError = error
            }
        }
        if let latest {
            return outcome(latest)
        }
        throw lastError ?? HostResolverError.failed(host, "no answer")
    }
}

/// Names this VM's proxy has seen resolve to a steered front. Only touched
/// from the proxy's serial queue.
struct SteeringMemory: Sendable {
    private(set) var names: Set<String>

    init(seed: Set<String> = []) {
        names = Set(seed.map(DomainPattern.normalize))
    }

    func contains(_ host: String) -> Bool {
        names.contains(DomainPattern.normalize(host))
    }

    mutating func note(_ host: String) {
        names.insert(DomainPattern.normalize(host))
    }
}
