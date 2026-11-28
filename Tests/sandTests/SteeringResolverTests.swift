import Foundation
import Testing
@testable import sand

/// Returns one scripted answer per call (the last one repeats); nil throws.
private final class ScriptedResolver: HostResolving, @unchecked Sendable {
    private let lock = NSLock()
    private var answers: [[sand.IPAddress]?]
    private(set) var calls = 0

    init(_ answers: [[String]?]) {
        self.answers = answers.map { $0?.compactMap(sand.IPAddress.init) }
    }

    func resolve(_ host: String) async throws -> [sand.IPAddress] {
        let answer: [sand.IPAddress]? = lock.withLock {
            calls += 1
            return answers.count > 1 ? answers.removeFirst() : answers.first ?? nil
        }
        guard let answer else { throw HostResolverError.failed(host, "scripted failure") }
        return answer
    }

    var callCount: Int { lock.withLock { calls } }
}

private final class SleepLog: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [TimeInterval] = []
    var delays: [TimeInterval] { lock.withLock { storage } }
    func record(_ delay: TimeInterval) { lock.withLock { storage.append(delay) } }
}

@Suite struct SteeringResolverTests {
    private func resolver(_ scripted: ScriptedResolver, sleeps: SleepLog = SleepLog()) -> SteeringResolver {
        SteeringResolver(resolver: scripted, retryDelays: [0.25, 0.5, 1, 1.5]) { sleeps.record($0) }
    }

    @Test func publicAnswerFlipsBackToTheSteeredFront() async throws {
        // Observed: api.github.com public right after VM network bring-up, steered again later.
        let scripted = ScriptedResolver([["140.82.114.6"], ["140.82.114.6"], ["172.16.0.150"]])
        let sleeps = SleepLog()
        let outcome = try await resolver(scripted, sleeps: sleeps).resolve("api.github.com", expectSteered: true)
        #expect(outcome.addresses == [IPAddress("172.16.0.150")!])
        #expect(outcome.firstAnswer == [IPAddress("140.82.114.6")!])
        #expect(outcome.attempts == 3)
        #expect(outcome.flipped && outcome.steered)
        #expect(sleeps.delays == [0.25, 0.5])
    }

    @Test func persistentPublicAnswerGivesUpAfterTheBackoff() async throws {
        let scripted = ScriptedResolver([["140.82.114.6"]])
        let sleeps = SleepLog()
        let outcome = try await resolver(scripted, sleeps: sleeps).resolve("api.github.com", expectSteered: true)
        #expect(outcome.addresses == [IPAddress("140.82.114.6")!])
        #expect(outcome.attempts == 5)
        #expect(!outcome.steered)
        #expect(sleeps.delays == [0.25, 0.5, 1, 1.5])
        #expect(scripted.callCount == 5)
    }

    @Test func unexpectedNameResolvesOnce() async throws {
        let scripted = ScriptedResolver([["140.82.114.6"], ["172.16.0.150"]])
        let outcome = try await resolver(scripted).resolve("api.github.com", expectSteered: false)
        #expect(outcome.attempts == 1)
        #expect(!outcome.flipped)
        #expect(scripted.callCount == 1)
    }

    @Test func steeredFirstAnswerIsNotRetried() async throws {
        let scripted = ScriptedResolver([["172.16.7.60"]])
        let outcome = try await resolver(scripted).resolve("github.com", expectSteered: true)
        #expect(outcome.attempts == 1 && outcome.steered)
    }

    @Test func resolverErrorsDuringTheFlipAreRetried() async throws {
        let scripted = ScriptedResolver([nil, nil, ["172.16.0.150"]])
        let outcome = try await resolver(scripted).resolve("api.github.com", expectSteered: true)
        #expect(outcome.steered)
        #expect(outcome.firstAnswer.isEmpty)
        #expect(outcome.attempts == 3)
    }

    @Test func allErrorsThrow() async {
        let scripted = ScriptedResolver([nil])
        await #expect(throws: (any Error).self) {
            try await resolver(scripted).resolve("api.github.com", expectSteered: true)
        }
        let once = ScriptedResolver([nil])
        await #expect(throws: (any Error).self) {
            try await resolver(once).resolve("api.github.com", expectSteered: false)
        }
        #expect(once.callCount == 1)
    }

    @Test func mixedAnswerPrefersTheSteeredFront() {
        let mixed = ["140.82.114.6", "172.16.0.150"].compactMap(IPAddress.init)
        #expect(SteeringResolver.preferSteered(mixed).first == IPAddress("172.16.0.150"))
        #expect(SteeringResolver.hasSteerable(mixed))
        #expect(!SteeringResolver.hasSteerable([IPAddress("100.64.0.1")!]))
    }

    @Test func defaultBackoffIsAboutFiveSeconds() {
        let total = SteeringResolver.defaultRetryDelays.reduce(0, +)
        #expect(total >= 4 && total <= 6)
        #expect(total < EgressProxy.Limits().connectTimeout)
    }

    @Test func learningRecordsWhichNamesWereSteered() async {
        let routes = RouteInspector(netstatOutput: """
        default            10.0.0.1           UGScg                en12
        172.16             link#30            UCS                 utun8
        """)
        let resolver = StaticHostResolver(table: ["github.com": [IPAddress("172.16.7.60")!], "api.github.com": [IPAddress("140.82.114.6")!]])
        let observed = await DestinationGuard.learnSteering(names: ["github.com", "api.github.com", "gist.github.com"], resolver: resolver, routes: routes)
        #expect(observed.interfaces == ["utun8"])
        #expect(observed.steeredNames == ["github.com"])
        #expect(observed.publicNames == ["api.github.com"])
    }

    @Test func memoryIsCaseAndDotInsensitive() {
        var memory = SteeringMemory(seed: ["GitHub.com."])
        #expect(memory.contains("github.com"))
        #expect(!memory.contains("api.github.com"))
        memory.note("API.github.com")
        #expect(memory.contains("api.github.com"))
    }

    @Test func requireSteeringChangesThePolicyHash() throws {
        let plain = try NetworkConfig.secureDefault.compile()
        let required = try NetworkConfig(selection: .profile(.github), requireSteering: true).compile()
        #expect(plain.policyHash != required.policyHash)
        // Logging-only options do not.
        let quiet = try NetworkConfig(selection: .profile(.github), quietDenies: ["noise.example.com"], quietOSBackground: false).compile()
        #expect(plain.policyHash == quiet.policyHash)
    }
}
