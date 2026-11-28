import ArgumentParser
import Foundation

@available(macOS 15.0, *)
struct BrokerCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "broker",
        abstract: "Broker-mode development tools: device keys and a local mock broker.",
        subcommands: [MockBrokerCommand.self, BrokerKeygenCommand.self]
    )
}

@available(macOS 15.0, *)
struct BrokerKeygenCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "keygen",
        abstract: "Create a P-256 device key (<out>/<device-id>.key.pem, mode 0600) and its public key."
    )

    @Option(name: .long, help: "Device id (^[a-z0-9][a-z0-9-]{0,49}$).")
    var deviceId: String
    @Option(name: .long, help: "Output directory.")
    var out: String = "~/.sand/broker"

    mutating func run() async throws {
        guard BrokerConfig.isValidDeviceId(deviceId) else {
            throw ValidationError("--device-id must match ^[a-z0-9][a-z0-9-]{0,49}$")
        }
        let key = DeviceKey.generate()
        let paths = try key.save(directory: out, deviceId: deviceId)
        print("device key:  \(paths.privatePath) (0600)")
        print("public key:  \(paths.publicPath)")
        print("key_id:      \(key.keyId)")
    }
}

/// `sand broker mock`: the broker API on loopback for development. It signs
/// with a GitHub App key on this Mac (Keychain label or PEM) and must never
/// be used for enterprise endpoints.
@available(macOS 15.0, *)
struct MockBrokerCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "mock",
        abstract: "Run the development-only mock broker on 127.0.0.1."
    )

    @Option(name: .shortAndLong, help: "Mock broker YAML (see fixtures/broker_mock.yml).")
    var config: String
    @Option(name: .long, help: "Append sand.audit.v1 JSON lines here.")
    var auditLog: String?
    @OptionGroup
    var logLevel: LogLevelOptions

    static let enableVariable = "SAND_DEVELOPMENT_BROKER"

    mutating func run() async throws {
        guard ProcessInfo.processInfo.environment[Self.enableVariable] == "1" else {
            throw ValidationError("sand broker mock is development only; set \(Self.enableVariable)=1 to run it.")
        }
        let level = logLevel.resolvedLevel()
        let logger = Logger(label: "broker.mock", minimumLevel: level, sink: try logLevel.makeLogFileSink())
        let config = try MockBrokerConfig.load(path: config)
        let errors = config.validationErrors()
        guard errors.isEmpty else {
            throw ValidationError("mock broker config invalid: \(errors.joined(separator: "; "))")
        }
        let devices = try config.devices.map { device in
            MockBrokerStore.DeviceRecord(
                id: device.id,
                publicKey: try DeviceKey.loadPublicKey(path: device.publicKeyPath),
                owner: BrokerOwner(githubUserId: device.owner.id, githubLogin: device.owner.login),
                revoked: device.revoked ?? false
            )
        }
        let auth = try GitHubAuth(
            appId: config.github.appId,
            privateKeyPath: config.github.privateKeyPath.map(Config.expandPath),
            privateKeyKeychainLabel: config.github.privateKeyKeychainLabel
        )
        let github = GitHubService(auth: auth, session: URLSession.shared, organization: config.github.owner, repository: config.github.repository)
        let auditFile = try auditLog.map { try AuditFileSink(path: $0) }
        let store = MockBrokerStore(config: config, devices: devices, github: github, audit: { event in
            let line = event.jsonLine()
            logger.info("audit \(line)")
            auditFile?.writeLine(line)
        })
        // Sign the first App JWT now: an unanswered Keychain prompt or a bad
        // key fails here, not inside the first allocation request.
        FileHandle.standardError.write(Data("sand broker mock: signing a GitHub App JWT (approve the Keychain prompt if one appears)...\n".utf8))
        do {
            _ = try await store.warmUp()
        } catch let error as BrokerAPIError {
            throw ValidationError("mock broker could not reach GitHub as the App (\(error.code): \(error.message)). If a Keychain prompt is pending, approve it and start again.")
        }
        let failures = await store.checkPreconditions(force: true)
        if !failures.isEmpty {
            let mode = config.policy.enforcesTierAPreconditions ? "enforce: allocations will be refused" : "warn: allocating anyway"
            FileHandle.standardError.write(Data("sand broker mock: Tier A preconditions not met (\(mode)): \(failures.joined(separator: ", "))\n".utf8))
            logger.warning("tier A preconditions not met (\(mode)): \(failures.joined(separator: ","))")
        }
        let routes = MockBrokerRoutes(store: store)
        let server = LoopbackHTTPServer(maxBodyBytes: 16_384) { request in
            await routes.handle(request)
        }
        let port = try await server.start(host: config.listen.host, port: UInt16(config.listen.port))
        FileHandle.standardError.write(Data("""
        ************************************************************************
        sand broker mock: DEVELOPMENT ONLY. Listening on http://127.0.0.1:\(port)
        It signs with the GitHub App key on this Mac and serves \(config.github.owner)/\(config.github.repository)
        only. Never point enterprise devices or production credentials at it.
        ************************************************************************

        """.utf8))
        logger.info("mock broker listening on 127.0.0.1:\(port) policy \(config.policy.version)")
        await store.collectGarbage()
        var lastGC = Date()
        while !Task.isCancelled {
            try await Task.sleep(nanoseconds: 2_000_000_000)
            await store.tick()
            if Date().timeIntervalSince(lastGC) >= 300 {
                await store.collectGarbage()
                lastGC = Date()
            }
        }
        server.stop()
    }
}
