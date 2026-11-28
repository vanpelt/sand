import Foundation

enum TartError: Error {
    case emptyIP
}

struct Tart: Sendable {
    enum VMStatus {
        case missing
        case stopped
        case running
    }
    struct DirectoryMount: Equatable {
        let hostPath: String
        let name: String
        let readOnly: Bool

        var runArgument: String {
            var options: [String] = []
            if readOnly {
                options.append("ro")
            }
            if options.isEmpty {
                return "\(name):\(hostPath)"
            }
            return "\(name):\(hostPath):" + options.joined(separator: ",")
        }
    }

    struct RunOptions {
        let directoryMounts: [DirectoryMount]
        let noAudio: Bool
        let noGraphics: Bool
        let noClipboard: Bool
        let nested: Bool
        let rootDiskOpts: String?
        let network: NetworkPolicy

        static let `default` = RunOptions(directoryMounts: [], noAudio: false, noGraphics: true, noClipboard: false, nested: false)

        init(directoryMounts: [DirectoryMount], noAudio: Bool, noGraphics: Bool, noClipboard: Bool, nested: Bool, rootDiskOpts: String? = nil, network: NetworkPolicy = .shared) {
            self.directoryMounts = directoryMounts
            self.noAudio = noAudio
            self.noGraphics = noGraphics
            self.noClipboard = noClipboard
            self.nested = nested
            self.rootDiskOpts = rootDiskOpts
            self.network = network
        }
    }

    struct Display {
        let width: Int
        let height: Int
        let unit: String?

        var argument: String {
            let suffix = unit.map { $0 } ?? ""
            return "\(width)x\(height)\(suffix)"
        }
    }

    let processRunner: ProcessRunning
    let logger: Logger
    /// Used to find tart's absolute path under the softnet backend; injectable for tests.
    let isExecutable: @Sendable (String) -> Bool

    init(processRunner: ProcessRunning, logger: Logger, isExecutable: @escaping @Sendable (String) -> Bool = { FileManager.default.isExecutableFile(atPath: $0) }) {
        self.processRunner = processRunner
        self.logger = logger
        self.isExecutable = isExecutable
    }

    func prepare(source: String) async throws {
        if try await hasOCI(source: source) {
            return
        }
        try await pull(source: source)
    }

    func pull(source: String) async throws {
        _ = try await run(arguments: ["pull", source], wait: true)
    }

    func clone(source: String, name: String) async throws {
        _ = try await run(arguments: ["clone", source, name], wait: true)
    }

    func set(
        name: String,
        cpuCores: Int?,
        memoryMb: Int?,
        display: Display?,
        displayRefit: Bool?,
        diskSizeGb: Int?
    ) async throws {
        var arguments = ["set", name]
        if let cpuCores {
            arguments.append(contentsOf: ["--cpu", String(cpuCores)])
        }
        if let memoryMb {
            arguments.append(contentsOf: ["--memory", String(memoryMb)])
        }
        if let display {
            arguments.append(contentsOf: ["--display", display.argument])
        }
        if let displayRefit {
            arguments.append(displayRefit ? "--display-refit" : "--no-display-refit")
        }
        if let diskSizeGb {
            arguments.append(contentsOf: ["--disk-size", String(diskSizeGb)])
        }
        guard arguments.count > 2 else {
            return
        }
        _ = try await run(arguments: arguments, wait: true)
    }

    @discardableResult
    func run(name: String, options: RunOptions = .default) throws -> ProcessHandle {
        var arguments = ["run", name]
        arguments.append(contentsOf: options.network.tartArguments)
        if options.noGraphics {
            arguments.append("--no-graphics")
        }
        if options.noAudio {
            arguments.append("--no-audio")
        }
        if options.noClipboard {
            arguments.append("--no-clipboard")
        }
        if options.nested {
            arguments.append("--nested")
        }
        if let rootDiskOpts = options.rootDiskOpts {
            arguments.append("--root-disk-opts=\(rootDiskOpts)")
        }
        for mount in options.directoryMounts {
            arguments.append("--dir")
            arguments.append(mount.runArgument)
        }
        logger.debug("tart \(arguments.joined(separator: " "))")
        let launch = try Self.runLaunch(network: options.network, isExecutable: isExecutable)
        return try processRunner.start(executable: launch.executable, arguments: arguments, environment: launch.environment)
    }

    enum LaunchError: Error, CustomStringConvertible {
        case softnetNotBound
        case tartNotFound

        var description: String {
            switch self {
            case .softnetNotBound:
                return "refusing to start tart under the softnet backend without a checked softnet binary"
            case .tartNotFound:
                return "tart not found in PATH"
            }
        }
    }

    /// The system directories tart run needs (sudo, diskutil, tar), never a
    /// user-writable one that could hold a different `softnet`.
    static let softnetSystemPath = "/usr/bin:/bin:/usr/sbin:/sbin"

    /// How to launch `tart run`. tart 2.42 execs the first `softnet` on its
    /// PATH, so under the softnet backend tart is started by absolute path with
    /// PATH set to the checked softnet's directory followed only by root-owned
    /// system directories: tart execs exactly that binary, and if it vanishes
    /// tart fails instead of finding the Homebrew one. Everything else in the
    /// environment (minus Sentry variables) is inherited.
    static func runLaunch(
        network: NetworkPolicy,
        base: [String: String] = ProcessInfo.processInfo.environment,
        isExecutable: (String) -> Bool = { FileManager.default.isExecutableFile(atPath: $0) }
    ) throws -> (executable: String, environment: [String: String]) {
        var environment = scrubbedEnvironment(base)
        guard network.usesSoftnet else {
            return ("tart", environment)
        }
        guard let softnet = network.host.softnet else {
            throw LaunchError.softnetNotBound
        }
        let searchPath = base["PATH"] ?? softnetSystemPath
        guard let tart = searchPath.split(separator: ":").map({ ($0 as Substring).appending("/tart") }).first(where: isExecutable) else {
            throw LaunchError.tartNotFound
        }
        environment["PATH"] = softnet.directory + ":" + softnetSystemPath
        return (tart, environment)
    }

    /// Variables Tart forwards to Sentry crash reporting; never hand them VM context.
    static let scrubbedVariables = ["SENTRY_DSN", "CIRRUS_SENTRY_TAGS"]

    static func scrubbedEnvironment(_ base: [String: String] = ProcessInfo.processInfo.environment) -> [String: String] {
        base.filter { !scrubbedVariables.contains($0.key) }
    }

    /// `tart run --help` mentions the stateful softnet allow flag.
    func supportsSoftnetAllow() async -> Bool {
        let help = (try? await run(arguments: ["run", "--help"], wait: true))?.stdout ?? ""
        return help.contains("--net-softnet-allow")
    }

    func version() async -> String {
        ((try? await run(arguments: ["--version"], wait: true))?.stdout ?? "unknown").trimmingCharacters(in: .whitespacesAndNewlines)
    }

    func ip(name: String, wait: Int) async throws -> String {
        let result = try await run(arguments: ["ip", name, "--wait", String(wait)], wait: true)
        let value = result?.stdout.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if value.isEmpty {
            throw TartError.emptyIP
        }
        return value
    }

    func stop(name: String, timeout: Int? = nil) async throws {
        var arguments = ["stop", name]
        if let timeout {
            arguments.append(contentsOf: ["--timeout", String(timeout)])
        }
        _ = try await run(arguments: arguments, wait: true)
    }

    func delete(name: String) async throws {
        _ = try await run(arguments: ["delete", name], wait: true)
    }

    func isRunning(name: String) async throws -> Bool {
        return try await status(name: name) == .running
    }

    func status(name: String) async throws -> VMStatus {
        let result = try await run(arguments: ["list", "--format", "json"], wait: true)
        let output = result?.stdout ?? ""
        guard let entry = entryFromJSON(output: output, name: name) else {
            return .missing
        }
        if entry.running == true {
            return .running
        }
        return .stopped
    }

    private func hasOCI(source: String) async throws -> Bool {
        let result = try await run(arguments: ["list", "--source", "oci", "--quiet"], wait: true)
        let output = result?.stdout ?? ""
        let expected = normalizeOCI(source)
        return output
            .split(separator: "\n")
            .map { normalizeOCI(String($0)) }
            .contains(expected)
    }

    private func normalizeOCI(_ source: String) -> String {
        let prefix = "oci://"
        if source.hasPrefix(prefix) {
            return String(source.dropFirst(prefix.count))
        }
        return source
    }

    private struct TartListEntry: Decodable {
        let name: String
        let running: Bool?

        private enum CodingKeys: String, CodingKey {
            case name = "Name"
            case running = "Running"
        }
    }

    private func entryFromJSON(output: String, name: String) -> TartListEntry? {
        guard let data = output.data(using: .utf8) else {
            return nil
        }
        guard let entries = try? JSONDecoder().decode([TartListEntry].self, from: data) else {
            return nil
        }
        return entries.first(where: { $0.name == name })
    }


    private func run(arguments: [String], wait: Bool) async throws -> ProcessResult? {
        logger.debug("tart \(arguments.joined(separator: " "))")
        return try await processRunner.run(executable: "tart", arguments: arguments, wait: wait, environment: Self.scrubbedEnvironment())
    }
}
