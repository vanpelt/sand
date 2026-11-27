import Foundation

struct NetworkAuditEvent: Sendable, Equatable {
    let name: String
    let level: LogLevel
    let fields: [String: String]

    /// `network.connect decision=deny host=example.com port=443 reason=not-allowlisted`
    var line: String {
        ([name] + fields.keys.sorted().map { "\($0)=\(Self.sanitize(fields[$0] ?? ""))" }).joined(separator: " ")
    }

    static func sanitize(_ value: String) -> String {
        let cleaned = value.map { character -> Character in
            character.isWhitespace || character == "=" || !character.isASCII ? "_" : character
        }
        return String(cleaned.prefix(300))
    }
}

/// Appends audit events as JSON lines (one object per line).
final class AuditFileSink: @unchecked Sendable {
    private let handle: FileHandle
    private let lock = NSLock()
    private let formatter: ISO8601DateFormatter

    init(path: String) throws {
        let expanded = Config.expandPath(path)
        if !FileManager.default.fileExists(atPath: expanded) {
            FileManager.default.createFile(atPath: expanded, contents: nil, attributes: [.posixPermissions: 0o600])
        }
        guard let handle = FileHandle(forWritingAtPath: expanded) else {
            throw LogFileError.openFailed("Failed to open audit file at \(expanded)")
        }
        try handle.seekToEnd()
        self.handle = handle
        formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    }

    /// `/var/log/sand.log` -> `/var/log/sand.network.jsonl`
    static func path(nextTo logFile: String) -> String {
        let url = URL(fileURLWithPath: Config.expandPath(logFile))
        let base = url.deletingPathExtension().lastPathComponent
        return url.deletingLastPathComponent().appendingPathComponent("\(base).network.jsonl").path
    }

    func write(_ event: NetworkAuditEvent) {
        var object = event.fields
        object["event"] = event.name
        object["level"] = event.level.rawValue
        lock.withLock {
            object["ts"] = formatter.string(from: Date())
            guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) else { return }
            handle.write(data + Data("\n".utf8))
        }
    }
}

/// Structured, redacted network audit events. Fields never carry tokens,
/// request paths (CONNECT has none) or user paths; host addresses are named by
/// interface rather than IP where they appear.
struct NetworkAudit: Sendable {
    let logger: Logger?
    let file: AuditFileSink?
    let observer: (@Sendable (NetworkAuditEvent) -> Void)?

    init(logger: Logger?, file: AuditFileSink? = nil, observer: (@Sendable (NetworkAuditEvent) -> Void)? = nil) {
        self.logger = logger
        self.file = file
        self.observer = observer
    }

    static let silent = NetworkAudit(logger: nil)

    func emit(_ name: String, level: LogLevel = .info, _ fields: [String: String] = [:]) {
        let event = NetworkAuditEvent(name: name, level: level, fields: fields)
        logger?.log(level, event.line)
        file?.write(event)
        observer?(event)
    }
}

/// Collects events in tests.
final class AuditRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [NetworkAuditEvent] = []

    var events: [NetworkAuditEvent] {
        lock.withLock { storage }
    }

    var audit: NetworkAudit {
        NetworkAudit(logger: nil) { [self] event in
            lock.withLock { storage.append(event) }
        }
    }
}
