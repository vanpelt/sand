import Foundation

/// `sand.audit.v1` event (`docs/broker-api.md` §5). Built only through
/// `AuditEvent.make`, which enforces the field rules: strings only, at most 32
/// keys, 512 bytes per value, and no secret or free-text keys.
struct AuditEvent: Codable, Sendable, Equatable {
    enum Source: String, Codable, Sendable { case device, broker, relay }
    enum Level: String, Codable, Sendable { case info, warning, error }

    var schema = "sand.audit.v1"
    let eventId: String
    let time: Date
    let source: Source
    let type: String
    let level: Level
    var deviceId: String?
    var allocationId: String?
    var repositoryId: Int?
    var runnerId: Int?
    var runId: Int?
    var runAttempt: Int?
    var jobId: Int?
    var decision: AdmissionVerdict?
    var reasons: [DenyReason]?
    var policyVersion: String?
    var sandVersion: String?
    var fields: [String: String]

    static let maxFields = 32
    static let maxValueBytes = 512

    /// Keys that must never appear in `fields` (secrets and workflow-controlled free text).
    static let forbiddenFieldKeys: Set<String> = [
        "jit_config", "jitconfig", "nonce", "session_token", "oidc_token", "signature",
        "installation_token", "token", "jwt", "app_jwt", "proxy_credentials", "password",
        "github_workflow", "head_ref", "commit_message", "message"
    ]

    static func make(
        type: String,
        source: Source = .device,
        level: Level = .info,
        now: Date = Date(),
        deviceId: String? = nil,
        allocationId: String? = nil,
        repositoryId: Int? = nil,
        runnerId: Int? = nil,
        runId: Int? = nil,
        runAttempt: Int? = nil,
        jobId: Int? = nil,
        decision: AdmissionVerdict? = nil,
        reasons: [DenyReason]? = nil,
        policyVersion: String? = nil,
        fields: [String: String] = [:],
        secrets: [String] = []
    ) -> AuditEvent {
        AuditEvent(
            eventId: UUID().uuidString.lowercased(),
            time: Date(timeIntervalSince1970: now.timeIntervalSince1970.rounded(.down)),
            source: source, type: type, level: level,
            deviceId: deviceId, allocationId: allocationId, repositoryId: repositoryId, runnerId: runnerId,
            runId: runId, runAttempt: runAttempt, jobId: jobId, decision: decision, reasons: reasons,
            policyVersion: policyVersion, sandVersion: SandVersion.current,
            fields: sanitize(fields, secrets: secrets)
        )
    }

    static func sanitize(_ fields: [String: String], secrets: [String] = []) -> [String: String] {
        var result: [String: String] = [:]
        for key in fields.keys.sorted() {
            guard result.count < maxFields else { break }
            let normalized = key.lowercased()
            guard !forbiddenFieldKeys.contains(normalized), !normalized.contains("token"), !normalized.contains("secret") else { continue }
            var value = Runner.redact(fields[key] ?? "", secrets: secrets)
            if value.utf8.count > maxValueBytes {
                value = String(decoding: Array(value.utf8.prefix(maxValueBytes)), as: UTF8.self)
                while value.utf8.count > maxValueBytes { value.removeLast() }
            }
            result[key] = value
        }
        return result
    }

    func jsonLine() -> String {
        let data = (try? BrokerJSON.encoder().encode(self)) ?? Data()
        return String(decoding: data, as: UTF8.self)
    }
}

enum SandVersion {
    static let current = "0.9.0-dev"
}

/// Sink for device-side admission audit events: a log line plus, when the run
/// has a log file, the `*.audit.jsonl` next to it (shared with network audit).
struct AdmissionAudit: Sendable {
    let emitEvent: @Sendable (AuditEvent) -> Void

    static let silent = AdmissionAudit { _ in }

    static func logging(_ logger: Logger?, file: AuditFileSink? = nil) -> AdmissionAudit {
        AdmissionAudit { event in
            let level: LogLevel = event.level == .error ? .error : (event.level == .warning ? .warning : .info)
            let line = event.jsonLine()
            logger?.log(level, "audit \(line)")
            file?.writeLine(line)
        }
    }

    func emit(_ event: AuditEvent) {
        emitEvent(event)
    }
}
