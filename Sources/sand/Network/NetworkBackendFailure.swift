import Foundation

/// Classifies why `tart run` died before the VM was reachable under an
/// isolated policy. Any such exit counts as an enforcement failure; the
/// reason only makes the audit line and the message actionable.
enum NetworkBackendFailure {
    static func classify(stderr: String, backend: EnforcementBackend?) -> String {
        let text = stderr.lowercased()
        if text.contains("softnet process terminated prematurely") {
            return "softnet-terminated"
        }
        if text.contains("softnet") && (text.contains("sudo") || text.contains("permission") || text.contains("not permitted") || text.contains("root")) {
            return "softnet-privilege"
        }
        if text.contains("softnet") {
            return "softnet-failed"
        }
        if text.contains("net-host") || text.contains("host-only") || text.contains("vmnet") || (backend == .hostOnly && text.contains("network")) {
            return "host-network-failed"
        }
        return "tart-exited-early"
    }

    /// The last meaningful stderr line(s), short enough for an audit field.
    static func summary(_ stderr: String) -> String {
        let lines = stderr.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        // Prefer tart's own error lines (RuntimeFailed(...), Error: ...) over wrapper noise.
        let errors = lines.filter { line in ["runtimefailed", "error", "terminated", "failed"].contains { line.lowercased().contains($0) } }
        let text = (errors.isEmpty ? Array(lines.suffix(3)) : Array(errors.suffix(2))).joined(separator: " | ")
        return text.isEmpty ? "no stderr" : String(text.prefix(280))
    }
}
