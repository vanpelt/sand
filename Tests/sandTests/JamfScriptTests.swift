import Foundation
import Testing

/// The Jamf scripts in deploy/jamf, run without root: syntax, lint, the
/// installer's pin checks (--verify-only), the generated sudoers rule and the
/// extension attribute's output.
@Suite struct JamfScriptTests {
    static let deploy = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("deploy/jamf")
    static let installer = deploy.appendingPathComponent("install-managed-softnet.sh").path
    static let scripts = ["install-managed-softnet.sh", "uninstall-managed-softnet.sh", "sand-readiness-ea.sh"].map { deploy.appendingPathComponent($0).path }

    struct Output {
        let status: Int32
        let stdout: String
        let stderr: String
    }

    static func run(_ executable: String, _ arguments: [String]) throws -> Output {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let out = Pipe()
        let err = Pipe()
        process.standardOutput = out
        process.standardError = err
        try process.run()
        let stdout = out.fileHandleForReading.readDataToEndOfFile()
        let stderr = err.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return Output(status: process.terminationStatus, stdout: String(decoding: stdout, as: UTF8.self), stderr: String(decoding: stderr, as: UTF8.self))
    }

    static func sha256(_ path: String) throws -> String {
        let output = try run("/usr/bin/shasum", ["-a", "256", path])
        return String(output.stdout.split(separator: " ").first ?? "")
    }

    @Test func scriptsParseAndPassShellcheckWhenInstalled() throws {
        for script in Self.scripts {
            #expect(try Self.run("/bin/bash", ["-n", script]).status == 0, "\(script)")
        }
        let shellcheck = ["/opt/homebrew/bin/shellcheck", "/usr/local/bin/shellcheck"].first { FileManager.default.isExecutableFile(atPath: $0) }
        if let shellcheck {
            let output = try Self.run(shellcheck, Self.scripts)
            #expect(output.status == 0, "\(output.stdout)")
        }
    }

    @Test func installerVerifiesTheBinaryAgainstThePin() throws {
        // Any Mach-O works for --verify-only; nothing is installed and no root is needed.
        let digest = try Self.sha256("/usr/bin/true")
        let ok = try Self.run(Self.installer, ["--verify-only", "--from", "/usr/bin/true", "--sha256", digest])
        #expect(ok.status == 0, "\(ok.stderr)")
        #expect(ok.stdout.contains("nothing installed"))
        let wrong = try Self.run(Self.installer, ["--verify-only", "--from", "/usr/bin/true", "--sha256", String(repeating: "a", count: 64)])
        #expect(wrong.status != 0)
        #expect(wrong.stderr.contains("expected aaaa"))
        // A version with no pinned digest and no --sha256 is refused.
        let unpinned = try Self.run(Self.installer, ["--verify-only", "--from", "/usr/bin/true", "--version", "9.9.9"])
        #expect(unpinned.status != 0)
        #expect(unpinned.stderr.contains("no pinned SHA-256"))
    }

    @Test func installerRejectsARelativeJamfSourcePath() throws {
        let output = try Self.run(Self.installer, ["/", "host", "user", "suid", "relative/softnet"])
        #expect(output.status != 0)
        #expect(output.stderr.contains("absolute path"))
    }

    @Test func generatedSudoersRuleValidates() throws {
        let output = try Self.run(Self.installer, ["--print-sudoers", "--group", "sandrunners"])
        #expect(output.status == 0)
        #expect(output.stdout.contains("%sandrunners ALL=(root) NOPASSWD: /usr/local/libexec/sand/softnet\n"))
        #expect(!output.stdout.contains("SETENV:"))
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("sand-sudoers-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: file) }
        try output.stdout.write(to: file, atomically: true, encoding: .utf8)
        let visudo = try Self.run("/usr/sbin/visudo", ["-cf", file.path])
        #expect(visudo.status == 0, "\(visudo.stdout)\(visudo.stderr)")
    }

    @Test func extensionAttributeAlwaysPrintsOneResult() throws {
        let output = try Self.run("/bin/bash", [Self.deploy.appendingPathComponent("sand-readiness-ea.sh").path])
        #expect(output.status == 0)
        let lines = output.stdout.split(separator: "\n")
        #expect(lines.count == 1)
        let line = String(lines.first ?? "")
        #expect(line.hasPrefix("<result>") && line.hasSuffix("</result>"))
        #expect(["<result>ready;", "<result>ready-hostonly;", "<result>not-ready;"].contains { line.hasPrefix($0) })
    }
}
