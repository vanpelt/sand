import Darwin
import Foundation

/// The softnet binary tart will exec for one VM.
///
/// tart 2.42 finds `softnet` by walking its own PATH, so sand launches tart with
/// `directory` as the first PATH entry: tart then execs exactly `resolved`.
struct SoftnetLocation: Sendable, Equatable {
    enum Source: String, Sendable {
        /// `vm.run.network.softnetPath`.
        case config
        /// The managed install location (`/usr/local/libexec/sand/softnet`).
        case managed
        /// The first `softnet` on sand's PATH (fallback).
        case path
    }

    /// As configured or discovered (may be a symlink).
    let path: String
    /// realpath(3) of `path`: what tart execs and what every check inspects.
    let resolved: String
    let source: Source

    var directory: String { (resolved as NSString).deletingLastPathComponent }

    /// `managed /usr/local/libexec/sand/softnet`
    var summary: String {
        resolved == path ? "\(source.rawValue) \(path)" : "\(source.rawValue) \(path) -> \(resolved)"
    }
}

/// Where sand looks for softnet, in order: `softnetPath` from the config, the
/// managed install location, then PATH.
///
/// The managed location is `/usr/local/libexec/sand`: `/usr/local` and
/// `/usr/local/libexec` ship root:wheel 0755 on macOS (Intel and Apple
/// Silicon), it is outside SIP, it is not on anyone's PATH (so a setuid binary
/// there is not picked up by other tools), `libexec` is the conventional home
/// for helper binaries, and unlike `/opt/homebrew` or `/usr/local/bin` on Intel
/// Homebrew installs it is never handed to the user by a package manager.
enum SoftnetDiscovery {
    static let managedDirectory = "/usr/local/libexec/sand"
    static let managedPath = managedDirectory + "/softnet"
    /// Written by `deploy/jamf/install-managed-softnet.sh`; `shasum -a 256` format.
    static let manifestName = "softnet.sha256"

    enum Outcome: Sendable, Equatable {
        case found(SoftnetLocation)
        case missing(String)
    }

    static func locate(configuredPath: String?, fileSystem: PreflightFileSystem) -> Outcome {
        if let configuredPath {
            // An explicit path is authoritative: never fall back from it.
            guard fileSystem.fileExists(configuredPath) else {
                return .missing("vm.run.network.softnetPath \(configuredPath) does not exist")
            }
            return .found(SoftnetLocation(path: configuredPath, resolved: fileSystem.realpath(configuredPath), source: .config))
        }
        if fileSystem.fileExists(managedPath) {
            // Present means managed: an unsafe managed install fails instead of
            // silently trying whatever softnet is on PATH.
            return .found(SoftnetLocation(path: managedPath, resolved: fileSystem.realpath(managedPath), source: .managed))
        }
        if let path = fileSystem.which("softnet") {
            return .found(SoftnetLocation(path: path, resolved: fileSystem.realpath(path), source: .path))
        }
        return .missing("softnet not found at \(managedPath) or in PATH")
    }

    /// `/usr/local/libexec/sand/softnet` -> [`/usr/local/libexec/sand`, `/usr/local/libexec`, `/usr/local`, `/usr`, `/`]
    static func ancestors(of path: String) -> [String] {
        var result: [String] = []
        var current = (path as NSString).deletingLastPathComponent
        while true {
            result.append(current.isEmpty ? "/" : current)
            if current == "/" || current.isEmpty { break }
            current = (current as NSString).deletingLastPathComponent
        }
        return result
    }

    /// Why a softnet that runs as root (setuid, or via `sudo -n`) at `location`
    /// could be replaced by a non-root user; empty when it cannot.
    ///
    /// Strict: the binary and every directory up to `/` must be owned by root
    /// and not writable by group or other (a root-owned sticky directory such
    /// as `/private/tmp` is tolerated: nobody else can rename root's entry).
    /// Symlinks are resolved first, so a symlink anywhere in the configured
    /// path is judged by where it points, and tart is pointed at the resolved
    /// directory, never at the symlink.
    static func pathProblems(_ location: SoftnetLocation, fileSystem: PreflightFileSystem) -> [String] {
        var problems: [String] = []
        let resolved = location.resolved
        guard resolved.hasPrefix("/") else {
            return ["\(resolved) is not an absolute path"]
        }
        if (resolved as NSString).lastPathComponent != "softnet" {
            // tart looks the binary up by the name `softnet`.
            problems.append("\(resolved) is not named softnet (tart execs `softnet` from PATH)")
        }
        let groupOrOtherWrite = UInt16(S_IWGRP | S_IWOTH)
        guard let binary = fileSystem.ownerAndMode(resolved) else {
            return problems + ["cannot stat \(resolved)"]
        }
        if binary.uid != 0 {
            problems.append("\(resolved) is owned by uid \(binary.uid), not root")
        }
        if binary.mode & groupOrOtherWrite != 0 {
            problems.append("\(resolved) is writable by group or other (mode \(String(binary.mode & 0o7777, radix: 8)))")
        }
        for directory in ancestors(of: resolved) {
            guard let info = fileSystem.ownerAndMode(directory) else {
                problems.append("cannot stat \(directory)")
                continue
            }
            if info.uid != 0 {
                problems.append("\(directory) is owned by uid \(info.uid), not root")
            }
            let sticky = info.mode & UInt16(S_ISVTX) != 0
            if info.mode & groupOrOtherWrite != 0, !(sticky && info.uid == 0) {
                problems.append("\(directory) is writable by group or other (mode \(String(info.mode & 0o7777, radix: 8)))")
            }
        }
        return problems
    }

    static func isSetuidRoot(_ resolved: String, fileSystem: PreflightFileSystem) -> Bool {
        guard let info = fileSystem.ownerAndMode(resolved) else { return false }
        return info.uid == 0 && info.mode & UInt16(S_ISUID) != 0
    }

    /// The first token of a `shasum -a 256` line, lowercased, if it is 64 hex digits.
    static func parseManifest(_ text: String) -> String? {
        guard let token = text.split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "\n" }).first else { return nil }
        let digest = token.lowercased()
        return isSHA256(digest) ? digest : nil
    }

    static func isSHA256(_ value: String) -> Bool {
        value.count == 64 && value.allSatisfy { $0.isHexDigit && $0.isASCII }
    }
}
