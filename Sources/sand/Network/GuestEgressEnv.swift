import Foundation

/// Guest-side proxy settings. These are for usability only: enforcement is
/// the enforcement backend (hostOnly or softnet) plus the host-side proxy, so a tool that
/// ignores them simply fails to connect.
struct GuestEgressEnv: Sendable, Equatable {
    let proxyURL: String
    let noProxy: String
    /// Set when the host's TLS-inspection CA is trusted in the guest
    /// (`tlsInspection: trustHostCA`): point TLS clients at the combined bundle.
    var trustsInspectionCA = false

    static let standard = GuestEgressEnv(
        proxyURL: "http://127.0.0.1:\(NetworkPolicy.guestProxyPort)",
        noProxy: "localhost,127.0.0.1,::1"
    )

    func trustingInspectionCA() -> GuestEgressEnv {
        var copy = self
        copy.trustsInspectionCA = true
        return copy
    }

    var variables: [(String, String)] {
        var variables = [
            ("https_proxy", proxyURL), ("http_proxy", proxyURL),
            ("HTTPS_PROXY", proxyURL), ("HTTP_PROXY", proxyURL),
            ("no_proxy", noProxy), ("NO_PROXY", noProxy),
            // Node 24+ ignores https_proxy unless this is set (usability only).
            ("NODE_USE_ENV_PROXY", "1")
        ]
        if trustsInspectionCA {
            // A combined bundle (guest defaults + inspection CA), never a replacement.
            variables += [
                ("SSL_CERT_FILE", GuestInspectionTrust.bundlePath),
                ("REQUESTS_CA_BUNDLE", GuestInspectionTrust.bundlePath),
                ("CURL_CA_BUNDLE", GuestInspectionTrust.bundlePath),
                ("GIT_SSL_CAINFO", GuestInspectionTrust.bundlePath),
                // Node appends these to its built-in roots.
                ("NODE_EXTRA_CA_CERTS", GuestInspectionTrust.extraPath)
            ]
        }
        return variables
    }

    /// Quotes `NAME=value` for a guest shell. A value starting with `$HOME/`
    /// (only Sand's own fixed CA paths) expands `$HOME` in the guest.
    static func quoteAssignment(_ name: String, _ value: String) -> String {
        let home = "$HOME/"
        guard value.hasPrefix(home) else {
            return GitHubProvisioner.shellQuote("\(name)=\(value)")
        }
        return GitHubProvisioner.shellQuote("\(name)=") + "\"$HOME\"" + GitHubProvisioner.shellQuote("/" + value.dropFirst(home.count))
    }

    /// `env https_proxy=... ...` prefix for a single command.
    var envPrefix: String {
        "env " + variables.map { Self.quoteAssignment($0.0, $0.1) }.joined(separator: " ")
    }

    /// Writes the runner's `.env`, which the runner loads at startup and passes to job steps.
    /// The runner does not expand variables there, so `$HOME` is expanded when writing.
    func runnerDotEnvCommand(directory: String = "~/actions-runner", extra: [(String, String)] = []) -> String {
        Self.dotEnvCommand(variables: variables + extra, directory: directory)
    }

    /// `printf` of quoted `NAME=value` lines into `<directory>/.env` (overwrites).
    static func dotEnvCommand(variables: [(String, String)], directory: String = "~/actions-runner") -> String {
        let lines = variables.map { quoteAssignment($0.0, $0.1) }.joined(separator: " ")
        return "printf '%s\\n' \(lines) > \(directory)/.env"
    }

    /// Exports for login shells (`bash -lc`, zsh), then the macOS system web
    /// proxy for URLSession tools (xcodebuild, SwiftPM) and DNS pointed at
    /// loopback so tools that resolve before proxying fail fast. Best effort:
    /// failures print a WARN line and never fail provisioning.
    var guestSetupCommand: String {
        let exports = variables.map { GitHubProvisioner.shellQuote("export \($0.0)=\($0.1)") }.joined(separator: " ")
        let port = String(NetworkPolicy.guestProxyPort)
        return [
            "printf '%s\\n' \(exports) >> ~/.zshenv",
            // Do not create ~/.bash_profile when only ~/.profile exists: bash would stop reading ~/.profile.
            "if [ -f ~/.bash_profile ] || [ ! -f ~/.profile ]; then f=~/.bash_profile; else f=~/.profile; fi; printf '%s\\n' \(exports) >> \"$f\"",
            "if [ \"$(uname -s)\" = Darwin ]; then networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | sed 's/^\\*//' | while IFS= read -r svc; do "
                + "sudo -n networksetup -setwebproxy \"$svc\" 127.0.0.1 \(port) >/dev/null 2>&1 "
                + "&& sudo -n networksetup -setsecurewebproxy \"$svc\" 127.0.0.1 \(port) >/dev/null 2>&1 "
                + "&& sudo -n networksetup -setproxybypassdomains \"$svc\" localhost 127.0.0.1 >/dev/null 2>&1 "
                + "&& sudo -n networksetup -setdnsservers \"$svc\" 127.0.0.1 >/dev/null 2>&1 "
                + "|| echo \"WARN: could not set the system proxy for network service $svc\"; done; fi",
            "true"
        ].joined(separator: "; ")
    }
}
