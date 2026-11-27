import Foundation

/// Guest-side proxy settings. These are for usability only: enforcement is
/// softnet deny-all on the host plus the host-side proxy, so a tool that
/// ignores them simply fails to connect.
struct GuestEgressEnv: Sendable, Equatable {
    let proxyURL: String
    let noProxy: String

    static let standard = GuestEgressEnv(
        proxyURL: "http://127.0.0.1:\(NetworkPolicy.guestProxyPort)",
        noProxy: "localhost,127.0.0.1,::1"
    )

    var variables: [(String, String)] {
        [
            ("https_proxy", proxyURL), ("http_proxy", proxyURL),
            ("HTTPS_PROXY", proxyURL), ("HTTP_PROXY", proxyURL),
            ("no_proxy", noProxy), ("NO_PROXY", noProxy)
        ]
    }

    /// `env https_proxy=... ...` prefix for a single command.
    var envPrefix: String {
        "env " + variables.map { "\($0.0)=\(GitHubProvisioner.shellQuote($0.1))" }.joined(separator: " ")
    }

    /// Writes the runner's `.env`, which the runner loads at startup and passes to job steps.
    func runnerDotEnvCommand(directory: String = "~/actions-runner") -> String {
        let lines = variables.map { GitHubProvisioner.shellQuote("\($0.0)=\($0.1)") }.joined(separator: " ")
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
