import Foundation

enum AdmissionHookError: Error, Equatable, CustomStringConvertible {
    case invalidAllocationId
    case invalidNonce
    case invalidCommand

    var description: String {
        switch self {
        case .invalidAllocationId: return "allocation id does not match ^alc_[0-9A-Z]{26}$"
        case .invalidNonce: return "allocation nonce is not 32 bytes of base64url"
        case .invalidCommand: return "hook kill/block command contains a quote or newline"
        }
    }
}

/// The guest `job-started` hook (ADR 0001 §3, steps 3-7). The runner runs `.sh`
/// hooks with `bash -e`; the script switches to `set +e` and never exits
/// non-zero, because a failing hook does not stop `pre:`, `post:` or
/// `always()` steps (E2). Deny kills the runner and blocks; the host destroys
/// the VM. Stdout carries fixed strings only.
enum AdmissionHook {
    static let guestDirectory = "$HOME/.sand/hooks"
    static let guestPath = "$HOME/.sand/hooks/job-started.sh"
    static let admittedMarker = "sand: job admitted"
    static let deniedMarker = "sand: job not admitted; stopping runner"
    static let killCommand = "/usr/bin/pkill -KILL -f 'bin/Runner.Listener' || true; /usr/bin/pkill -KILL -f 'bin/Runner.Worker' || true"
    static let blockCommand = "/bin/sleep 3600"

    static let template = #"""
    #!/bin/bash
    # Sand job-started admission gate. Generated per allocation by Sand; do not edit.
    # Contract: exit 0 only on an explicit "allow". Every other path kills the
    # runner and blocks forever; the host destroys the VM. Never exit non-zero:
    # a failed hook step does not stop pre/post/always() steps (ADR 0001, E2).
    # Prints fixed strings only (stdout is parsed for workflow commands).
    set +e
    set +x
    SAND_ALLOCATION_ID='@@ALLOCATION_ID@@'
    SAND_NONCE='@@NONCE@@'
    SAND_RELAY='http://127.0.0.1:@@RELAY_PORT@@/v1/admission'

    sand_deny() {
      echo "sand: job not admitted; stopping runner"
      @@KILL_COMMAND@@
      while :; do @@BLOCK_COMMAND@@; done
    }

    num='^[1-9][0-9]{0,18}$'
    [[ "${GITHUB_RUN_ID:-}" =~ $num ]] || sand_deny
    [[ "${GITHUB_RUN_ATTEMPT:-}" =~ $num ]] || sand_deny
    [[ "${GITHUB_REPOSITORY_ID:-}" =~ $num ]] || sand_deny
    [[ "${RUNNER_NAME:-}" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || sand_deny
    sand_job="${GITHUB_JOB:-}"
    [[ "$sand_job" =~ ^[A-Za-z_][A-Za-z0-9_-]{0,99}$ ]] || sand_job=""

    sand_body=$(printf '{"allocation_id":"%s","nonce":"%s","hints":{"repository_id":%s,"run_id":%s,"run_attempt":%s,"runner_name":"%s","job_key":"%s"}}' \
      "$SAND_ALLOCATION_ID" "$SAND_NONCE" "$GITHUB_REPOSITORY_ID" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$RUNNER_NAME" "$sand_job")

    sand_verdict=$(/usr/bin/curl -q --silent --proto '=http' --noproxy '*' --max-time @@CURL_MAX_TIME@@ --connect-timeout 5 \
      -H 'Content-Type: application/json' --data-binary "$sand_body" "$SAND_RELAY" 2>/dev/null)

    if [ "$sand_verdict" = "allow" ]; then
      echo "sand: job admitted"
      exit 0
    fi
    sand_deny

    """#

    /// Fills in the template. The id and nonce are checked against their fixed
    /// formats, so they can never break out of the single-quoted assignments.
    static func script(
        allocationId: String,
        nonce: String,
        relayPort: Int = NetworkPolicy.guestAdmissionPort,
        killCommand: String = killCommand,
        blockCommand: String = blockCommand
    ) throws -> String {
        guard BrokerID.matches(allocationId, prefix: "alc") else { throw AdmissionHookError.invalidAllocationId }
        guard Base64URL.isToken32(nonce) else { throw AdmissionHookError.invalidNonce }
        guard !killCommand.contains("\n"), !blockCommand.contains("\n"), !blockCommand.contains("'") else {
            throw AdmissionHookError.invalidCommand
        }
        return template
            .replacingOccurrences(of: "@@ALLOCATION_ID@@", with: allocationId)
            .replacingOccurrences(of: "@@NONCE@@", with: nonce)
            .replacingOccurrences(of: "@@RELAY_PORT@@", with: String(relayPort))
            .replacingOccurrences(of: "@@CURL_MAX_TIME@@", with: String(AdmissionTimeouts.hookCurlSeconds))
            .replacingOccurrences(of: "@@KILL_COMMAND@@", with: killCommand)
            .replacingOccurrences(of: "@@BLOCK_COMMAND@@", with: blockCommand)
    }

    /// Guest commands that install the hook read-only, outside `actions-runner`.
    /// The script (it holds the nonce) travels on the SSH session's stdin, never
    /// in a process argument on the host or in the guest.
    static func installCommands(script: String) -> [GuestCommand] {
        [
            GuestCommand("mkdir -p \"$HOME/.sand/hooks\" && chmod 0755 \"$HOME/.sand/hooks\" && rm -f \"$HOME/.sand/hooks/job-started.sh\""),
            GuestCommand(
                "umask 077 && /bin/cat > \"$HOME/.sand/hooks/job-started.sh\" && chmod 0555 \"$HOME/.sand/hooks/job-started.sh\" && chmod 0555 \"$HOME/.sand/hooks\"",
                stdin: script
            )
        ]
    }
}

/// One guest command, optionally with data for its stdin (secrets travel
/// there rather than in `ssh` arguments, which `ps` shows to every local user).
struct GuestCommand: Sendable, Equatable {
    let command: String
    var stdin: String?

    init(_ command: String, stdin: String? = nil) {
        self.command = command
        self.stdin = stdin
    }
}
