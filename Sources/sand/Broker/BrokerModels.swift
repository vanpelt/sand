import Foundation

/// Wire types for the Sand broker API v1 (`docs/broker-api.md`,
/// `docs/broker/openapi.yaml`). Keys are snake_case on the wire; every coder
/// comes from `BrokerJSON` so Swift names stay camelCase.
enum BrokerJSON {
    static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }

    static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }
}

/// Every reason code the broker can deny with. The raw values are the contract.
enum DenyReason: String, Codable, Sendable, CaseIterable, Hashable {
    case allocationState = "allocation_state"
    case allocationExpired = "allocation_expired"
    case nonceMismatch = "nonce_mismatch"
    case alreadyAdmitted = "already_admitted"
    case hintInvalid = "hint_invalid"
    case repositoryMismatch = "repository_mismatch"
    case jobNotFoundForRunner = "job_not_found_for_runner"
    case multipleJobsForRunner = "multiple_jobs_for_runner"
    case jobNotInProgress = "job_not_in_progress"
    case runnerNameMismatch = "runner_name_mismatch"
    case forkHead = "fork_head"
    case eventNotAllowed = "event_not_allowed"
    case actorNotUser = "actor_not_user"
    case actorNotOwner = "actor_not_owner"
    case triggeringActorNotOwner = "triggering_actor_not_owner"
    case workflowNotAllowed = "workflow_not_allowed"
    case reusableWorkflowNotAllowed = "reusable_workflow_not_allowed"
    case refNotAllowed = "ref_not_allowed"
    case labelsMismatch = "labels_mismatch"
    case oidcRequired = "oidc_required"
    case oidcInvalid = "oidc_invalid"
    case oidcClaimMismatch = "oidc_claim_mismatch"
    case oidcUnsupported = "oidc_unsupported"
    case circuitOpen = "circuit_open"
    case githubUnavailable = "github_unavailable"
    case admissionTimeout = "admission_timeout"
}

enum AllocationState: String, Codable, Sendable {
    case requested, registered, assigned, admitted, denied, expired, failed, released, cleaning, closed

    /// States that still own a runner registration and block a new allocation.
    var isOutstanding: Bool {
        self == .registered || self == .assigned || self == .admitted
    }
}

enum AdmissionVerdict: String, Codable, Sendable {
    case allow, deny
}

enum ReleaseReason: String, Codable, Sendable {
    case completed, denied
    case vmFailed = "vm_failed"
    case verifierKill = "verifier_kill"
    case shutdown, expired, unused
}

// MARK: - Device sessions

struct ChallengeRequest: Codable, Sendable, Equatable {
    let deviceId: String
}

struct BrokerChallenge: Codable, Sendable, Equatable {
    let challengeId: String
    let challenge: String
    let expiresAt: Date
}

struct SessionRequest: Codable, Sendable, Equatable {
    let deviceId: String
    let keyId: String
    let challengeId: String
    let signature: String
}

struct BrokerOwner: Codable, Sendable, Equatable {
    let githubUserId: Int
    let githubLogin: String
}

struct BrokerSession: Codable, Sendable, Equatable {
    let sessionToken: String
    let expiresAt: Date
    let deviceId: String
    let owner: BrokerOwner
    let policyVersion: String
}

// MARK: - Allocations

struct RepositoryName: Codable, Sendable, Equatable {
    let owner: String
    let name: String
}

struct AllocationRequest: Codable, Sendable, Equatable {
    struct SandInfo: Codable, Sendable, Equatable {
        let version: String
        let networkPolicyHash: String?
        let vmName: String
    }

    struct Capabilities: Codable, Sendable, Equatable {
        var admissionHook = true
        var assignmentVerifier = true
        var oidc = false
    }

    let repository: RepositoryName
    let runnerNamePrefix: String
    let sand: SandInfo
    var capabilities = Capabilities()
}

struct BrokerRepository: Codable, Sendable, Equatable {
    let id: Int
    let owner: String
    let name: String
}

struct BrokerRunner: Codable, Sendable, Equatable {
    let id: Int
    let name: String
    var labels: [String]?
    var runnerGroupId: Int?
    var ephemeral: Bool?
}

struct AdmissionSettings: Codable, Sendable, Equatable {
    let deadlineSeconds: Int
    let requireOidc: Bool
    let oidcAudience: String
}

struct Allocation: Codable, Sendable, Equatable {
    let allocationId: String
    let state: AllocationState
    let nonce: String
    let createdAt: Date
    let expiresAt: Date
    let repository: BrokerRepository
    let runner: BrokerRunner
    /// SECRET. Present only in the first `201`.
    var jitConfig: String?
    let admission: AdmissionSettings
    let policyVersion: String
}

struct JobRef: Codable, Sendable, Equatable {
    let id: Int
    let runId: Int
    let runAttempt: Int
    var status: String?
    var observedAt: Date?
}

struct AllocationStatus: Codable, Sendable, Equatable {
    let allocationId: String
    let state: AllocationState
    let expiresAt: Date
    let runner: BrokerRunner
    var observedJob: JobRef?
    var admittedJob: JobRef?
    var decision: AdmissionVerdict?
}

// MARK: - Admissions

struct AdmissionHints: Codable, Sendable, Equatable {
    let repositoryId: Int
    let runId: Int
    let runAttempt: Int
    let runnerName: String
    let jobKey: String

    static let runnerNamePattern = #"^[A-Za-z0-9._-]{1,64}$"#
    static let jobKeyPattern = #"^[A-Za-z_][A-Za-z0-9_-]{0,99}$"#

    var isWellFormed: Bool {
        repositoryId > 0 && runId > 0 && runAttempt > 0
            && runnerName.range(of: Self.runnerNamePattern, options: .regularExpression) != nil
            && (jobKey.isEmpty || jobKey.range(of: Self.jobKeyPattern, options: .regularExpression) != nil)
    }
}

struct AdmissionRequest: Codable, Sendable, Equatable {
    struct Relay: Codable, Sendable, Equatable {
        let receivedAt: Date
        let vmName: String
    }

    let nonce: String
    let hints: AdmissionHints
    var oidcToken: String?
    var relay: Relay?
}

struct AdmissionJob: Codable, Sendable, Equatable {
    let id: Int
    let runId: Int
    let runAttempt: Int
    var workflowPath: String?
    var headSha: String?
    var headBranch: String?
    var event: String?
    var actorId: Int?
    var triggeringActorId: Int?
    var labels: [String]?
}

struct AdmissionDecision: Codable, Sendable, Equatable {
    let admissionId: String
    let decision: AdmissionVerdict
    let reasons: [DenyReason]
    var job: AdmissionJob?
    let policyVersion: String
    let decidedAt: Date
}

// MARK: - Release, health, errors

struct ReleaseRequest: Codable, Sendable, Equatable {
    let reason: ReleaseReason
    var jobId: Int?
    var detail: String?
}

struct ReleaseResult: Codable, Sendable, Equatable {
    let state: AllocationState
    let runnerDeleted: Bool
    var nextAttemptAt: Date?
}

struct BrokerHealth: Codable, Sendable, Equatable {
    let status: String
    let version: String
    let policyVersion: String
}

struct AuditBatch: Codable, Sendable {
    let events: [AuditEvent]
}

struct AuditAccepted: Codable, Sendable, Equatable {
    let accepted: Int
}

struct BrokerErrorBody: Codable, Sendable, Equatable {
    struct Detail: Codable, Sendable, Equatable {
        let code: String
        let message: String
        var retryAfterSeconds: Int?
    }

    let error: Detail
    var requestId: String?
}

/// Broker-style identifiers: a prefix plus 26 characters of `[0-9A-Z]`
/// (Crockford base32, as in a ULID), from a CSPRNG.
enum BrokerID {
    static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    static func make(_ prefix: String, random: (Int) -> [UInt8] = BrokerRandom.bytes) -> String {
        let bytes = random(26)
        return prefix + "_" + String(bytes.map { alphabet[Int($0) % alphabet.count] })
    }

    static func matches(_ value: String, prefix: String) -> Bool {
        value.range(of: "^\(prefix)_[0-9A-Z]{26}$", options: .regularExpression) != nil
    }
}

enum BrokerRandom {
    static func bytes(_ count: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        precondition(status == errSecSuccess, "SecRandomCopyBytes failed")
        return bytes
    }
}

enum Base64URL {
    static func encode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func decode(_ string: String) -> Data? {
        guard string.range(of: "^[A-Za-z0-9_-]*$", options: .regularExpression) != nil else { return nil }
        var base64 = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64 += "=" }
        return Data(base64Encoded: base64)
    }

    /// A 32-byte value in unpadded base64url is exactly 43 characters.
    static func isToken32(_ value: String) -> Bool {
        value.range(of: "^[A-Za-z0-9_-]{43}$", options: .regularExpression) != nil
    }
}

/// Constant-time comparison for nonces and tokens.
func constantTimeEquals(_ lhs: String, _ rhs: String) -> Bool {
    let a = Array(lhs.utf8), b = Array(rhs.utf8)
    var diff = UInt8(a.count == b.count ? 0 : 1)
    for index in 0..<max(a.count, b.count) {
        let x = index < a.count ? a[index] : 0
        let y = index < b.count ? b[index] : 0
        diff |= x ^ y
    }
    return diff == 0
}
