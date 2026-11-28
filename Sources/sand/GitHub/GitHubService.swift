import Foundation

protocol URLSessionProtocol: Sendable {
    func data(for request: URLRequest) async throws -> (Data, URLResponse)
}

extension URLSession: URLSessionProtocol {}

enum GitHubServiceError: Error {
    case invalidResponse
    case httpError(status: Int, body: String)
    case repositoryRequired
}

struct GitHubService: Sendable {
    struct InstallationResponse: Decodable {
        let id: Int
    }

    struct AccessTokenResponse: Decodable {
        let token: String
        let expiresAt: String?
    }

    struct RunnerTokenResponse: Decodable {
        let token: String
    }

    struct RunnerRegistrationCredentials: Sendable {
        let runnerToken: String
        let installationToken: String
    }

    struct RunnersResponse: Decodable {
        struct Runner: Decodable, Sendable, Equatable {
            let id: Int
            let name: String
            var status: String?
            var busy: Bool?
        }

        var totalCount: Int?
        let runners: [Runner]
    }


    let auth: GitHubAuthenticating
    let session: URLSessionProtocol
    let organization: String
    let repository: String?
    let baseURL = URL(string: "https://api.github.com")!
    /// Installation tokens are reused until 5 minutes before they expire:
    /// fewer App JWT signings, so fewer Keychain prompts.
    let tokenCache = InstallationTokenCache()

    func runnerRegistrationToken() async throws -> String {
        try await runnerRegistrationCredentials().runnerToken
    }

    func runnerRegistrationCredentials() async throws -> RunnerRegistrationCredentials {
        let installationId = try await installationID()
        let accessToken = try await installationAccessToken(installationId: installationId)
        let tokenResponse: RunnerTokenResponse = try await request(path: registrationTokenPath(), method: "POST", token: accessToken)
        return RunnerRegistrationCredentials(runnerToken: tokenResponse.token, installationToken: accessToken)
    }

    func deleteRunner(named name: String) async throws -> Bool {
        let installationId = try await installationID()
        let accessToken = try await installationAccessToken(installationId: installationId)
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._~"))
        let encodedName = name.addingPercentEncoding(withAllowedCharacters: allowed) ?? name
        let response: RunnersResponse = try await request(path: "\(runnersPath())?name=\(encodedName)", method: "GET", token: accessToken)
        guard let runner = response.runners.first(where: { $0.name == name }) else {
            return false
        }
        _ = try await send(path: "\(runnersPath())/\(runner.id)", method: "DELETE", token: accessToken)
        return true
    }


    private func installationID() async throws -> Int {
        let token = try auth.token(now: Date())
        let response: InstallationResponse = try await request(path: installationPath(), method: "GET", token: token)
        return response.id
    }

    private func installationAccessToken(installationId: Int) async throws -> String {
        if let cached = tokenCache.valid(now: Date()) {
            return cached
        }
        let token = try auth.token(now: Date())
        let response: AccessTokenResponse = try await request(path: "/app/installations/\(installationId)/access_tokens", method: "POST", token: token)
        let expiry = response.expiresAt.flatMap { ISO8601DateFormatter().date(from: $0) } ?? Date().addingTimeInterval(3600)
        tokenCache.store(response.token, expiresAt: expiry)
        return response.token
    }

    /// An installation token for the configured repository or organization.
    func accessToken() async throws -> String {
        if let cached = tokenCache.valid(now: Date()) {
            return cached
        }
        return try await installationAccessToken(installationId: try await installationID())
    }

    private func request<T: Decodable>(path: String, method: String, token: String, body: Data? = nil) async throws -> T {
        let data = try await send(path: path, method: method, token: token, body: body)
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(T.self, from: data)
    }

    private func send(path: String, method: String, token: String, body: Data? = nil) async throws -> Data {
        let (data, status) = try await sendRaw(path: path, method: method, token: token, body: body)
        if !(200...299).contains(status) {
            let body = String(data: data, encoding: .utf8) ?? ""
            throw GitHubServiceError.httpError(status: status, body: body)
        }
        return data
    }

    private func sendRaw(path: String, method: String, token: String, body: Data? = nil) async throws -> (Data, Int) {
        let url = URL(string: path, relativeTo: baseURL)!
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("sand", forHTTPHeaderField: "User-Agent")
        if let body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = body
        }
        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw GitHubServiceError.invalidResponse
        }
        return (data, httpResponse.statusCode)
    }

    private func installationPath() -> String {
        if let repository {
            return "/repos/\(organization)/\(repository)/installation"
        }
        return "/orgs/\(organization)/installation"
    }

    private func registrationTokenPath() -> String {
        if let repository {
            return "/repos/\(organization)/\(repository)/actions/runners/registration-token"
        }
        return "/orgs/\(organization)/actions/runners/registration-token"
    }

    private func runnersPath() -> String {
        if let repository {
            return "/repos/\(organization)/\(repository)/actions/runners"
        }
        return "/orgs/\(organization)/actions/runners"
    }

    // MARK: - Broker (repository scope only)

    private func repositoryPath() throws -> String {
        guard let repository else { throw GitHubServiceError.repositoryRequired }
        return "/repos/\(organization)/\(repository)"
    }

    func repositoryInfo() async throws -> GitHubRepositoryInfo {
        try await request(path: try repositoryPath(), method: "GET", token: try await accessToken())
    }

    /// `POST .../actions/runners/generate-jitconfig`. The returned config is a secret.
    func generateJITConfig(name: String, labels: [String], runnerGroupId: Int, workFolder: String = "_work") async throws -> GitHubJITConfig {
        let body = try JSONSerialization.data(withJSONObject: [
            "name": name, "runner_group_id": runnerGroupId, "labels": labels, "work_folder": workFolder
        ], options: [.sortedKeys])
        return try await request(path: "\(try repositoryPath())/actions/runners/generate-jitconfig", method: "POST", token: try await accessToken(), body: body)
    }

    func runs(status: String) async throws -> [GitHubRun] {
        let response: GitHubRunsResponse = try await request(path: "\(try repositoryPath())/actions/runs?status=\(status)&per_page=100", method: "GET", token: try await accessToken())
        return response.workflowRuns
    }

    /// The run as it was for `attempt` (actor and triggering actor of that attempt).
    func runAttempt(runId: Int, attempt: Int) async throws -> GitHubRun {
        try await request(path: "\(try repositoryPath())/actions/runs/\(runId)/attempts/\(attempt)", method: "GET", token: try await accessToken())
    }

    /// Every job of one run attempt, following pagination.
    func attemptJobs(runId: Int, attempt: Int) async throws -> [GitHubJob] {
        let token = try await accessToken()
        var jobs: [GitHubJob] = []
        var page = 1
        while page <= 50 {
            let response: GitHubJobsResponse = try await request(
                path: "\(try repositoryPath())/actions/runs/\(runId)/attempts/\(attempt)/jobs?per_page=100&page=\(page)",
                method: "GET", token: token
            )
            jobs += response.jobs
            if response.jobs.isEmpty || jobs.count >= response.totalCount {
                break
            }
            page += 1
        }
        return jobs
    }

    func deleteRunner(id: Int) async throws -> DeleteRunnerResult {
        let (data, status) = try await sendRaw(path: "\(try repositoryPath())/actions/runners/\(id)", method: "DELETE", token: try await accessToken())
        switch status {
        case 200...299: return .deleted
        case 404: return .notFound
        case 422: return .busy
        default: throw GitHubServiceError.httpError(status: status, body: String(data: data, encoding: .utf8) ?? "")
        }
    }

    func listRunners() async throws -> [RunnersResponse.Runner] {
        let token = try await accessToken()
        var runners: [RunnersResponse.Runner] = []
        var page = 1
        while page <= 20 {
            let response: RunnersResponse = try await request(path: "\(try repositoryPath())/actions/runners?per_page=100&page=\(page)", method: "GET", token: token)
            runners += response.runners
            if response.runners.isEmpty || runners.count >= (response.totalCount ?? 0) {
                break
            }
            page += 1
        }
        return runners
    }

    func cancelRun(id: Int) async throws {
        _ = try await send(path: "\(try repositoryPath())/actions/runs/\(id)/cancel", method: "POST", token: try await accessToken())
    }
}

enum DeleteRunnerResult: Sendable, Equatable {
    case deleted, busy, notFound
}

final class InstallationTokenCache: @unchecked Sendable {
    private let lock = NSLock()
    private var token: String?
    private var expiresAt = Date.distantPast
    static let margin: TimeInterval = 300

    func valid(now: Date) -> String? {
        lock.withLock { now.addingTimeInterval(Self.margin) < expiresAt ? token : nil }
    }

    func store(_ token: String, expiresAt: Date) {
        lock.withLock {
            self.token = token
            self.expiresAt = expiresAt
        }
    }
}

// MARK: - REST shapes used by the broker (decoded with convertFromSnakeCase)

struct GitHubRepositoryInfo: Codable, Sendable, Equatable {
    struct Owner: Codable, Sendable, Equatable { let login: String; let id: Int }
    let id: Int
    let name: String
    let owner: Owner
}

struct GitHubActor: Codable, Sendable, Equatable {
    let id: Int
    let login: String
    let type: String
}

struct GitHubRepoRef: Codable, Sendable, Equatable {
    let id: Int
}

struct GitHubRun: Codable, Sendable, Equatable {
    struct ReferencedWorkflow: Codable, Sendable, Equatable { let path: String }
    let id: Int
    var runAttempt: Int?
    let event: String
    var status: String?
    let path: String
    var headBranch: String?
    let headSha: String
    let repository: GitHubRepoRef
    var headRepository: GitHubRepoRef?
    var actor: GitHubActor?
    var triggeringActor: GitHubActor?
    var referencedWorkflows: [ReferencedWorkflow]?
}

struct GitHubRunsResponse: Codable, Sendable {
    let totalCount: Int
    let workflowRuns: [GitHubRun]
}

struct GitHubJob: Codable, Sendable, Equatable {
    let id: Int
    let runId: Int
    var runAttempt: Int?
    let status: String
    var name: String?
    var runnerId: Int?
    var runnerName: String?
    var labels: [String]
    var headSha: String?
}

struct GitHubJobsResponse: Codable, Sendable {
    let totalCount: Int
    let jobs: [GitHubJob]
}

struct GitHubJITConfig: Decodable, Sendable {
    struct Runner: Decodable, Sendable {
        struct Label: Decodable, Sendable { let name: String }
        let id: Int
        let name: String
        var labels: [Label]?
        var ephemeral: Bool?
        var runnerGroupId: Int?
    }
    let runner: Runner
    /// SECRET.
    let encodedJitConfig: String
}
