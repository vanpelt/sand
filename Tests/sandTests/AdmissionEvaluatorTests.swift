import Foundation
import Testing
@testable import sand

@Suite struct AdmissionEvaluatorTests {
    private func evaluate(run: GitHubRun = Spike.run(), jobs: [GitHubJob] = [Spike.job()], hints: AdmissionHints = Spike.hints(), policy: AdmissionPolicy = Spike.policy, owner: Int = Spike.ownerId) -> AdmissionEvaluator.Result {
        AdmissionEvaluator.evaluate(allocation: Spike.facts, hints: hints, run: run, jobs: jobs, policy: policy, ownerId: owner)
    }

    @Test func allowsAnOwnerPush() {
        let result = evaluate()
        #expect(result.decision == .allow)
        #expect(result.reasons.isEmpty)
        #expect(result.job?.id == Spike.jobId)
        #expect(result.job?.workflowPath == ".github/workflows/self-hosted-smoke.yml")
    }

    @Test func allowsAnOwnerRerunAttempt2() {
        let result = evaluate(run: Spike.run(attempt: 2), jobs: [Spike.job(id: 140_862_368_530, attempt: 2)], hints: Spike.hints(attempt: 2))
        #expect(result.decision == .allow)
        #expect(result.job?.runAttempt == 2)
    }

    @Test func allowsWorkflowDispatch() {
        #expect(evaluate(run: Spike.run(event: "workflow_dispatch", branch: "main")).decision == .allow)
    }

    struct Case: Sendable, CustomStringConvertible {
        let name: String
        let run: GitHubRun
        let jobs: [GitHubJob]
        let hints: AdmissionHints
        let expected: DenyReason
        var description: String { name }

        init(_ name: String, run: GitHubRun = Spike.run(), jobs: [GitHubJob] = [Spike.job()], hints: AdmissionHints = Spike.hints(), _ expected: DenyReason) {
            self.name = name
            self.run = run
            self.jobs = jobs
            self.hints = hints
            self.expected = expected
        }
    }

    static let denyCases: [Case] = [
        Case("fork head", run: Spike.run(headRepositoryId: 999), .forkHead),
        Case("missing head repository", run: Spike.run(headRepositoryId: nil), .forkHead),
        Case("pull_request", run: Spike.run(event: "pull_request"), .eventNotAllowed),
        Case("schedule", run: Spike.run(event: "schedule"), .eventNotAllowed),
        Case("merge_group", run: Spike.run(event: "merge_group"), .eventNotAllowed),
        Case("workflow_run", run: Spike.run(event: "workflow_run"), .eventNotAllowed),
        Case("bot actor", run: Spike.run(actor: GitHubActor(id: 17, login: "x[bot]", type: "Bot")), .actorNotUser),
        Case("actor not owner", run: Spike.run(actor: GitHubActor(id: 42, login: "other", type: "User")), .actorNotOwner),
        Case("triggering actor not owner", run: Spike.run(triggeringActor: GitHubActor(id: 42, login: "other", type: "User")), .triggeringActorNotOwner),
        Case("workflow not allowed", run: Spike.run(path: ".github/workflows/spike-decoy.yml"), .workflowNotAllowed),
        Case("reusable workflow", run: Spike.run(referenced: ["org/repo/.github/workflows/r.yml@main"]), .reusableWorkflowNotAllowed),
        Case("ref not allowed", run: Spike.run(branch: "spike/job-admission"), .refNotAllowed),
        Case("glob needs a suffix", run: Spike.run(branch: "feature/"), .refNotAllowed),
        Case("glob is a prefix match only", run: Spike.run(branch: "featurex/a"), .refNotAllowed),
        Case("labels not a subset", jobs: [Spike.job(labels: ["self-hosted", "sand", "gpu"])], .labelsMismatch),
        Case("no job for our runner", jobs: [Spike.job(runnerId: 7)], .jobNotFoundForRunner),
        Case("no jobs at all", jobs: [], .jobNotFoundForRunner),
        Case("two jobs for our runner", jobs: [Spike.job(), Spike.job(id: 2)], .multipleJobsForRunner),
        Case("job queued", jobs: [Spike.job(status: "queued")], .jobNotInProgress),
        Case("runner name mismatch", jobs: [Spike.job(runnerName: "other")], .runnerNameMismatch),
        Case("hint repository mismatch", hints: Spike.hints(repositoryId: 5), .repositoryMismatch),
    ]

    @Test(arguments: denyCases)
    func deniesEachReason(_ testCase: Case) {
        let result = evaluate(run: testCase.run, jobs: testCase.jobs, hints: testCase.hints)
        #expect(result.decision == .deny)
        #expect(result.reasons.contains(testCase.expected), "\(testCase.name): \(result.reasons)")
    }

    @Test func featureGlobMatchesNestedBranches() {
        #expect(Spike.policy.branchAllowed("feature/job-admission"))
        #expect(Spike.policy.branchAllowed("feature/a/b"))
        #expect(Spike.policy.branchAllowed("main"))
        #expect(!Spike.policy.branchAllowed("mainline"))
        #expect(!Spike.policy.branchAllowed(nil))
    }

    @Test func reportsSeveralReasonsTogether() {
        let other = GitHubActor(id: 42, login: "other", type: "User")
        let result = evaluate(run: Spike.run(event: "pull_request", path: ".github/workflows/spike-decoy.yml", actor: other, triggeringActor: other))
        #expect(result.decision == .deny)
        #expect(Set(result.reasons).isSuperset(of: [.eventNotAllowed, .workflowNotAllowed, .actorNotOwner, .triggeringActorNotOwner]))
        #expect(result.job?.id == Spike.jobId, "the identified job is reported with a deny")
    }

    @Test func runLevelReasonsBackTheDemandCheck() {
        #expect(AdmissionEvaluator.runReasons(run: Spike.run(), policy: Spike.policy, ownerId: Spike.ownerId, repositoryId: Spike.repositoryId).isEmpty)
        #expect(AdmissionEvaluator.runReasons(run: Spike.run(event: "schedule"), policy: Spike.policy, ownerId: Spike.ownerId, repositoryId: Spike.repositoryId) == [.eventNotAllowed])
    }
}
