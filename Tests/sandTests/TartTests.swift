import XCTest
@testable import sand

final class MockProcessRunner: ProcessRunning, @unchecked Sendable {
    struct Call: Equatable {
        let executable: String
        let arguments: [String]
        let wait: Bool
    }

    var calls: [Call] = []
    var results: [ProcessResult?] = []
    var startCalls: [Call] = []
    var startResults: [Result<ProcessResult, Error>] = []

    func run(executable: String, arguments: [String], wait: Bool) async throws -> ProcessResult? {
        calls.append(Call(executable: executable, arguments: arguments, wait: wait))
        if results.isEmpty {
            return ProcessResult(stdout: "", stderr: "", exitCode: 0)
        }
        return results.removeFirst()
    }

    func start(executable: String, arguments: [String]) throws -> ProcessHandle {
        startCalls.append(Call(executable: executable, arguments: arguments, wait: false))
        let result = startResults.isEmpty ? .success(ProcessResult(stdout: "", stderr: "", exitCode: 0)) : startResults.removeFirst()
        return ProcessHandle(
            waitAsync: {
                try result.get()
            },
            terminate: {}
        )
    }
}

func makeTart(_ runner: ProcessRunning) -> Tart {
    Tart(processRunner: runner, logger: Logger(label: "tart.test", minimumLevel: .info), isExecutable: { $0.hasSuffix("/tart") })
}

/// A softnet policy as `NetworkPreflight.compile` binds it on a managed Mac.
func boundToManagedSoftnet(_ policy: NetworkPolicy) -> NetworkPolicy {
    var policy = policy
    policy.host.softnet = SoftnetLocation(path: SoftnetDiscovery.managedPath, resolved: SoftnetDiscovery.managedPath, source: .managed)
    return policy
}

final class TartTests: XCTestCase {
    func testCloneArgs() async throws {
        let runner = MockProcessRunner()
        let tart = makeTart(runner)
        try await tart.clone(source: "source", name: "ephemeral")
        XCTAssertEqual(runner.calls.first, .init(executable: "tart", arguments: ["clone", "source", "ephemeral"], wait: true))
    }

    func testRunArgs() async throws {
        let runner = MockProcessRunner()
        let tart = makeTart(runner)
        try tart.run(name: "ephemeral")
        XCTAssertEqual(runner.startCalls.first, .init(executable: "tart", arguments: ["run", "ephemeral", "--no-graphics"], wait: false))
    }

    func testRunArgsWithOptions() async throws {
        let runner = MockProcessRunner()
        let tart = makeTart(runner)
        let options = Tart.RunOptions(
            directoryMounts: [
                Tart.DirectoryMount(hostPath: "/tmp/dir", name: "dir", readOnly: true)
            ],
            noAudio: true,
            noGraphics: false,
            noClipboard: true,
            nested: true,
            rootDiskOpts: "caching=cached,sync=none"
        )
        try tart.run(name: "ephemeral", options: options)
        XCTAssertEqual(runner.startCalls.first, .init(
            executable: "tart",
            arguments: ["run", "ephemeral", "--no-audio", "--no-clipboard", "--nested", "--root-disk-opts=caching=cached,sync=none", "--dir", "dir:/tmp/dir:ro"],
            wait: false
        ))
    }


    func testRunUsesSoftnetIsolation() throws {
        let runner = MockProcessRunner()
        let tart = makeTart(runner)
        let options = Tart.RunOptions(
            directoryMounts: [], noAudio: true, noGraphics: true,
            noClipboard: true, nested: false,
            network: boundToManagedSoftnet(try NetworkConfig(mode: .softnet).compile())
        )
        _ = try tart.run(name: "ephemeral", options: options)
        XCTAssertEqual(runner.startCalls.last?.arguments, [
            "run", "ephemeral", "--net-softnet", "--no-graphics", "--no-audio", "--no-clipboard"
        ])
    }

    func testRunUsesRestrictedDefaultDenyBeforeBoot() throws {
        let runner = MockProcessRunner()
        let tart = makeTart(runner)
        let options = Tart.RunOptions(
            directoryMounts: [], noAudio: true, noGraphics: true,
            noClipboard: true, nested: false,
            network: boundToManagedSoftnet(try NetworkConfig(mode: .restricted, allowCIDRs: ["10.42.10.25/32", "10.42.11.0/24"]).compile())
        )
        _ = try tart.run(name: "ephemeral", options: options)
        XCTAssertEqual(runner.startCalls.last?.arguments, [
            "run", "ephemeral", "--net-softnet", "--net-softnet-block=0.0.0.0/0",
            "--net-softnet-allow=in proto tcp @host port 22,out 10.42.10.25/32,out 10.42.11.0/24",
            "--no-graphics", "--no-audio", "--no-clipboard"
        ])
    }

    func testNetworkCIDRValidationRejectsBroadAndMalformedRules() {
        for value in ["0.0.0.0/0", "0.0.0.0/1", "10.0.0.0/8", "@host",
                      "github.com", "::/0", "192.168.1.1/33", "999.1.2.3/32",
                      "10.01.1.1/32", "10.0.0.1", "10.0.0.1/24,127.0.0.1/32"] {
            XCTAssertFalse(NetworkPolicy.isAllowedCIDR(value), value)
        }
        XCTAssertTrue(NetworkPolicy.isAllowedCIDR("10.42.10.25/32"))
        XCTAssertTrue(NetworkPolicy.isAllowedCIDR("192.168.1.0/24"))
    }

    func testSetArgs() async throws {
        let runner = MockProcessRunner()
        let tart = makeTart(runner)
        let display = Tart.Display(width: 1920, height: 1080, unit: "px")
        try await tart.set(name: "ephemeral", cpuCores: 4, memoryMb: 4096, display: display, displayRefit: true, diskSizeGb: 80)
        XCTAssertEqual(runner.calls.first, .init(
            executable: "tart",
            arguments: ["set", "ephemeral", "--cpu", "4", "--memory", "4096", "--display", "1920x1080px", "--display-refit", "--disk-size", "80"],
            wait: true
        ))
    }

    func testIpArgs() async throws {
        let runner = MockProcessRunner()
        runner.results = [ProcessResult(stdout: "10.0.0.1\n", stderr: "", exitCode: 0)]
        let tart = makeTart(runner)
        let ip = try await tart.ip(name: "ephemeral", wait: 60)
        XCTAssertEqual(ip, "10.0.0.1")
        XCTAssertEqual(runner.calls.first, .init(executable: "tart", arguments: ["ip", "ephemeral", "--wait", "60"], wait: true))
    }

    func testPrepareSkipsPullWhenPresent() async throws {
        let runner = MockProcessRunner()
        runner.results = [ProcessResult(stdout: "ghcr.io/cirruslabs/macos-tahoe-xcode:latest\n", stderr: "", exitCode: 0)]
        let tart = makeTart(runner)
        try await tart.prepare(source: "ghcr.io/cirruslabs/macos-tahoe-xcode:latest")
        XCTAssertEqual(runner.calls, [
            .init(executable: "tart", arguments: ["list", "--source", "oci", "--quiet"], wait: true)
        ])
    }

    func testPreparePullsWhenMissing() async throws {
        let runner = MockProcessRunner()
        runner.results = [
            ProcessResult(stdout: "", stderr: "", exitCode: 0),
            ProcessResult(stdout: "", stderr: "", exitCode: 0)
        ]
        let tart = makeTart(runner)
        try await tart.prepare(source: "ghcr.io/cirruslabs/macos-tahoe-xcode:latest")
        XCTAssertEqual(runner.calls, [
            .init(executable: "tart", arguments: ["list", "--source", "oci", "--quiet"], wait: true),
            .init(executable: "tart", arguments: ["pull", "ghcr.io/cirruslabs/macos-tahoe-xcode:latest"], wait: true)
        ])
    }

    func testIsRunningUsesJsonList() async throws {
        let runner = MockProcessRunner()
        runner.results = [
            ProcessResult(stdout: "[{\"Name\":\"vm-1\",\"Running\":true}]", stderr: "", exitCode: 0)
        ]
        let tart = makeTart(runner)
        let running = try await tart.isRunning(name: "vm-1")
        XCTAssertTrue(running)
        XCTAssertEqual(runner.calls, [
            .init(executable: "tart", arguments: ["list", "--format", "json"], wait: true)
        ])
    }

    func testStatusMissingWhenVmNotFound() async throws {
        let runner = MockProcessRunner()
        runner.results = [
            ProcessResult(stdout: "[]", stderr: "", exitCode: 0)
        ]
        let tart = makeTart(runner)
        let status = try await tart.status(name: "missing")
        XCTAssertEqual(status, .missing)
    }

    func testStatusRunningWhenVmIsRunning() async throws {
        let runner = MockProcessRunner()
        runner.results = [
            ProcessResult(stdout: "[{\"Name\":\"vm-1\",\"Running\":true}]", stderr: "", exitCode: 0)
        ]
        let tart = makeTart(runner)
        let status = try await tart.status(name: "vm-1")
        XCTAssertEqual(status, .running)
    }

    func testStatusStoppedWhenVmIsStopped() async throws {
        let runner = MockProcessRunner()
        runner.results = [
            ProcessResult(stdout: "[{\"Name\":\"vm-1\",\"Running\":false}]", stderr: "", exitCode: 0)
        ]
        let tart = makeTart(runner)
        let status = try await tart.status(name: "vm-1")
        XCTAssertEqual(status, .stopped)
    }
}
