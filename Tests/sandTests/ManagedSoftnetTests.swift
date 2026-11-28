import Darwin
import Foundation
import Testing
@testable import sand

private let suidRoot = (uid: UInt32(0), mode: UInt16(S_ISUID) | 0o555)
private let cellarBinary = "/opt/homebrew/Cellar/softnet/0.26.0/bin/softnet"
private let managedManifest = SoftnetDiscovery.managedDirectory + "/" + SoftnetDiscovery.manifestName

private func preflight(_ fileSystem: FakeFileSystem, runner: ScriptedProcessRunner = ScriptedProcessRunner(responder: currentToolHelp)) -> NetworkPreflight {
    makePreflight(runner: runner, fileSystem: fileSystem)
}

private func networkIssues(_ network: NetworkConfig) -> [ConfigValidationIssue] {
    let vm = Config.VM(
        source: .init(type: .local, image: nil, name: "golden"), hardware: nil, mounts: [], cache: nil,
        run: .init(noGraphics: true, noClipboard: true, nested: false, network: network),
        diskSizeGb: nil, ssh: .standard
    )
    let runner = Config.RunnerConfig(name: "net-test", vm: vm, provisioner: .init(type: .script, script: .init(run: "true"), github: nil), preRun: nil, postRun: nil, stopAfter: nil, healthCheck: nil)
    return ConfigValidator().validate(Config(runners: [runner]))
}

@Suite struct SoftnetDiscoveryTests {
    @Test func discoveryOrderIsConfigThenManagedThenPath() {
        var fileSystem = FakeFileSystem.managed()
        fileSystem.existing.insert("/opt/sand-tools/softnet")
        #expect(SoftnetDiscovery.locate(configuredPath: "/opt/sand-tools/softnet", fileSystem: fileSystem)
            == .found(SoftnetLocation(path: "/opt/sand-tools/softnet", resolved: "/opt/sand-tools/softnet", source: .config)))
        #expect(SoftnetDiscovery.locate(configuredPath: nil, fileSystem: fileSystem)
            == .found(SoftnetLocation(path: SoftnetDiscovery.managedPath, resolved: SoftnetDiscovery.managedPath, source: .managed)))
        let homebrew = FakeFileSystem.homebrewOwnedByUser(binary: (501, 0o555))
        #expect(SoftnetDiscovery.locate(configuredPath: nil, fileSystem: homebrew)
            == .found(SoftnetLocation(path: "/opt/homebrew/bin/softnet", resolved: cellarBinary, source: .path)))
    }

    @Test func aMissingConfiguredPathNeverFallsBack() {
        let outcome = SoftnetDiscovery.locate(configuredPath: "/nope/softnet", fileSystem: FakeFileSystem.managed())
        guard case let .missing(reason) = outcome else {
            Issue.record("expected missing, got \(outcome)")
            return
        }
        #expect(reason.contains("/nope/softnet"))
    }

    @Test func ancestorsWalkToRoot() {
        #expect(SoftnetDiscovery.ancestors(of: "/usr/local/libexec/sand/softnet") == ["/usr/local/libexec/sand", "/usr/local/libexec", "/usr/local", "/usr", "/"])
        #expect(SoftnetDiscovery.ancestors(of: "/softnet") == ["/"])
    }

    @Test func manifestParsing() {
        let digest = String(repeating: "AB", count: 32)
        #expect(SoftnetDiscovery.parseManifest("\(digest)  /usr/local/libexec/sand/softnet\n") == digest.lowercased())
        #expect(SoftnetDiscovery.parseManifest("not-a-digest softnet") == nil)
        #expect(SoftnetDiscovery.parseManifest("") == nil)
    }
}

@Suite struct SoftnetPathSafetyTests {
    @Test func homebrewSetuidSoftnetIsALocalPrivilegeEscalationAndIsNeverRun() async {
        let fileSystem = FakeFileSystem.homebrewOwnedByUser(binary: suidRoot)
        let runner = ScriptedProcessRunner(responder: currentToolHelp)
        let checks = await preflight(fileSystem, runner: runner).checkSoftnet(SoftnetDiscovery.locate(configuredPath: nil, fileSystem: fileSystem), pin: nil)
        #expect(checks.map(\.name) == [NetworkPreflight.pathCheckName])
        let path = checks[0]
        #expect(path.status == .failed)
        #expect(path.detail.contains("local privilege escalation"))
        #expect(path.detail.contains("/opt/homebrew/Cellar/softnet/0.26.0/bin is owned by uid 501"))
        #expect(path.remediation?.contains("install-managed-softnet.sh") == true)
        // Neither `softnet --help` nor `sudo -n` ran against the unsafe binary.
        #expect(!runner.calls.contains { $0.executable.hasSuffix("softnet") || $0.executable == "sudo" })
    }

    @Test func rootOwnedBinaryInAUserDirectoryStillFails() {
        // chown root + chmod u+s on the Cellar file is not enough: the user can rename it away.
        let fileSystem = FakeFileSystem.homebrewOwnedByUser(binary: suidRoot)
        let location = SoftnetLocation(path: cellarBinary, resolved: cellarBinary, source: .config)
        let problems = SoftnetDiscovery.pathProblems(location, fileSystem: fileSystem)
        #expect(!problems.contains { $0.hasPrefix(cellarBinary + " ") })
        #expect(problems.contains { $0.contains("/opt/homebrew/Cellar is writable by group or other (mode 775)") })
    }

    @Test func groupWritableAncestorFailsButRootStickyIsTolerated() {
        var fileSystem = FakeFileSystem()
        fileSystem.owner = (0, 0o755)
        let location = SoftnetLocation(path: "/private/tmp/sand/softnet", resolved: "/private/tmp/sand/softnet", source: .config)
        fileSystem.owners["/private/tmp"] = (0, UInt16(S_ISVTX) | 0o777)
        #expect(SoftnetDiscovery.pathProblems(location, fileSystem: fileSystem).isEmpty)
        fileSystem.owners["/private/tmp/sand"] = (0, 0o775)
        #expect(SoftnetDiscovery.pathProblems(location, fileSystem: fileSystem) == ["/private/tmp/sand is writable by group or other (mode 775)"])
        fileSystem.owners["/private/tmp/sand"] = (501, UInt16(S_ISVTX) | 0o777)
        #expect(SoftnetDiscovery.pathProblems(location, fileSystem: fileSystem).count == 2)
    }

    @Test func colonInThePathIsRejected() {
        var fileSystem = FakeFileSystem()
        fileSystem.owner = (0, 0o755)
        let location = SoftnetLocation(path: "/opt/a:b/softnet", resolved: "/opt/a:b/softnet", source: .config)
        #expect(SoftnetDiscovery.pathProblems(location, fileSystem: fileSystem).contains { $0.contains("contains ':'") })
    }

    @Test func realSymlinkIsJudgedByItsTarget() throws {
        // Real file system: a symlink named softnet pointing into another
        // directory is resolved, and the target's directories are what P12 inspects.
        let base = FileManager.default.temporaryDirectory.appendingPathComponent("sand-symlink-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: base) }
        let real = base.appendingPathComponent("user-dir")
        let linkDirectory = base.appendingPathComponent("link-dir")
        try FileManager.default.createDirectory(at: real, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: linkDirectory, withIntermediateDirectories: true)
        try Data("#!/bin/sh\n".utf8).write(to: real.appendingPathComponent("softnet"))
        try FileManager.default.createSymbolicLink(atPath: linkDirectory.appendingPathComponent("softnet").path, withDestinationPath: real.appendingPathComponent("softnet").path)
        let fileSystem = SystemPreflightFileSystem()
        let outcome = SoftnetDiscovery.locate(configuredPath: linkDirectory.appendingPathComponent("softnet").path, fileSystem: fileSystem)
        guard case let .found(location) = outcome else {
            Issue.record("expected found, got \(outcome)")
            return
        }
        let realDirectory = fileSystem.realpath(real.path)
        #expect(location.resolved == realDirectory + "/softnet")
        #expect(location.directory == realDirectory)
        let problems = SoftnetDiscovery.pathProblems(location, fileSystem: fileSystem)
        // Owned by the test user, so it fails, and it is the target that is named.
        #expect(problems.contains { $0.hasPrefix(realDirectory + "/softnet is owned by uid") })
        #expect(problems.contains { $0.hasPrefix(realDirectory + " is owned by uid") })
        #expect(!problems.contains { $0.contains("link-dir") })
    }

    @Test func binaryMustBeNamedSoftnetAndNotWritable() {
        var fileSystem = FakeFileSystem()
        fileSystem.owner = (0, 0o755)
        fileSystem.owners["/usr/local/libexec/sand/softnet-0.26"] = (0, 0o775)
        let location = SoftnetLocation(path: "/usr/local/libexec/sand/softnet", resolved: "/usr/local/libexec/sand/softnet-0.26", source: .managed)
        let problems = SoftnetDiscovery.pathProblems(location, fileSystem: fileSystem)
        #expect(problems.contains { $0.contains("is not named softnet") })
        #expect(problems.contains { $0.contains("softnet-0.26 is writable by group or other") })
    }
}

@Suite struct ManagedSoftnetBackendTests {
    @Test func managedSetuidSoftnetIsChosenByDefaultWithZeroConfig() async throws {
        let fileSystem = FakeFileSystem.managed()
        let preflight = preflight(fileSystem)
        let policy = try await preflight.compile(.secureDefault, sshPort: 22)
        #expect(policy.backend == .softnet)
        #expect(policy.host.softnet?.source == .managed)
        #expect(policy.host.autoFallback == nil)
        let checks = await preflight.run(policy: policy, includeSSHTools: false)
        #expect(NetworkPreflight.failures(checks).isEmpty, "\(checks.map(\.line))")
        #expect(checks.contains { $0.name == NetworkPreflight.pinCheckName && $0.status == .ok && $0.detail.contains(managedManifest) })
        #expect(NetworkPreflight.failures(await preflight.perVM(policy: policy)).isEmpty)
        #expect(policy.explain().contains { $0.contains("softnet binary: /usr/local/libexec/sand/softnet (managed)") })
    }

    @Test func homebrewSetuidSoftnetMakesAutoFallBackLoudly() async throws {
        let preflight = preflight(FakeFileSystem.homebrewOwnedByUser(binary: suidRoot))
        let policy = try await preflight.compile(.secureDefault, sshPort: 22)
        #expect(policy.backend == .hostOnly)
        let fallback = try #require(policy.host.autoFallback)
        #expect(fallback.loud)
        #expect(fallback.reason.contains("local privilege escalation"))
        let checks = await preflight.run(policy: policy, includeSSHTools: false)
        #expect(checks.contains { $0.name == "P0 backend auto" && $0.status == .warning })
        #expect(policy.explain().contains { $0.hasPrefix("backend auto chose hostOnly:") })
    }

    @Test func plainHomebrewSoftnetFallsBackQuietly() async throws {
        // This Mac's state: user-owned, not setuid, not sudo-allowed.
        let policy = try await preflight(FakeFileSystem.homebrewOwnedByUser(binary: (501, 0o555))).compile(.secureDefault, sshPort: 22)
        #expect(policy.backend == .hostOnly)
        #expect(policy.host.autoFallback?.loud == false)
    }

    @Test func explicitSoftnetBackendFailsClosedOnAnUnsafePath() async throws {
        let preflight = preflight(FakeFileSystem.homebrewOwnedByUser(binary: suidRoot))
        let policy = try await preflight.compile(NetworkConfig(selection: .profile(.github), backend: .softnet), sshPort: 22)
        #expect(policy.backend == .softnet)
        let failures = NetworkPreflight.failures(await preflight.run(policy: policy, includeSSHTools: false))
        #expect(failures.map(\.name) == [NetworkPreflight.pathCheckName])
        #expect(NetworkStartup.failureMessage(failures).contains("install-managed-softnet.sh"))
    }

    @Test func manifestMismatchFailsClosedEvenUnderAuto() async throws {
        let tampered = FakeFileSystem.managed(digest: String(repeating: "cd", count: 32), manifest: String(repeating: "ab", count: 32) + "  softnet\n")
        let preflight = preflight(tampered)
        let policy = try await preflight.compile(.secureDefault, sshPort: 22)
        // A tampered managed binary is not a reason to quietly downgrade.
        #expect(policy.backend == .softnet)
        let failures = NetworkPreflight.failures(await preflight.perVM(policy: policy))
        #expect(failures.map(\.name) == [NetworkPreflight.pinCheckName])
        #expect(failures.first?.detail.contains("expected abab") == true)
    }

    @Test func brokenManagedSoftnetFailsClosedUnderAuto() async throws {
        // A managed install that is unprivileged, on a loosened path, or gone
        // from softnetPath never downgrades a fleet Mac to hostOnly.
        var loosened = FakeFileSystem.managed()
        loosened.owners[SoftnetDiscovery.managedDirectory] = (0, 0o775)
        var notRunnable = FakeFileSystem.managed()
        notRunnable.notExecutable.insert(SoftnetDiscovery.managedPath)
        let cases: [(FakeFileSystem, NetworkConfig, String)] = [
            (FakeFileSystem.managed(mode: 0o555), .secureDefault, "P3 softnet privilege"),
            (loosened, .secureDefault, NetworkPreflight.pathCheckName),
            (notRunnable, .secureDefault, "P3 softnet privilege"),
            (FakeFileSystem.managed(), NetworkConfig(selection: .profile(.github), softnetPath: "/opt/sand-tools/softnet"), "P2 softnet"),
        ]
        for (fileSystem, config, failing) in cases {
            let preflight = preflight(fileSystem)
            let policy = try await preflight.compile(config, sshPort: 22)
            #expect(policy.backend == .softnet, "\(failing)")
            #expect(policy.host.autoFallback == nil)
            let failures = NetworkPreflight.failures(await preflight.run(policy: policy, includeSSHTools: false))
            #expect(failures.map(\.name).contains(failing), "\(failures.map(\.line))")
            #expect(!NetworkPreflight.failures(await preflight.perVM(policy: policy)).isEmpty)
        }
    }

    @Test func setuidSoftnetTheUserCannotExecuteFailsP3() async {
        var fileSystem = FakeFileSystem.managed(mode: UInt16(S_ISUID) | 0o550)
        fileSystem.notExecutable.insert(SoftnetDiscovery.managedPath)
        let location = SoftnetLocation(path: SoftnetDiscovery.managedPath, resolved: SoftnetDiscovery.managedPath, source: .managed)
        let check = await preflight(fileSystem).checkSoftnetPrivilege(location)
        #expect(check.status == .failed)
        #expect(check.remediation?.contains("--group") == true)
        fileSystem.notExecutable = []
        #expect(await preflight(fileSystem).checkSoftnetPrivilege(location).status == .ok)
    }

    @Test func configuredPinIsCheckedToo() async throws {
        let fileSystem = FakeFileSystem.managed()
        let pinned = NetworkConfig(selection: .profile(.github), backend: .softnet, softnetSHA256: String(repeating: "ef", count: 32))
        let policy = try await preflight(fileSystem).compile(pinned, sshPort: 22)
        let failures = NetworkPreflight.failures(await preflight(fileSystem).perVM(policy: policy))
        #expect(failures.first?.detail.contains("vm.run.network.softnetSHA256") == true)
        let matching = NetworkConfig(selection: .profile(.github), backend: .softnet, softnetSHA256: String(repeating: "AB", count: 32).lowercased())
        let ok = try await preflight(fileSystem).compile(matching, sshPort: 22)
        #expect(NetworkPreflight.failures(await preflight(fileSystem).perVM(policy: ok)).isEmpty)
    }

    @Test func userWritableManifestFails() {
        var fileSystem = FakeFileSystem.managed()
        fileSystem.owners[managedManifest] = (501, 0o644)
        let location = SoftnetLocation(path: SoftnetDiscovery.managedPath, resolved: SoftnetDiscovery.managedPath, source: .managed)
        let check = preflight(fileSystem).checkSoftnetPin(location, configured: nil)
        #expect(check.status == .failed)
    }

    @Test func managedInstallWithoutManifestWarns() {
        var fileSystem = FakeFileSystem.managed()
        fileSystem.files[managedManifest] = nil
        let location = SoftnetLocation(path: SoftnetDiscovery.managedPath, resolved: SoftnetDiscovery.managedPath, source: .managed)
        #expect(preflight(fileSystem).checkSoftnetPin(location, configured: nil).status == .warning)
    }

    @Test func tartExecsExactlyTheCheckedSoftnet() async throws {
        let policy = try await preflight(FakeFileSystem.managed()).compile(.secureDefault, sshPort: 22)
        let launch = try Tart.runLaunch(network: policy, base: ["PATH": "/opt/homebrew/bin:/usr/bin", "HOME": "/Users/x", "SENTRY_DSN": "x"], isExecutable: { $0 == "/opt/homebrew/bin/tart" })
        // tart by absolute path; its PATH holds no user-writable directory that could hold another softnet.
        #expect(launch.executable == "/opt/homebrew/bin/tart")
        #expect(launch.environment["PATH"] == "/usr/local/libexec/sand:/usr/bin:/bin:/usr/sbin:/sbin")
        #expect(launch.environment["HOME"] == "/Users/x")
        #expect(launch.environment["SENTRY_DSN"] == nil)
        let hostOnly = try NetworkConfig.secureDefault.compile()
        let hostOnlyLaunch = try Tart.runLaunch(network: hostOnly, base: ["PATH": "/opt/homebrew/bin"])
        #expect(hostOnlyLaunch.executable == "tart")
        #expect(hostOnlyLaunch.environment["PATH"] == "/opt/homebrew/bin")
    }

    @Test func tartRefusesToStartUnderSoftnetWithoutACheckedBinary() async throws {
        // A softnet policy that was never bound to a checked binary must not
        // let tart pick whatever softnet the user's PATH has.
        var unbound = try await preflight(FakeFileSystem.managed()).compile(.secureDefault, sshPort: 22)
        unbound.host.softnet = nil
        #expect(throws: Tart.LaunchError.self) { try Tart.runLaunch(network: unbound, base: ["PATH": "/opt/homebrew/bin"], isExecutable: { _ in true }) }
        let bound = try await preflight(FakeFileSystem.managed()).compile(.secureDefault, sshPort: 22)
        #expect(throws: Tart.LaunchError.self) { try Tart.runLaunch(network: bound, base: ["PATH": "/opt/homebrew/bin"], isExecutable: { _ in false }) }
    }

    @Test func tartRunIsLaunchedWithThatEnvironment() async throws {
        let policy = try await preflight(FakeFileSystem.managed()).compile(.secureDefault, sshPort: 22)
        let runner = ScriptedProcessRunner(responder: currentToolHelp)
        _ = try makeTart(runner).run(name: "vm", options: .init(directoryMounts: [], noAudio: true, noGraphics: true, noClipboard: true, nested: false, network: policy))
        let call = try #require(runner.calls.first { $0.arguments.first == "run" })
        #expect(call.executable.hasPrefix("/") && call.executable.hasSuffix("/tart"))
        #expect(call.environment?["PATH"] == SoftnetDiscovery.managedDirectory + ":" + Tart.softnetSystemPath)
    }
}

@Suite struct SoftnetConfigTests {
    @Test func yamlKeysDecode() throws {
        let yaml = """
        runners:
          - name: net-test
            vm:
              source:
                type: local
                name: golden
              run:
                network:
                  profile: github
                  softnetPath: /usr/local/libexec/sand/softnet
                  softnetSHA256: \(String(repeating: "AB", count: 32))
            provisioner:
              type: script
              config:
                run: echo ok
        """
        let network = try #require(try Config.load(path: writeTempFile(contents: yaml).path).runners.first?.vm.run.network)
        #expect(network.backendChoice == .auto)
        #expect(network.softnetPath == SoftnetDiscovery.managedPath)
        #expect(network.softnetSHA256 == String(repeating: "ab", count: 32))
        #expect(!networkIssues(network).contains { $0.severity == .error })
    }

    @Test func validation() {
        let errors = { (network: NetworkConfig) in networkIssues(network).filter { $0.severity == .error }.map(\.message) }
        #expect(errors(NetworkConfig(selection: .profile(.github), softnetPath: "softnet")).contains { $0.contains("softnetPath must be an absolute path") })
        #expect(errors(NetworkConfig(selection: .profile(.github), softnetPath: "/usr/local/bin/softnet-dev")).contains { $0.contains("named softnet") })
        #expect(errors(NetworkConfig(selection: .profile(.github), softnetSHA256: "abc")).contains { $0.contains("64 hex digits") })
        #expect(errors(NetworkConfig(selection: .profile(.github), softnetPath: "/opt/a:b/softnet")).contains { $0.contains("must not contain ':'") })
        #expect(errors(NetworkConfig(selection: .mode(.shared), softnetPath: "/usr/local/libexec/sand/softnet")).contains { $0.contains("mode: shared") })
        let homebrew = networkIssues(NetworkConfig(selection: .profile(.github), softnetPath: "/opt/homebrew/bin/softnet"))
        #expect(homebrew.contains { $0.severity == .warning && $0.message.contains("Homebrew") })
        let hostOnly = networkIssues(NetworkConfig(selection: .profile(.github), backend: .hostOnly, softnetPath: SoftnetDiscovery.managedPath))
        #expect(hostOnly.contains { $0.severity == .warning && $0.message.contains("no effect") })
    }

    /// Diagnostic for a real Mac (SAND_HOST_TESTS=1): older Intel Homebrew made
    /// /usr/local user-owned, where the managed installer correctly refuses.
    @Test(.enabled(if: ProcessInfo.processInfo.environment["SAND_HOST_TESTS"] == "1"))
    func managedLocationIsRootOwnedOnThisMac() {
        // The chosen location's existing ancestors ship root:wheel 0755 on macOS.
        let fileSystem = SystemPreflightFileSystem()
        for directory in SoftnetDiscovery.ancestors(of: SoftnetDiscovery.managedPath) where fileSystem.fileExists(directory) && directory != SoftnetDiscovery.managedDirectory {
            let info = fileSystem.ownerAndMode(directory)
            #expect(info?.uid == 0, "\(directory)")
            #expect((info?.mode ?? 0o777) & UInt16(S_IWGRP | S_IWOTH) == 0, "\(directory)")
        }
    }
}
