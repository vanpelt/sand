import Foundation
import Testing
@testable import sand

private func loadRun(_ runYAML: String, mounts: String = "") throws -> Config.VM {
    let yaml = """
    runners:
      - name: net-test
        vm:
          source:
            type: local
            name: golden
    \(mounts)
    \(runYAML)
        provisioner:
          type: script
          config:
            run: echo ok
    """
    let config = try Config.load(path: writeTempFile(contents: yaml).path)
    return try #require(config.runners.first?.vm)
}

private func validationMessages(_ vm: Config.VM) -> [ConfigValidationIssue] {
    let runner = Config.RunnerConfig(
        name: "net-test", vm: vm,
        provisioner: .init(type: .script, script: .init(run: "true"), github: nil),
        preRun: nil, postRun: nil, stopAfter: nil, healthCheck: nil
    )
    return ConfigValidator().validate(Config(runners: [runner]))
}

private func vm(network: NetworkConfig, noClipboard: Bool = true, nested: Bool = false, mounts: [Config.DirectoryMount] = []) -> Config.VM {
    Config.VM(
        source: .init(type: .local, image: nil, name: "golden"), hardware: nil, mounts: mounts, cache: nil,
        run: .init(noGraphics: true, noClipboard: noClipboard, nested: nested, network: network),
        diskSizeGb: nil, ssh: .standard
    )
}

@Suite struct NetworkConfigTests {
    @Test func omittedNetworkKeyIsTheGitHubProfile() throws {
        let vm = try loadRun("")
        #expect(vm.run.network == .secureDefault)
        #expect(vm.run.network.profile == .github)
        #expect(vm.run.noClipboard == true)
        let policy = try vm.run.network.compile()
        #expect(policy.egress != nil)
        #expect(policy.requiresSoftnet)
    }

    @Test func explicitSharedModeDecodesAndWarns() throws {
        let vm = try loadRun("""
              run:
                network: { mode: shared }
        """)
        #expect(vm.run.network.mode == .shared)
        #expect(vm.run.noClipboard == false)
        let issues = validationMessages(vm)
        #expect(issues.contains { $0.severity == .warning && $0.message.contains("unrestricted host/LAN/VPN/corporate network reach") })
        #expect(!issues.contains { $0.severity == .error })
    }

    @Test func profileAndModeTogetherIsAnError() {
        #expect(throws: (any Error).self) {
            try loadRun("""
                  run:
                    network: { profile: github, mode: shared }
            """)
        }
    }

    @Test func emptyNetworkBlockIsAnError() {
        #expect(throws: (any Error).self) {
            try loadRun("""
                  run:
                    network: {}
            """)
        }
    }

    @Test(arguments: ["profile: corporate", "mode: open", "profile: github, presets: [maven]"])
    func unknownProfileModeOrPresetIsAnError(body: String) {
        #expect(throws: (any Error).self) {
            try loadRun("""
                  run:
                    network: { \(body) }
            """)
        }
    }

    @Test func noClipboardDefaultsToTrueUnderAProfileAndFalseExplicitWarns() throws {
        let offline = try loadRun("""
              run:
                network: { profile: offline }
        """)
        #expect(offline.run.noClipboard == true)
        let explicit = try loadRun("""
              run:
                noClipboard: false
                network: { profile: github }
        """)
        #expect(explicit.run.noClipboard == false)
        #expect(validationMessages(explicit).contains { $0.severity == .warning && $0.message.contains("clipboard") })
    }

    @Test func legacyRestrictedRoundTripsAndAddsHostSSH() throws {
        let vm = try loadRun("""
              run:
                network:
                  mode: restricted
                  allowCIDRs: [10.42.10.25/32]
        """)
        #expect(vm.run.network.mode == .restricted)
        #expect(vm.run.network.allowCIDRs == ["10.42.10.25/32"])
        let policy = try vm.run.network.compile()
        #expect(policy.kind == .restricted(["10.42.10.25/32"]))
        #expect(policy.tartArguments.last == "--net-softnet-allow=in proto tcp @host port 22,out 10.42.10.25/32")
        #expect(validationMessages(vm).filter { $0.severity == .error }.isEmpty)
    }

    @Test func extendedProfileCompilesPresetsDomainsAndCIDRs() throws {
        let vm = try loadRun("""
              run:
                network:
                  profile: github
                  presets: [npm, pypi]
                  allowedDomains: [Registry.Example-Artifacts.com., "*.cdn.example.com", "git.example.org:8443"]
                  verify: strict
                  allowedCIDRs:
                    - { cidr: 203.0.113.10/32, port: 443 }
        """)
        let policy = try vm.run.network.compile()
        let egress = try #require(policy.egress)
        #expect(egress.verify == .strict)
        #expect(egress.allows(host: "registry.npmjs.org", port: 443))
        #expect(egress.allows(host: "files.pythonhosted.org", port: 443))
        #expect(egress.allows(host: "registry.example-artifacts.com", port: 443))
        #expect(egress.allows(host: "a.cdn.example.com", port: 443))
        #expect(egress.allows(host: "git.example.org", port: 8443))
        #expect(!egress.allows(host: "git.example.org", port: 443))
        #expect(!egress.allows(host: "example.com", port: 443))
        #expect(policy.tartArguments.last == "--net-softnet-allow=in proto tcp @host port 22,out proto tcp 203.0.113.10/32 port 443")
        let errors = validationMessages(vm).filter { $0.severity == .error }
        #expect(errors.isEmpty, "\(errors)")
    }

    @Test(arguments: ["10.0.0.5", "[::1]", "*", "*.com", "a.*.b.com", "github.com:0", "github.com:70000", "bad_label.com", "-x.example.com", "1.2.3.4:443"])
    func allowedDomainsRejections(entry: String) {
        #expect(throws: (any Error).self) { try DomainRule.parse(entry) }
        let issues = validationMessages(vm(network: NetworkConfig(selection: .profile(.github), allowedDomains: [entry])))
        #expect(issues.contains { $0.severity == .error && $0.message.contains("allowedDomains") })
    }

    @Test func allowedDomainsNormalisesCaseAndTrailingDot() throws {
        let rule = try DomainRule.parse("  GitHub.COM. ")
        #expect(rule.pattern == DomainPattern(kind: .exact("github.com")))
        #expect(rule.port == 443)
        #expect(try DomainRule.parse("git.example.org:8443").port == 8443)
    }

    @Test func sshOrSmtpPortsWarn() {
        let issues = validationMessages(vm(network: NetworkConfig(selection: .profile(.github), allowedDomains: ["git.example.org:22"])))
        #expect(issues.contains { $0.severity == .warning && $0.message.contains("port 22") })
    }

    @Test func directCIDRRulesRejectPrivateAndWideRanges() {
        let privateAllow = vm(network: NetworkConfig(selection: .profile(.github), allowedCIDRs: [DirectCIDRAllow(cidr: "172.16.7.60/32", port: 443)]))
        #expect(validationMessages(privateAllow).contains { $0.severity == .error && $0.message.contains("private") })
        let reviewed = vm(network: NetworkConfig(selection: .profile(.github), allowedCIDRs: [DirectCIDRAllow(cidr: "172.16.7.60/32", port: 443, allowPrivate: true)]))
        #expect(validationMessages(reviewed).filter { $0.severity == .error }.isEmpty)
        #expect(validationMessages(reviewed).contains { $0.severity == .warning && $0.message.contains("allowPrivate") })
        let wide = vm(network: NetworkConfig(selection: .profile(.github), allowedCIDRs: [DirectCIDRAllow(cidr: "0.0.0.0/0", port: 443)]))
        #expect(validationMessages(wide).contains { $0.severity == .error })
        #expect(throws: (any Error).self) { try wide.run.network.compile() }
    }

    @Test func isolatedProfilesRejectMountsNestedAndVerifyOff() {
        let mount = Config.DirectoryMount(hostPath: "/tmp", name: "tmp", mode: .ro)
        let messages = validationMessages(vm(network: .secureDefault, nested: true, mounts: [mount])).map(\.message).joined(separator: "\n")
        #expect(messages.contains("does not permit host directory mounts"))
        #expect(messages.contains("nested: false"))
        let verifyOff = validationMessages(vm(network: NetworkConfig(selection: .profile(.github), verify: .off)))
        #expect(verifyOff.contains { $0.severity == .error && $0.message.contains("verify: off") })
        let offlineOff = validationMessages(vm(network: NetworkConfig(selection: .profile(.offline), verify: .off)))
        #expect(offlineOff.filter { $0.severity == .error }.isEmpty)
    }

    @Test func reservedKeysAreRejected() {
        let ssh = validationMessages(vm(network: NetworkConfig(selection: .profile(.github), allowGitHubSSH: true)))
        #expect(ssh.contains { $0.severity == .error && $0.message.contains("allowGitHubSSH") })
        let gateway = validationMessages(vm(network: NetworkConfig(selection: .profile(.github), transport: .gateway)))
        #expect(gateway.contains { $0.severity == .error && $0.message.contains("gateway") })
    }

    @Test func modeRejectsProfileOnlyKeys() {
        let issues = validationMessages(vm(network: NetworkConfig(selection: .mode(.softnet), allowedDomains: ["example.com"])))
        #expect(issues.contains { $0.severity == .error && $0.message.contains("require a profile") })
    }

    @Test func policyHashIsStableAndChangesWithDomains() throws {
        let base = try NetworkConfig.secureDefault.compile()
        #expect(base.policyHash == (try NetworkConfig.secureDefault.compile()).policyHash)
        #expect(base.policyHash.count == 64)
        let extended = try NetworkConfig(selection: .profile(.github), allowedDomains: ["example.org"]).compile()
        #expect(base.policyHash != extended.policyHash)
        #expect(base.explain().contains { $0.contains("productionresultssa*.blob.core.windows.net") })
    }
}

@Suite struct SoftnetRulesTests {
    @Test func githubProfileEmitsDenyAllPlusHostSSH() throws {
        #expect(try NetworkConfig.secureDefault.compile().tartArguments == [
            "--net-softnet", "--net-softnet-block=0.0.0.0/0", "--net-softnet-allow=in proto tcp @host port 22"
        ])
    }

    @Test func sshRuleFollowsTheConfiguredPort() throws {
        #expect(try NetworkConfig(selection: .profile(.offline)).compile(sshPort: 2222).tartArguments.last == "--net-softnet-allow=in proto tcp @host port 2222")
    }

    @Test func restrictedPutsHostSSHAheadOfDirectAllows() throws {
        let args = try NetworkConfig(mode: .restricted, allowCIDRs: ["10.42.10.25/32"]).compile().tartArguments
        #expect(args == ["--net-softnet", "--net-softnet-block=0.0.0.0/0", "--net-softnet-allow=in proto tcp @host port 22,out 10.42.10.25/32"])
    }

    @Test func renderedRulesNeverContainCommas() throws {
        let policy = try NetworkConfig(selection: .profile(.github), allowedCIDRs: [DirectCIDRAllow(cidr: "203.0.113.0/24", port: 443)]).compile()
        for rule in try #require(policy.softnet).allows {
            #expect(!rule.render().contains(","))
        }
        #expect(throws: SoftnetRuleError.self) {
            try SoftnetRuleSet.denyAll(allowing: [SoftnetRule(direction: .outbound, proto: nil, target: .cidr("1.2.3.4/32,0.0.0.0/0"), port: nil)])
        }
    }

    @Test(arguments: [0, 1, 8, 16, 23])
    func portfulAllowWiderThanSlash24IsRefused(prefix: Int) {
        #expect(throws: SoftnetRuleError.self) {
            try SoftnetRuleSet.denyAll(allowing: [SoftnetRule(direction: .outbound, proto: .tcp, target: .cidr("0.0.0.0/\(prefix)"), port: 443)])
        }
    }

    @Test func exposeIsNeverEmitted() throws {
        for config in [NetworkConfig.secureDefault, NetworkConfig(selection: .profile(.offline)), NetworkConfig(mode: .restricted, allowCIDRs: ["10.0.0.0/24"]), NetworkConfig(mode: .softnet)] {
            #expect(!(try config.compile()).tartArguments.contains { $0.contains("expose") })
        }
    }

    @Test func sharedPolicyEmitsNothing() throws {
        #expect(try NetworkConfig(mode: .shared).compile().tartArguments == [])
        #expect(NetworkPolicy.shared.tartArguments == [])
        #expect(!NetworkPolicy.shared.requiresSoftnet)
    }
}

@Suite struct DomainPatternTests {
    @Test func leadingWildcardMatchesSubdomainsOnly() throws {
        let pattern = try DomainPattern.parse("*.actions.githubusercontent.com")
        #expect(pattern.matches("pipelines.actions.githubusercontent.com"))
        #expect(pattern.matches("a.b.actions.githubusercontent.com"))
        #expect(!pattern.matches("actions.githubusercontent.com"))
        #expect(!pattern.matches("evilactions.githubusercontent.com"))
        #expect(!pattern.matches("x.actions.githubusercontent.com.evil.com"))
        #expect(!pattern.matches(".actions.githubusercontent.com"))
    }

    @Test func firstLabelGlobStaysInsideTheLabel() throws {
        let pattern = try DomainPattern.parse("productionresultssa*.blob.core.windows.net")
        #expect(pattern.matches("productionresultssa12.blob.core.windows.net"))
        #expect(!pattern.matches("a.productionresultssa1.blob.core.windows.net"))
        #expect(!pattern.matches("evil.blob.core.windows.net"))
        #expect(!pattern.matches("productionresultssa1.blob.core.windows.net.evil.com"))
    }

    @Test func matchingIsCaseAndTrailingDotInsensitive() throws {
        #expect(try DomainPattern.parse("GitHub.com").matches("GITHUB.COM."))
        #expect(try DomainPattern.parse("*.pkg.github.com").matches("NPM.pkg.GitHub.com."))
    }

    @Test func exactNeverMatchesSubdomainsOrIPs() throws {
        let pattern = try DomainPattern.parse("github.com")
        #expect(!pattern.matches("api.github.com"))
        #expect(!pattern.matches("github.com.evil.com"))
        #expect(!pattern.matches("140.82.112.3"))
    }

    @Test func everyBuiltInPresetParses() throws {
        for preset in EgressPreset.allCases {
            for domain in preset.domains {
                _ = try DomainRule.parse(domain)
            }
        }
        for name in EgressPreset.steeredNames {
            #expect(EgressPreset.github.domains.contains(name))
        }
    }
}
