import Foundation

struct SSHClient {
    let processRunner: ProcessRunning
    let host: String
    let config: Config.SSH

    /// `-F /dev/null` ignores the host user's ~/.ssh/config (and the system
    /// one), so a `Host *` ForwardAgent/RemoteForward/ProxyCommand/ControlMaster
    /// can never hand the guest the user's agent or open guest-to-host paths
    /// that bypass softnet and the egress proxy.
    static let hardeningOptions = [
        "-F", "/dev/null",
        "-o", "ForwardAgent=no",
        "-o", "ForwardX11=no",
        "-o", "PermitLocalCommand=no",
        "-o", "ControlMaster=no",
        "-o", "ControlPath=none"
    ]

    /// Sessions that must forward nothing at all (exec and scp; not the tunnel).
    static let noForwardingOptions = ["-o", "ClearAllForwardings=yes"]

    static let connectionOptions = hardeningOptions + [
        "-o", "PreferredAuthentications=password",
        "-o", "PubkeyAuthentication=no",
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=6"
    ]

    /// The host environment without the ssh-agent socket, so no ssh child can
    /// offer the user's keys or agent to the guest.
    static func childEnvironment(_ base: [String: String] = ProcessInfo.processInfo.environment) -> [String: String] {
        var environment = base
        environment.removeValue(forKey: "SSH_AUTH_SOCK")
        environment.removeValue(forKey: "SSH_AGENT_PID")
        return environment
    }

    func exec(command: String) async throws -> ProcessResult? {
        return try await processRunner.run(
            executable: "sshpass",
            arguments: sshArguments(command: command),
            wait: true,
            environment: Self.childEnvironment()
        )
    }

    func start(command: String) throws -> ProcessHandle {
        return try processRunner.start(
            executable: "sshpass",
            arguments: sshArguments(command: command),
            environment: Self.childEnvironment()
        )
    }

    func copy(localPath: String, remotePath: String) async throws -> ProcessResult? {
        return try await processRunner.run(
            executable: "sshpass",
            arguments: ["-p", config.password, "scp"] + Self.connectionOptions + Self.noForwardingOptions + [
                "-P", String(config.port),
                localPath,
                "\(config.user)@\(host):\(remotePath)"
            ],
            wait: true,
            environment: Self.childEnvironment()
        )
    }

    /// `ssh -N -R 127.0.0.1:<remotePort>:127.0.0.1:<localPort>`: the guest's
    /// loopback port forwards to the host-side egress proxy over this session.
    /// Options here come before the shared ones because ssh keeps the first value.
    func startReverseTunnel(remotePort: Int, localPort: UInt16) throws -> ProcessHandle {
        try processRunner.start(executable: "sshpass", arguments: reverseTunnelArguments(remotePort: remotePort, localPort: localPort), environment: Self.childEnvironment())
    }

    func reverseTunnelArguments(remotePort: Int, localPort: UInt16) -> [String] {
        ["-p", config.password, "ssh", "-N",
         "-o", "ExitOnForwardFailure=yes",
         "-o", "ServerAliveInterval=15",
         "-o", "ServerAliveCountMax=2",
         "-R", "127.0.0.1:\(remotePort):127.0.0.1:\(localPort)"] + Self.connectionOptions + [
            "-p", String(config.port),
            "\(config.user)@\(host)"
        ]
    }

    func checkConnection() async throws {
        _ = try await exec(command: "true")
    }

    private func sshArguments(command: String) -> [String] {
        let escaped = command.replacingOccurrences(of: "'", with: "'\"'\"'")
        return ["-p", config.password, "ssh"] + Self.connectionOptions + Self.noForwardingOptions + [
            "-p", String(config.port),
            "\(config.user)@\(host)",
            "/bin/bash -lc '\(escaped)'"
        ]
    }
}
