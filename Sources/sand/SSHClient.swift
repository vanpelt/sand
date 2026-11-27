import Foundation

struct SSHClient {
    let processRunner: ProcessRunning
    let host: String
    let config: Config.SSH

    static let connectionOptions = [
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

    func exec(command: String) async throws -> ProcessResult? {
        return try await processRunner.run(
            executable: "sshpass",
            arguments: sshArguments(command: command),
            wait: true
        )
    }

    func start(command: String) throws -> ProcessHandle {
        return try processRunner.start(
            executable: "sshpass",
            arguments: sshArguments(command: command)
        )
    }

    func copy(localPath: String, remotePath: String) async throws -> ProcessResult? {
        return try await processRunner.run(
            executable: "sshpass",
            arguments: ["-p", config.password, "scp"] + Self.connectionOptions + [
                "-P", String(config.port),
                localPath,
                "\(config.user)@\(host):\(remotePath)"
            ],
            wait: true
        )
    }

    /// `ssh -N -R 127.0.0.1:<remotePort>:127.0.0.1:<localPort>`: the guest's
    /// loopback port forwards to the host-side egress proxy over this session.
    /// Options here come before the shared ones because ssh keeps the first value.
    func startReverseTunnel(remotePort: Int, localPort: UInt16) throws -> ProcessHandle {
        try processRunner.start(executable: "sshpass", arguments: reverseTunnelArguments(remotePort: remotePort, localPort: localPort))
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
        return ["-p", config.password, "ssh"] + Self.connectionOptions + [
            "-p", String(config.port),
            "\(config.user)@\(host)",
            "/bin/bash -lc '\(escaped)'"
        ]
    }
}
