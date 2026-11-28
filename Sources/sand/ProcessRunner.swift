import Foundation

private final class PipeDrain: @unchecked Sendable {
    private let handle: FileHandle
    private let lock = NSLock()
    private var data = Data()
    private var finished = false

    init(pipe: Pipe) {
        handle = pipe.fileHandleForReading
        handle.readabilityHandler = { [self] handle in
            lock.withLock {
                guard !finished else {
                    handle.readabilityHandler = nil
                    return
                }
                let chunk = handle.availableData
                if chunk.isEmpty {
                    handle.readabilityHandler = nil
                } else {
                    data.append(chunk)
                }
            }
        }
    }

    func finish() -> Data {
        handle.readabilityHandler = nil
        return lock.withLock {
            if !finished {
                finished = true
                drainRemaining()
                try? handle.close()
            }
            return data
        }
    }

    private func drainRemaining() {
        let descriptor = handle.fileDescriptor
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) >= 0 else {
            return
        }
        var buffer = [UInt8](repeating: 0, count: 65_536)
        while true {
            let count = buffer.withUnsafeMutableBytes { read(descriptor, $0.baseAddress, $0.count) }
            guard count > 0 else {
                return
            }
            data.append(contentsOf: buffer[0..<count])
        }
    }
}

struct ProcessResult: Sendable {
    let stdout: String
    let stderr: String
    let exitCode: Int32
}

actor ProcessHandle {
    private let process: Process?
    private let stdoutDrain: PipeDrain?
    private let stderrDrain: PipeDrain?
    private let command: [String]?
    private let waitAsyncBlock: (() async throws -> ProcessResult)?
    private let terminateBlock: (() -> Void)?
    private let hasExitedBlock: (@Sendable () -> Bool)?
    private var cachedResult: Result<ProcessResult, Error>?
    private var waiters: [UUID: CheckedContinuation<ProcessResult, Error>] = [:]
    private var terminationHandlerInstalled = false
    /// The child's pid (nil for injected fakes).
    nonisolated let processIdentifier: Int32?

    init(process: Process, stdoutPipe: Pipe, stderrPipe: Pipe, command: [String]) {
        self.process = process
        self.processIdentifier = process.processIdentifier
        self.stdoutDrain = PipeDrain(pipe: stdoutPipe)
        self.stderrDrain = PipeDrain(pipe: stderrPipe)
        self.command = command
        self.waitAsyncBlock = nil
        self.terminateBlock = nil
        self.hasExitedBlock = nil
    }

    init(
        waitAsync: @escaping () async throws -> ProcessResult,
        terminate: @escaping () -> Void,
        hasExited: (@Sendable () -> Bool)? = nil,
        processIdentifier: Int32? = nil
    ) {
        self.process = nil
        self.processIdentifier = processIdentifier
        self.hasExitedBlock = hasExited
        self.stdoutDrain = nil
        self.stderrDrain = nil
        self.command = nil
        self.waitAsyncBlock = waitAsync
        self.terminateBlock = terminate
    }

    func waitAsync(terminateOnCancel: Bool = true) async throws -> ProcessResult {
        if let waitAsyncBlock {
            return try await waitAsyncBlock()
        }
        if let cachedResult {
            return try cachedResult.get()
        }
        guard let process else {
            throw ProcessRunnerError.invalidCommand
        }
        if !process.isRunning {
            return try resolveResult().get()
        }
        let waiterID = UUID()
        return try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { continuation in
                if let cachedResult {
                    continuation.resume(with: cachedResult)
                    return
                }
                waiters[waiterID] = continuation
                installTerminationHandlerIfNeeded()
                if !process.isRunning {
                    waiters.removeValue(forKey: waiterID)
                    continuation.resume(with: resolveResult())
                }
            }
        }, onCancel: {
            Task { await cancelWaiter(id: waiterID, terminateProcess: terminateOnCancel) }
        })
    }

    func hasExited() -> Bool {
        if let process { return !process.isRunning }
        if let hasExitedBlock { return hasExitedBlock() }
        return cachedResult != nil
    }

    func terminate() {
        if let terminateBlock {
            terminateBlock()
            return
        }
        guard let process, process.isRunning else {
            return
        }
        process.terminate()
    }

    private func resolveResult() -> Result<ProcessResult, Error> {
        if let cachedResult {
            return cachedResult
        }
        guard let process, let stdoutDrain, let stderrDrain, let command else {
            let failure = Result<ProcessResult, Error>.failure(ProcessRunnerError.invalidCommand)
            cachedResult = failure
            return failure
        }
        let stdoutData = stdoutDrain.finish()
        let stderrData = stderrDrain.finish()
        let stdout = String(data: stdoutData, encoding: .utf8) ?? ""
        let stderr = String(data: stderrData, encoding: .utf8) ?? ""
        let exitCode = process.terminationStatus
        let result: Result<ProcessResult, Error>
        if exitCode != 0 {
            result = .failure(ProcessRunnerError.failed(exitCode: exitCode, stdout: stdout, stderr: stderr, command: command))
        } else {
            result = .success(ProcessResult(stdout: stdout, stderr: stderr, exitCode: exitCode))
        }
        cachedResult = result
        return result
    }

    private func installTerminationHandlerIfNeeded() {
        guard !terminationHandlerInstalled, let process else {
            return
        }
        terminationHandlerInstalled = true
        process.terminationHandler = { [weak self] _ in
            guard let self else {
                return
            }
            Task { await self.processDidExit() }
        }
    }

    private func processDidExit() {
        let result = resolveResult()
        resumeWaiters(with: result)
    }

    private func resumeWaiters(with result: Result<ProcessResult, Error>) {
        let pending = waiters
        waiters = [:]
        for continuation in pending.values {
            continuation.resume(with: result)
        }
    }

    private func cancelWaiter(id: UUID, terminateProcess: Bool) {
        if let continuation = waiters.removeValue(forKey: id) {
            continuation.resume(throwing: CancellationError())
        }
        if terminateProcess, cachedResult == nil, let process, process.isRunning {
            process.terminate()
        }
    }
}

enum ProcessRunnerError: Error, CustomStringConvertible {
    case failed(exitCode: Int32, stdout: String, stderr: String, command: [String])
    case invalidCommand

    var description: String {
        switch self {
        case let .failed(exitCode, _, stderr, command):
            let program = command.first ?? "process"
            let detail = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            if detail.isEmpty {
                return "\(program) exited with code \(exitCode)"
            }
            return "\(program) exited with code \(exitCode): \(detail)"
        case .invalidCommand:
            return "invalid command"
        }
    }
}

protocol ProcessRunning: Sendable {
    func run(executable: String, arguments: [String], wait: Bool) async throws -> ProcessResult?
    func start(executable: String, arguments: [String]) throws -> ProcessHandle
    /// `environment` replaces the child's environment when non-nil.
    func run(executable: String, arguments: [String], wait: Bool, environment: [String: String]?) async throws -> ProcessResult?
    func start(executable: String, arguments: [String], environment: [String: String]?) throws -> ProcessHandle
    /// Like `start`, writing `stdin` to the child's standard input and closing it.
    func start(executable: String, arguments: [String], environment: [String: String]?, stdin: Data?) throws -> ProcessHandle
}

extension ProcessRunning {
    // Fakes that do not care about the environment only implement the two-argument forms.
    func run(executable: String, arguments: [String], wait: Bool, environment: [String: String]?) async throws -> ProcessResult? {
        try await run(executable: executable, arguments: arguments, wait: wait)
    }

    func start(executable: String, arguments: [String], environment: [String: String]?) throws -> ProcessHandle {
        try start(executable: executable, arguments: arguments)
    }

    // Fakes that do not care about stdin drop it.
    func start(executable: String, arguments: [String], environment: [String: String]?, stdin: Data?) throws -> ProcessHandle {
        try start(executable: executable, arguments: arguments, environment: environment)
    }
}

struct SystemProcessRunner: ProcessRunning, Sendable {
    func run(executable: String, arguments: [String], wait: Bool) async throws -> ProcessResult? {
        try await run(executable: executable, arguments: arguments, wait: wait, environment: nil)
    }

    func start(executable: String, arguments: [String]) throws -> ProcessHandle {
        try start(executable: executable, arguments: arguments, environment: nil)
    }

    func run(executable: String, arguments: [String], wait: Bool, environment: [String: String]?) async throws -> ProcessResult? {
        let handle = try start(executable: executable, arguments: arguments, environment: environment)
        guard wait else {
            return nil
        }
        return try await handle.waitAsync()
    }

    func start(executable: String, arguments: [String], environment: [String: String]?) throws -> ProcessHandle {
        try start(executable: executable, arguments: arguments, environment: environment, stdin: nil)
    }

    func start(executable: String, arguments: [String], environment: [String: String]?, stdin: Data?) throws -> ProcessHandle {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        if let environment {
            process.environment = environment
        }
        let command = [executable] + arguments
        process.arguments = command
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
        let stdinPipe = stdin.map { _ in Pipe() }
        if let stdinPipe {
            process.standardInput = stdinPipe
        }
        try process.run()
        if let stdin, let stdinPipe {
            // Written off the caller's thread: a pipe holds only ~64 KiB.
            let writer = stdinPipe.fileHandleForWriting
            DispatchQueue.global(qos: .userInitiated).async {
                try? writer.write(contentsOf: stdin)
                try? writer.close()
            }
        }
        return ProcessHandle(process: process, stdoutPipe: stdoutPipe, stderrPipe: stderrPipe, command: command)
    }
}
