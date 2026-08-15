import Foundation

enum BridgeFailure: LocalizedError {
  case unavailable(String)
  case rejected(String)
  case malformed(String)

  var errorDescription: String? {
    switch self {
    case .unavailable(let message), .rejected(let message), .malformed(let message):
      return message
    }
  }
}

/// A single long-lived Rust helper process. Requests are newline-delimited JSON
/// written to stdin, so seed material never appears in argv or environment data.
/// Calls are serialized to keep the protocol deterministic and to retain the
/// authenticated age update selected during application startup.
final class FortressBridge {
  private let process = Process()
  private let input = Pipe()
  private let output = Pipe()
  private let diagnostics = Pipe()
  private let queue = DispatchQueue(label: "dev.local.fortress.native-bridge")
  private var outputBuffer = Data()
  private var launchError: Error?

  init(helperURL: URL? = nil) {
    let helper: URL
    if let helperURL {
      helper = helperURL
    } else if let executableDirectory = Bundle.main.executableURL?.deletingLastPathComponent() {
      helper = executableDirectory.appendingPathComponent("fortress-core")
    } else {
      launchError = BridgeFailure.unavailable("Could not locate the Fortress application bundle.")
      return
    }
    process.executableURL = helper
    process.arguments = ["--native-bridge"]
    process.standardInput = input
    process.standardOutput = output
    process.standardError = diagnostics
    diagnostics.fileHandleForReading.readabilityHandler = { handle in
      _ = handle.availableData
    }
    do {
      try process.run()
    } catch {
      launchError = BridgeFailure.unavailable(
        "Could not start the protected Rust core: \(error.localizedDescription)")
    }
  }

  deinit {
    diagnostics.fileHandleForReading.readabilityHandler = nil
    try? input.fileHandleForWriting.close()
    if process.isRunning {
      process.terminate()
    }
  }

  func call(_ request: [String: Any], completion: @escaping (Result<[String: Any], Error>) -> Void)
  {
    queue.async { [weak self] in
      guard let self else { return }
      let result: Result<[String: Any], Error>
      do {
        if let launchError = self.launchError {
          throw launchError
        }
        guard self.process.isRunning else {
          throw BridgeFailure.unavailable("The protected Rust core is not running.")
        }
        var payload = try JSONSerialization.data(withJSONObject: request)
        defer { payload.resetBytes(in: 0..<payload.count) }
        payload.append(0x0A)
        try self.input.fileHandleForWriting.write(contentsOf: payload)
        var responseData = try self.readLine()
        defer { responseData.resetBytes(in: 0..<responseData.count) }
        guard
          let envelope = try JSONSerialization.jsonObject(with: responseData) as? [String: Any],
          let ok = envelope["ok"] as? Bool
        else {
          throw BridgeFailure.malformed("The protected Rust core returned an invalid response.")
        }
        if ok, let response = envelope["result"] as? [String: Any] {
          result = .success(response)
        } else {
          let message =
            envelope["error"] as? String ?? "The protected Rust core rejected the request."
          result = .failure(BridgeFailure.rejected(message))
        }
      } catch {
        result = .failure(error)
      }
      DispatchQueue.main.async {
        completion(result)
      }
    }
  }

  private func readLine() throws -> Data {
    while true {
      if let newline = outputBuffer.firstIndex(of: 0x0A) {
        let line = Data(outputBuffer.prefix(upTo: newline))
        outputBuffer.resetBytes(in: outputBuffer.startIndex...newline)
        outputBuffer.removeSubrange(...newline)
        return line
      }
      // `readData(ofLength:)` waits for the full requested byte count on a
      // pipe. Bridge replies are normally much smaller than 4096 bytes, so
      // using it here deadlocks both processes: Swift waits for padding that
      // will never arrive while Rust waits for the next request. `availableData`
      // blocks only until some bytes arrive, then returns the currently
      // available chunk so the newline framing above can make progress.
      let chunk = output.fileHandleForReading.availableData
      if chunk.isEmpty {
        throw BridgeFailure.unavailable("The protected Rust core closed unexpectedly.")
      }
      outputBuffer.append(chunk)
      if outputBuffer.count > 32 * 1024 * 1024 {
        throw BridgeFailure.malformed("The protected Rust core returned too much data.")
      }
    }
  }
}
