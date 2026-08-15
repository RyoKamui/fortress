import Foundation

@main
struct BridgeAudit {
  static func main() {
    guard CommandLine.arguments.count == 2 else {
      fail("Usage: bridge-audit /path/to/fortress-core")
    }

    let bridge = FortressBridge(
      helperURL: URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: false))
    let health = waitForReply(
      from: bridge,
      request: ["operation": "health"],
      label: "health")
    guard health["native_bridge"] as? Int == 1 else {
      fail("Native bridge health response has the wrong protocol version.")
    }

    let validation = waitForReply(
      from: bridge,
      request: [
        "operation": "validate_mnemonic",
        "language": "English",
        "phrase":
          "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
      ],
      label: "mnemonic validation")
    guard validation["valid"] as? Bool == true, validation["word_count"] as? Int == 12 else {
      fail("Native bridge mnemonic validation returned an unexpected result.")
    }

    let mouseGeneration = waitForReply(
      from: bridge,
      request: [
        "operation": "generate_mnemonic",
        "language": "English",
        "word_count": 24,
        "mouse_entropy_hex": String(repeating: "a5", count: 32),
      ],
      label: "mouse-assisted mnemonic generation")
    guard
      mouseGeneration["word_count"] as? Int == 24,
      let phrase = mouseGeneration["phrase"] as? String,
      phrase.split(whereSeparator: { $0.isWhitespace }).count == 24
    else {
      fail("Native bridge mouse-assisted generation returned an unexpected result.")
    }

    print("Native Swift-to-Rust bridge audit passed, including mouse-assisted generation.")
  }

  private static func waitForReply(
    from bridge: FortressBridge, request: [String: Any], label: String
  ) -> [String: Any] {
    var reply: Result<[String: Any], Error>?
    bridge.call(request) { result in
      reply = result
    }

    let deadline = Date().addingTimeInterval(15)
    while reply == nil, Date() < deadline {
      RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.02))
    }
    guard let reply else {
      fail("Native bridge \(label) request timed out.")
    }
    switch reply {
    case .success(let value): return value
    case .failure(let error): fail("Native bridge \(label) request failed: \(error)")
    }
  }

  private static func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
  }
}
