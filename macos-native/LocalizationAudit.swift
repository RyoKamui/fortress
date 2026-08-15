import Foundation

@main
struct LocalizationAudit {
  static func main() {
    let localizedLanguages = AppLanguage.allCases.filter { $0 != .english }
    guard let baselineLanguage = localizedLanguages.first,
      let baseline = AppLanguage.translations[baselineLanguage]
    else {
      fail("No non-English translations are defined.")
    }
    let expectedKeys = Set(baseline.keys)
    if expectedKeys.isEmpty {
      fail("The native interface translation catalog is empty.")
    }

    for language in localizedLanguages {
      guard let catalog = AppLanguage.translations[language] else {
        fail("Missing translation catalog for \(language.rawValue).")
      }
      let keys = Set(catalog.keys)
      let missing = expectedKeys.subtracting(keys).sorted()
      let unexpected = keys.subtracting(expectedKeys).sorted()
      if !missing.isEmpty || !unexpected.isEmpty {
        fail(
          "Translation keys differ for \(language.rawValue). Missing: \(missing). Unexpected: \(unexpected)."
        )
      }
      if let empty = catalog.first(where: {
        $0.value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
      }) {
        fail("Empty translation for \(language.rawValue): \(empty.key)")
      }
    }

    for language in AppLanguage.allCases {
      let topics = language.helpTopics
      if topics.count != 7 {
        fail("\(language.rawValue) has \(topics.count) help topics; expected 7.")
      }
      for topic in topics
      where topic.title.isEmpty || topic.introduction.isEmpty || topic.bullets.count < 3
        || topic.exampleTitle.isEmpty || topic.example.isEmpty
      {
        fail("Incomplete help topic \(topic.id) for \(language.rawValue).")
      }
    }

    if CommandLine.arguments.count == 2 {
      auditRustParity(sourcePath: CommandLine.arguments[1])
    } else if CommandLine.arguments.count > 2 {
      fail("Usage: localization-audit [src/main.rs]")
    }

    print(
      "Native localization audit passed: \(expectedKeys.count) interface strings and 7 help topics in every language."
    )
  }

  private static func auditRustParity(sourcePath: String) {
    guard let source = try? String(contentsOfFile: sourcePath, encoding: .utf8) else {
      fail("Could not read Rust localization source: \(sourcePath)")
    }
    let sections: [(AppLanguage, String, String)] = [
      (.simplifiedChinese, "Self::SimplifiedChinese => match english {", "Self::Japanese => match english {"),
      (.japanese, "Self::Japanese => match english {", "Self::Korean => match english {"),
      (.korean, "Self::Korean => match english {", "_ => english,"),
    ]
    let pattern = #"\"((?:[^\"\\]|\\.)*)\"\s*=>\s*(?:\{\s*)?\"((?:[^\"\\]|\\.)*)\""#
    let regex: NSRegularExpression
    do {
      regex = try NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators])
    } catch {
      fail("Could not create Rust localization parser: \(error)")
    }

    for (language, startMarker, endMarker) in sections {
      guard let start = source.range(of: startMarker),
        let end = source.range(of: endMarker, range: start.upperBound..<source.endIndex),
        let swiftCatalog = AppLanguage.translations[language]
      else {
        fail("Could not locate the Rust localization section for \(language.rawValue).")
      }
      let body = String(source[start.upperBound..<end.lowerBound])
      let nsBody = body as NSString
      let matches = regex.matches(in: body, range: NSRange(location: 0, length: nsBody.length))
      var rustCatalog: [String: String] = [:]
      for match in matches {
        let key = nsBody.substring(with: match.range(at: 1))
        let value = nsBody.substring(with: match.range(at: 2))
        rustCatalog[key] = value
      }
      let mismatches = swiftCatalog.keys.sorted().compactMap { key -> String? in
        guard let rustValue = rustCatalog[key], rustValue != swiftCatalog[key] else { return nil }
        return "\(key): Swift=\(swiftCatalog[key] ?? "") | Rust=\(rustValue)"
      }
      if !mismatches.isEmpty {
        fail("Rust/Swift wording differs for \(language.rawValue):\n" + mismatches.joined(separator: "\n"))
      }
    }
  }

  private static func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
  }
}
