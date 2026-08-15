import Foundation

@main
struct NativeParityAudit {
  static func main() {
    guard CommandLine.arguments.count == 5 else {
      fail(
        "Usage: native-parity-audit <src/main.rs> <Components.swift> <MouseEntropy.swift> <Views.swift>"
      )
    }
    let rust = read(CommandLine.arguments[1])
    let swift = read(CommandLine.arguments[2])
    let swiftEntropy = read(CommandLine.arguments[3])
    let swiftViews = read(CommandLine.arguments[4])
    let colors = [
      ("background", 246, 247, 249),
      ("surface", 255, 255, 255),
      ("sidebar", 17, 19, 24),
      ("sidebar text", 248, 248, 250),
      ("sidebar muted", 166, 172, 185),
      ("accent", 82, 82, 204),
      ("accent soft", 238, 238, 255),
      ("accent border", 202, 202, 241),
      ("text", 29, 34, 44),
      ("muted text", 91, 99, 115),
      ("border", 222, 225, 232),
      ("success", 23, 123, 82),
      ("error", 185, 52, 68),
      ("warning", 166, 91, 28),
    ]
    for (name, red, green, blue) in colors {
      let rustValue = "from_rgb(\(red), \(green), \(blue))"
      let swiftValue = "red: \(red) / 255, green: \(green) / 255, blue: \(blue) / 255"
      if !rust.contains(rustValue) || !swift.contains(swiftValue) {
        fail("Rust/Swift \(name) color parity is missing: \(red), \(green), \(blue).")
      }
    }

    let swiftLogoMarkers = [
      "for row in 0..<4",
      "for column in 0..<3",
      "rect(8 + CGFloat(column)",
      "rect(25 + CGFloat(column)",
    ]
    if !swiftLogoMarkers.allSatisfy({ swift.contains($0) }) {
      fail("The native fortress mark no longer contains two sets of twelve mnemonic blocks.")
    }
    if !rust.contains("Twenty-four mnemonic blocks form a fortress around the protected seed.") {
      fail("The Rust fortress mark no longer documents the shared 24-block construction.")
    }

    let entropyThresholds = [
      ("samples", "MOUSE_ENTROPY_TARGET_SAMPLES: u32 = 1_000", "targetSamples = 1_000"),
      ("travel", "MOUSE_ENTROPY_TARGET_DIAGONALS: f32 = 12.0", "targetDiagonals = 12.0"),
      (
        "duration", "MOUSE_ENTROPY_MIN_DURATION: Duration = Duration::from_secs(30)",
        "minimumDuration = 30.0"
      ),
      ("grid columns", "MOUSE_ENTROPY_GRID_COLUMNS: u32 = 8", "gridColumns = 8"),
      ("grid rows", "MOUSE_ENTROPY_GRID_ROWS: u32 = 6", "gridRows = 6"),
      ("coverage", "MOUSE_ENTROPY_TARGET_CELLS: u32 = 36", "targetCells = 36"),
      ("turns", "MOUSE_ENTROPY_TARGET_DIRECTION_CHANGES: u32 = 80", "targetTurns = 80"),
      ("speed ranges", "MOUSE_ENTROPY_TARGET_SPEED_BUCKETS: u32 = 3", "targetSpeedRanges = 3"),
    ]
    for (name, rustMarker, swiftMarker) in entropyThresholds {
      if !rust.contains(rustMarker) || !swiftEntropy.contains(swiftMarker) {
        fail("Rust/Swift mouse entropy \(name) parity is missing.")
      }
    }
    if !swiftViews.contains("mouse-entropy-ceremony")
      || !swiftViews.contains("Movement checks complete—keep moving until the timer ends.")
    {
      fail("The native mouse entropy ceremony UI markers are missing.")
    }
    if !rust.contains("Screen coverage {coverage_percent}%")
      || !swiftViews.contains("Screen coverage \\(coveragePercent)%")
      || rust.contains("Coverage {coverage}/{total_cells}")
      || swiftViews.contains("Coverage \\(session.coverageCount)/\\(session.totalCells)")
    {
      fail("Rust/Swift mouse entropy coverage wording is not percentage-based.")
    }

    print(
      "Native parity audit passed: shared colors, fortress mark, and mouse entropy thresholds."
    )
  }

  private static func read(_ path: String) -> String {
    guard let value = try? String(contentsOfFile: path, encoding: .utf8) else {
      fail("Could not read parity source: \(path)")
    }
    return value
  }

  private static func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
  }
}
