import AppKit
import Combine
import CryptoKit
import Foundation

final class MouseEntropySession: ObservableObject {
  static let targetSamples = 1_000
  static let targetDiagonals = 12.0
  static let minimumDuration = 30.0
  static let gridColumns = 8
  static let gridRows = 6
  static let targetCells = 36
  static let targetTurns = 80
  static let targetSpeedRanges = 3
  static let trailLimit = 96

  @Published private(set) var elapsed = 0.0
  @Published private(set) var sampleCount = 0
  @Published private(set) var travelDistance = 0.0
  @Published private(set) var coveredCells: UInt64 = 0
  @Published private(set) var turnCount = 0
  @Published private(set) var speedRanges: UInt8 = 0
  @Published private(set) var trail: [CGPoint] = []

  private weak var window: NSWindow?
  private var eventMonitor: Any?
  private var timer: Timer?
  private var startedAt = ProcessInfo.processInfo.systemUptime
  private var lastSampleAt = ProcessInfo.processInfo.systemUptime
  private var lastPosition: CGPoint?
  private var previousDirection: CGPoint?
  private var viewport = CGSize.zero
  private var enteredFullscreen = false
  private var previousAcceptsMouseMovedEvents = false
  private var pool = Data(SHA256.hash(data: Data("Fortress native mouse event pool v1".utf8)))

  init(window: NSWindow?) {
    self.window = window
  }

  var progress: Double {
    min(max(elapsed / Self.minimumDuration, 0), 1)
  }

  var coverageCount: Int { coveredCells.nonzeroBitCount }
  var speedRangeCount: Int { speedRanges.nonzeroBitCount }
  var totalCells: Int { Self.gridColumns * Self.gridRows }

  var travelInDiagonals: Double {
    travelDistance / max(hypot(Double(viewport.width), Double(viewport.height)), 1)
  }

  var movementRequirementsMet: Bool {
    sampleCount >= Self.targetSamples
      && travelInDiagonals >= Self.targetDiagonals
      && coverageCount >= Self.targetCells
      && turnCount >= Self.targetTurns
      && speedRangeCount >= Self.targetSpeedRanges
  }

  var isReady: Bool {
    elapsed >= Self.minimumDuration && movementRequirementsMet
  }

  func start() {
    let now = ProcessInfo.processInfo.systemUptime
    startedAt = now
    lastSampleAt = now
    if let window {
      window.makeFirstResponder(nil)
      previousAcceptsMouseMovedEvents = window.acceptsMouseMovedEvents
      window.acceptsMouseMovedEvents = true
      if !window.styleMask.contains(.fullScreen) {
        enteredFullscreen = true
        window.toggleFullScreen(nil)
      }
    }

    let mask: NSEvent.EventTypeMask = [
      .mouseMoved, .leftMouseDragged, .rightMouseDragged, .otherMouseDragged,
    ]
    eventMonitor = NSEvent.addLocalMonitorForEvents(matching: mask) { [weak self] event in
      self?.absorb(event)
      return event
    }
    let timer = Timer(timeInterval: 1.0 / 30.0, repeats: true) { [weak self] _ in
      self?.tick()
    }
    self.timer = timer
    RunLoop.main.add(timer, forMode: .common)
  }

  func stop(restoreWindow: Bool) {
    if let eventMonitor {
      NSEvent.removeMonitor(eventMonitor)
      self.eventMonitor = nil
    }
    timer?.invalidate()
    timer = nil
    if let window {
      window.acceptsMouseMovedEvents = previousAcceptsMouseMovedEvents
      if restoreWindow && enteredFullscreen && window.styleMask.contains(.fullScreen) {
        window.toggleFullScreen(nil)
      }
    }
    enteredFullscreen = false
  }

  func discardDigest() {
    if !pool.isEmpty {
      pool.resetBytes(in: 0..<pool.count)
      pool.removeAll(keepingCapacity: false)
    }
  }

  func finalizeHex() -> String {
    var input = Data("Fortress native mouse entropy final v1".utf8)
    input.append(pool)
    appendUInt64(UInt64(sampleCount), to: &input)
    appendDouble(travelDistance, to: &input)
    appendUInt64(coveredCells, to: &input)
    appendUInt64(UInt64(turnCount), to: &input)
    input.append(speedRanges)
    appendUInt64(UInt64(elapsed * 1_000_000_000), to: &input)
    let digest = Data(SHA256.hash(data: input))
    input.resetBytes(in: 0..<input.count)
    discardDigest()
    return digest.map { String(format: "%02x", $0) }.joined()
  }

  private func tick() {
    elapsed = max(ProcessInfo.processInfo.systemUptime - startedAt, 0)
  }

  private func absorb(_ event: NSEvent) {
    guard event.window === window, let contentView = window?.contentView else { return }
    let position = event.locationInWindow
    let size = contentView.bounds.size
    guard position.x.isFinite, position.y.isFinite, size.width > 0, size.height > 0 else {
      return
    }

    let now = ProcessInfo.processInfo.systemUptime
    let sampleElapsed = max(now - startedAt, 0)
    let timingDelta = max(now - lastSampleAt, 0)
    let distance = lastPosition.map { hypot(position.x - $0.x, position.y - $0.y) } ?? 0
    if lastPosition != nil && distance < 0.75 { return }

    var direction: CGPoint?
    if let lastPosition, distance > 0 {
      direction = CGPoint(
        x: (position.x - lastPosition.x) / distance,
        y: (position.y - lastPosition.y) / distance)
    }
    if let previousDirection, let direction,
      previousDirection.x * direction.x + previousDirection.y * direction.y < 0.8
    {
      turnCount += 1
    }
    if distance > 0 && timingDelta > 0 {
      let speed = Double(distance) / timingDelta
      let bucket: Int
      if speed < 250 {
        bucket = 0
      } else if speed < 750 {
        bucket = 1
      } else if speed < 2_000 {
        bucket = 2
      } else {
        bucket = 3
      }
      speedRanges |= UInt8(1 << bucket)
    }

    let column = min(
      Int(min(max(position.x / size.width, 0), 0.999_999) * CGFloat(Self.gridColumns)),
      Self.gridColumns - 1)
    let row = min(
      Int(min(max(position.y / size.height, 0), 0.999_999) * CGFloat(Self.gridRows)),
      Self.gridRows - 1)
    coveredCells |= UInt64(1) << UInt64(row * Self.gridColumns + column)

    var input = Data("Fortress native mouse pointer sample v1".utf8)
    input.append(pool)
    appendDouble(Double(position.x), to: &input)
    appendDouble(Double(position.y), to: &input)
    appendDouble(Double(size.width), to: &input)
    appendDouble(Double(size.height), to: &input)
    appendDouble(Double(distance), to: &input)
    appendUInt64(UInt64(sampleElapsed * 1_000_000_000), to: &input)
    appendUInt64(UInt64(timingDelta * 1_000_000_000), to: &input)
    appendUInt64(UInt64(sampleCount), to: &input)
    appendUInt64(coveredCells, to: &input)
    appendUInt64(UInt64(turnCount), to: &input)
    input.append(speedRanges)
    pool = Data(SHA256.hash(data: input))
    input.resetBytes(in: 0..<input.count)

    lastSampleAt = now
    lastPosition = position
    previousDirection = direction
    viewport = size
    sampleCount += 1
    travelDistance += Double(distance)
    if trail.count == Self.trailLimit { trail.removeFirst() }
    trail.append(position)
  }

  private func appendUInt64(_ value: UInt64, to data: inout Data) {
    var littleEndian = value.littleEndian
    Swift.withUnsafeBytes(of: &littleEndian) { bytes in
      data.append(contentsOf: bytes)
    }
  }

  private func appendDouble(_ value: Double, to data: inout Data) {
    appendUInt64(value.bitPattern, to: &data)
  }
}
