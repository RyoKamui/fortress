import AppKit
import SwiftUI

final class FortressAppDelegate: NSObject, NSApplicationDelegate {
  private var mainWindow: NSWindow?

  func applicationDidFinishLaunching(_ notification: Notification) {
    DispatchQueue.main.async {
      guard let window = NSApplication.shared.windows.first else { return }
      self.mainWindow = window
      window.title = "Fortress"
      window.styleMask.remove(.fullSizeContentView)
      window.titleVisibility = .visible
      window.isReleasedWhenClosed = false
      window.setContentSize(NSSize(width: 1320, height: 900))
      window.minSize = NSSize(width: 1080, height: 740)
      window.center()
      window.titlebarAppearsTransparent = false
      window.makeKeyAndOrderFront(nil)
      NSApplication.shared.activate(ignoringOtherApps: true)
    }
  }

  func applicationShouldHandleReopen(
    _ sender: NSApplication, hasVisibleWindows flag: Bool
  ) -> Bool {
    if !flag, let mainWindow {
      mainWindow.makeKeyAndOrderFront(nil)
    }
    return true
  }

  func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    true
  }
}

@main
struct FortressNativeApp: App {
  @NSApplicationDelegateAdaptor(FortressAppDelegate.self) private var appDelegate
  @StateObject private var model = FortressModel()

  var body: some Scene {
    WindowGroup("Fortress") {
      FortressRootView()
        .environmentObject(model)
    }
    .commands {
      CommandGroup(replacing: .help) {
        Button(model.t("Help & safety guide")) {
          model.section = .help
          NSApplication.shared.activate(ignoringOtherApps: true)
        }
        .keyboardShortcut("?", modifiers: .command)
      }
      CommandMenu("Security") {
        Button(model.t("Clear sensitive data")) {
          model.clearSensitiveData()
        }
        .keyboardShortcut(.delete, modifiers: [.command, .shift])
      }
    }
  }
}
