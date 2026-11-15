import SwiftUI
import os
import SecretaryKit
import SecretaryVaultAccess

private let macAppLog = Logger(subsystem: "com.secretary.macapp", category: "sync-wiring")

@main
struct SecretaryMacApp: App {
    init() {
        // #746: before any open, so the bridge's rollback check reads the
        // baseline this app's sync writes. A failure leaves the bridge on its
        // `dirs` default, which is the same Application Support path.
        do {
            try installPlatformSyncStateDir()
        } catch {
            macAppLog.error("sync state dir not installed: \(diagnosticDetail(error), privacy: .public)")
        }
    }

    var body: some Scene {
        WindowGroup {
            MacRootView()
        }
        .windowResizability(.contentSize)
    }
}
