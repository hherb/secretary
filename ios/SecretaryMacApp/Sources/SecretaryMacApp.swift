import SwiftUI

@main
struct SecretaryMacApp: App {
    var body: some Scene {
        WindowGroup {
            MacDeviceUnlockView()
        }
        .windowResizability(.contentSize)
    }
}
