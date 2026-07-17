import SwiftUI

@main
struct SecretaryMacApp: App {
    var body: some Scene {
        WindowGroup {
            MacRootView()
        }
        .windowResizability(.contentSize)
    }
}
