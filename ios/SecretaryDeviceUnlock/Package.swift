// swift-tools-version: 6.0
import PackageDescription

// Swift 6 language mode (the tools-version 6.0 default) makes complete
// strict-concurrency checking a hard compile error rather than an opt-in
// warning. This closes the "vacuous concurrency bar" gap from #231: a
// non-`Sendable` value crossing an actor/`@MainActor` boundary now fails the
// build instead of slipping past minimal checking to manual review.
let package = Package(
    name: "SecretaryDeviceUnlock",
    platforms: [.macOS(.v13), .iOS(.v17)],
    products: [
        .library(name: "SecretaryDeviceUnlock", targets: ["SecretaryDeviceUnlock"]),
        .library(name: "SecretaryDeviceUnlockUI", targets: ["SecretaryDeviceUnlockUI"]),
        .library(name: "SecretaryDeviceUnlockTesting", targets: ["SecretaryDeviceUnlockTesting"]),
    ],
    targets: [
        .target(name: "SecretaryDeviceUnlock"),
        .target(name: "SecretaryDeviceUnlockUI", dependencies: ["SecretaryDeviceUnlock"]),
        .target(name: "SecretaryDeviceUnlockTesting", dependencies: ["SecretaryDeviceUnlock"]),
        .testTarget(
            name: "SecretaryDeviceUnlockTests",
            dependencies: ["SecretaryDeviceUnlock", "SecretaryDeviceUnlockTesting"]
        ),
        .testTarget(
            name: "SecretaryDeviceUnlockUITests",
            dependencies: ["SecretaryDeviceUnlockUI", "SecretaryDeviceUnlockTesting"]
        ),
    ]
)
