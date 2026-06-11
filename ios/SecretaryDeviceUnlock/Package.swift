// swift-tools-version: 5.9
import PackageDescription

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
