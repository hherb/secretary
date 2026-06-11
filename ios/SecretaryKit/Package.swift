// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SecretaryKit",
    platforms: [.iOS(.v17)],
    products: [
        .library(name: "SecretaryKit", targets: ["SecretaryKit"]),
    ],
    dependencies: [
        .package(path: "../SecretaryDeviceUnlock"),
    ],
    targets: [
        .binaryTarget(name: "SecretaryFFI", path: "../Secretary.xcframework"),
        .target(
            name: "SecretaryKit",
            dependencies: [
                "SecretaryFFI",
                .product(name: "SecretaryDeviceUnlock", package: "SecretaryDeviceUnlock"),
            ]
        ),
        .testTarget(
            name: "SecretaryKitTests",
            dependencies: [
                "SecretaryKit",
                .product(name: "SecretaryDeviceUnlockTesting", package: "SecretaryDeviceUnlock"),
            ],
            resources: [
                .copy("Resources/golden_vault_001"),
                .copy("Resources/golden_vault_001_inputs.json"),
            ]
        ),
    ]
)
