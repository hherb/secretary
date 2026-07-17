// swift-tools-version: 6.0
import PackageDescription

// Swift 6 language mode (the tools-version 6.0 default) makes complete
// strict-concurrency checking a hard compile error rather than an opt-in
// warning. This closes the "vacuous concurrency bar" gap from #231 on the
// highest-risk surface — the real uniffi / NSFilePresenter / dispatch adapters —
// where a non-`Sendable` value crossing an actor/`@MainActor` boundary now fails
// the build instead of slipping past minimal checking to manual review.
let package = Package(
    name: "SecretaryKit",
    platforms: [.macOS(.v13), .iOS(.v17)],
    products: [
        .library(name: "SecretaryKit", targets: ["SecretaryKit"]),
    ],
    dependencies: [
        .package(path: "../SecretaryDeviceUnlock"),
        .package(path: "../SecretaryVaultAccess"),
    ],
    targets: [
        .binaryTarget(name: "SecretaryFFI", path: "../Secretary.xcframework"),
        .target(
            name: "SecretaryKit",
            dependencies: [
                "SecretaryFFI",
                .product(name: "SecretaryDeviceUnlock", package: "SecretaryDeviceUnlock"),
                .product(name: "SecretaryDeviceUnlockUI", package: "SecretaryDeviceUnlock"),
                .product(name: "SecretaryVaultAccess", package: "SecretaryVaultAccess"),
                .product(name: "SecretaryVaultAccessUI", package: "SecretaryVaultAccess"),
            ]
        ),
        .testTarget(
            name: "SecretaryKitTests",
            dependencies: [
                "SecretaryKit",
                .product(name: "SecretaryDeviceUnlockTesting", package: "SecretaryDeviceUnlock"),
                .product(name: "SecretaryVaultAccessTesting", package: "SecretaryVaultAccess"),
            ],
            resources: [
                .copy("Resources/golden_vault_001"),
                .copy("Resources/golden_vault_001_inputs.json"),
            ]
        ),
    ]
)
