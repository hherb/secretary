// swift-tools-version: 6.0
import PackageDescription

// Swift 6 language mode (the tools-version 6.0 default) makes complete
// strict-concurrency checking a hard compile error rather than an opt-in
// warning. This closes the "vacuous concurrency bar" gap from #231: a
// non-`Sendable` value crossing an actor/`@MainActor` boundary now fails the
// build instead of slipping past minimal checking to manual review.
let package = Package(
    name: "SecretaryVaultAccess",
    platforms: [.macOS(.v13), .iOS(.v17)],
    products: [
        .library(name: "SecretaryVaultAccess", targets: ["SecretaryVaultAccess"]),
        .library(name: "SecretaryVaultAccessUI", targets: ["SecretaryVaultAccessUI"]),
        .library(name: "SecretaryVaultAccessTesting", targets: ["SecretaryVaultAccessTesting"]),
    ],
    targets: [
        .target(name: "SecretaryVaultAccess"),
        .target(name: "SecretaryVaultAccessUI", dependencies: ["SecretaryVaultAccess"]),
        .target(name: "SecretaryVaultAccessTesting", dependencies: ["SecretaryVaultAccess"]),
        .testTarget(
            name: "SecretaryVaultAccessTests",
            dependencies: ["SecretaryVaultAccess", "SecretaryVaultAccessTesting"]
        ),
        .testTarget(
            name: "SecretaryVaultAccessUITests",
            dependencies: ["SecretaryVaultAccessUI", "SecretaryVaultAccessTesting"]
        ),
    ]
)
