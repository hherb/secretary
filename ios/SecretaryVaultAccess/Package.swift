// swift-tools-version: 5.9
import PackageDescription

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
