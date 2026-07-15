import Foundation

/// Stages a WRITABLE copy of the bundled read-only golden_vault_001 into
/// Application Support on first launch (the bundle is read-only; enroll/disenroll
/// mutate the vault). Never touches the bundled fixture. Idempotent.
enum MacVaultProvisioning {
    struct ProvisioningError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    /// Returns the path to the writable staged vault, copying it on first call.
    static func stageGoldenVault() throws -> URL {
        let fm = FileManager.default
        let support = try fm.url(for: .applicationSupportDirectory,
                                 in: .userDomainMask, appropriateFor: nil, create: true)
        let dest = support.appendingPathComponent("golden_vault_001", isDirectory: true)
        if fm.fileExists(atPath: dest.path) { return dest }

        guard let bundled = Bundle.main.url(forResource: "golden_vault_001",
                                            withExtension: nil,
                                            subdirectory: "Fixtures") else {
            throw ProvisioningError(message: "golden_vault_001 not bundled — run ios/scripts/build-macos-app.sh")
        }
        try fm.copyItem(at: bundled, to: dest)
        return dest
    }

    /// The pinned vault_uuid (lowercase hex, no dashes) — used as `vaultId` so the
    /// post-open check (`session.vaultUuidHex == enrolledVaultId`) passes, and as
    /// the on-screen happy-path assertion.
    static func pinnedVaultUuidHex() throws -> String {
        guard let url = Bundle.main.url(forResource: "golden_vault_001_inputs",
                                        withExtension: "json",
                                        subdirectory: "Fixtures") else {
            throw ProvisioningError(message: "golden_vault_001_inputs.json not bundled")
        }
        let json = try JSONSerialization.jsonObject(with: Data(contentsOf: url))
        guard let dict = json as? [String: Any], let dashed = dict["vault_uuid"] as? String else {
            throw ProvisioningError(message: "vault_uuid missing from inputs JSON")
        }
        return dashed.replacingOccurrences(of: "-", with: "").lowercased()
    }
}
