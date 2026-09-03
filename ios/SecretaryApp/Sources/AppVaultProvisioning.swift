import Foundation

/// Stages a WRITABLE copy of the bundled read-only golden_vault_001 into the app
/// sandbox on first launch (the bundle is read-only; enroll/disenroll mutate the
/// vault). Never touches the bundled fixture. Idempotent.
enum AppVaultProvisioning {
    struct ProvisioningError: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    /// Returns the path to the writable staged vault, copying it on first call.
    ///
    /// SECURITY (audit SC-2): the bundled fixture's inputs JSON carries the
    /// golden vault's master password, recovery mnemonic and secret keys, all
    /// public on GitHub. Self-provisioning it is a DEBUG-only walking-skeleton
    /// affordance; a Release build must never open a vault whose credentials
    /// are published, so it refuses here regardless of what was bundled.
    static func stageGoldenVault() throws -> URL {
        #if !DEBUG
        throw ProvisioningError(message: "golden_vault_001 self-provisioning is debug-only; a release build must open a user-chosen vault")
        #endif
        let fm = FileManager.default
        let support = try fm.url(for: .applicationSupportDirectory,
                                 in: .userDomainMask, appropriateFor: nil, create: true)
        let dest = support.appendingPathComponent("golden_vault_001", isDirectory: true)
        if fm.fileExists(atPath: dest.path) { return dest }

        // Bundled under the "Fixtures" folder reference (not "Resources" — see
        // project.yml; that name breaks on-device codesign).
        guard let bundled = Bundle.main.url(forResource: "golden_vault_001",
                                            withExtension: nil,
                                            subdirectory: "Fixtures") else {
            throw ProvisioningError(message: "golden_vault_001 not bundled — run ios/scripts/build-app.sh")
        }
        try fm.copyItem(at: bundled, to: dest)
        return dest
    }

    /// The pinned vault_uuid (lowercase hex, no dashes) from the bundled inputs
    /// JSON, for the on-screen happy-path assertion.
    static func pinnedVaultUuidHex() throws -> String {
        #if !DEBUG
        throw ProvisioningError(message: "golden_vault_001 inputs are debug-only")
        #endif
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
