import XCTest
import Foundation

/// The pinned golden-vault UUID (lowercase hex, no dashes) read from the bundled
/// inputs JSON — the single source of truth, so tests stay honest if the fixture
/// is regenerated. Shared across SecretaryKitTests (was duplicated per file).
func goldenPinnedVaultUuidHex() throws -> String {
    let url = try XCTUnwrap(
        Bundle.module.url(forResource: "golden_vault_001_inputs", withExtension: "json"))
    let json = try JSONSerialization.jsonObject(with: Data(contentsOf: url))
    let dict = try XCTUnwrap(json as? [String: Any])
    let dashed = try XCTUnwrap(dict["vault_uuid"] as? String)
    return dashed.replacingOccurrences(of: "-", with: "").lowercased()
}
