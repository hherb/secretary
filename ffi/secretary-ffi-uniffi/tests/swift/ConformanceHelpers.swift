// Input resolution + hex codec + filesystem + after-chain walkers.
//
// Pure helpers — no test state. Mirrors helpers in
// core/tests/conformance_kat_helpers/fixtures.rs (Rust) and
// ConformanceHelpers.kt (Kotlin).

import Foundation

// --- Input resolution helpers ---

func resolveSource(_ source: String, goldenVaultDir: String) -> Data {
    let parts = source.split(separator: ":", maxSplits: 1)
    guard parts.count == 2 else {
        FileHandle.standardError.write(Data("malformed source ref: \(source)\n".utf8))
        exit(1)
    }
    let file = URL(fileURLWithPath: goldenVaultDir).appendingPathComponent(String(parts[0]))
    let field = String(parts[1])
    guard let bytes = try? Data(contentsOf: file),
        let obj = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
        let str = obj[field] as? String
    else {
        FileHandle.standardError.write(Data("failed to resolve \(source)\n".utf8))
        exit(1)
    }
    return Data(str.utf8)
}

func resolveVaultDir(_ inputs: [String: Any], goldenVaultDir: String) -> Data {
    if let s = inputs["vault_dir"] as? String {
        let url = URL(fileURLWithPath: goldenVaultDir).appendingPathComponent(s)
        return Data(url.path.utf8)
    }
    if let s = inputs["vault_dir_literal"] as? String {
        return Data(s.utf8)
    }
    FileHandle.standardError.write(Data("vector inputs missing vault_dir / vault_dir_literal\n".utf8))
    exit(1)
}

func resolvePassword(_ inputs: [String: Any], goldenVaultDir: String) -> Data {
    if let s = inputs["password_source"] as? String { return resolveSource(s, goldenVaultDir: goldenVaultDir) }
    if let s = inputs["password_literal_utf8"] as? String { return Data(s.utf8) }
    FileHandle.standardError.write(Data("vector inputs missing password_*\n".utf8))
    exit(1)
}

func resolveMnemonic(_ inputs: [String: Any], goldenVaultDir: String) -> Data {
    if let s = inputs["mnemonic_source"] as? String { return resolveSource(s, goldenVaultDir: goldenVaultDir) }
    if let s = inputs["mnemonic_literal_utf8"] as? String { return Data(s.utf8) }
    FileHandle.standardError.write(Data("vector inputs missing mnemonic_*\n".utf8))
    exit(1)
}

// --- Hex codec ---

func decodeHex(_ s: String) -> Data {
    var bytes: [UInt8] = []
    let chars = Array(s)
    var i = 0
    while i + 1 < chars.count {
        guard let b = UInt8(String(chars[i]) + String(chars[i + 1]), radix: 16) else {
            FileHandle.standardError.write(Data("malformed hex: \(s)\n".utf8))
            exit(1)
        }
        bytes.append(b)
        i += 2
    }
    return Data(bytes)
}

func encodeHex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

// --- v2 filesystem helpers ---

func recursiveCopy(_ from: URL, _ to: URL) throws {
    try FileManager.default.createDirectory(at: to, withIntermediateDirectories: true)
    for entry in try FileManager.default.contentsOfDirectory(at: from, includingPropertiesForKeys: nil) {
        var isDir: ObjCBool = false
        FileManager.default.fileExists(atPath: entry.path, isDirectory: &isDir)
        let dest = to.appendingPathComponent(entry.lastPathComponent)
        if isDir.boolValue {
            try recursiveCopy(entry, dest)
        } else {
            try FileManager.default.copyItem(at: entry, to: dest)
        }
    }
}

func readContactCardBytes(_ vaultDir: URL, _ userUuidHex: String) throws -> Data {
    precondition(userUuidHex.count == 32, "userUuidHex must be 32 chars")
    let h = userUuidHex
    let s8 = h.index(h.startIndex, offsetBy: 8)
    let s12 = h.index(h.startIndex, offsetBy: 12)
    let s16 = h.index(h.startIndex, offsetBy: 16)
    let s20 = h.index(h.startIndex, offsetBy: 20)
    let hyphenated = "\(h[..<s8])-\(h[s8..<s12])-\(h[s12..<s16])-\(h[s16..<s20])-\(h[s20...]).card"
    let path = vaultDir.appendingPathComponent("contacts").appendingPathComponent(hyphenated)
    return try Data(contentsOf: path)
}

// --- after-chain walkers ---

func findWritableDir(_ start: String, writableVaultDirs: [String: URL], vectors: [[String: Any]]) -> URL? {
    var current = start
    // Bounded by vectors.count — an authoring-error `after:` cycle would
    // otherwise hang. Fail loudly so the cycle is fixable, not silent.
    for _ in 0...vectors.count {
        if let url = writableVaultDirs[current] { return url }
        guard let parentAfter = vectors.first(where: { ($0["name"] as? String) == current })?["after"] as? String else {
            return nil
        }
        current = parentAfter
    }
    fatalError("after-chain cycle detected starting at '\(start)' (depth exceeded vectors.count)")
}

func findCacheAncestorName(_ start: String, cache: [String: OpenVaultOutput], vectors: [[String: Any]]) -> String? {
    var current = start
    // Cycle guard: see findWritableDir.
    for _ in 0...vectors.count {
        if cache[current] != nil { return current }
        guard let parentAfter = vectors.first(where: { ($0["name"] as? String) == current })?["after"] as? String else {
            return nil
        }
        current = parentAfter
    }
    fatalError("after-chain cycle detected starting at '\(start)' (depth exceeded vectors.count)")
}
