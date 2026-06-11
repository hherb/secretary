import Foundation

/// Overwrite `bytes` with zeros in place. Best-effort secret hygiene: it clears
/// only this array's backing buffer, so any *other* copies a caller made (e.g.
/// passed across the FFI) are out of reach. Swift's value-copy semantics make
/// full guarantees impossible — see the spec's zeroization note.
public func zeroize(_ bytes: inout [UInt8]) {
    bytes.withUnsafeMutableBytes { raw in
        guard let base = raw.baseAddress, raw.count > 0 else { return }
        memset_s(base, raw.count, 0, raw.count)
    }
}
