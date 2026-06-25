import Foundation

/// Overwrite every byte of `data` in place. Pure; post-condition: all bytes are
/// zero. Mirrors the Rust core's `Sensitive<T>`/`SecretBytes` discipline at the
/// one heap copy the Swift FFI boundary owns. No-op on empty data (#229).
func zeroize(_ data: inout Data) {
    guard !data.isEmpty else { return }
    data.resetBytes(in: 0..<data.count)
}

/// Build a `Data` from `bytes`, hand it to `body`, and scrub that `Data` on the
/// way out — the `defer` fires on both a normal return and a thrown error, so the
/// FFI-boundary copy never lingers in the heap.
///
/// Scope/limitation: this scrubs the adapter-owned `Data` copy only. It does NOT
/// scrub the caller's `bytes` array — Swift arrays are copy-on-write, so mutating
/// our binding would allocate a throwaway buffer and leave the caller's storage
/// intact. The caller's lifetime is minimized separately by the "password passed
/// per call, never stored" port discipline (#229).
func withZeroizingData<T>(_ bytes: [UInt8], _ body: (Data) throws -> T) rethrows -> T {
    var data = Data(bytes)
    defer { zeroize(&data) }
    return try body(data)
}
