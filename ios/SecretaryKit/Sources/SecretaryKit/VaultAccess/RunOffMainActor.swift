import Foundation

/// Run a synchronous, CPU-bound (Argon2id) throwing closure off the calling
/// actor on a user-initiated global queue, *suspending* the caller rather than
/// blocking it. Used by the real vault open/create adapters so a `@MainActor`
/// caller's UI stays responsive during the KDF.
///
/// Implemented with `withCheckedThrowingContinuation` (not `Task.detached`) on
/// purpose: `Task<Success, _>` constrains `Success: Sendable`, but the open
/// adapter returns `any VaultSession` (a non-`Sendable` `AnyObject`), which would
/// emit a Swift-5.9 Sendable warning. `CheckedContinuation`'s result type is
/// unconstrained, so the freshly-built session transfers back across the
/// suspension cleanly. `work` is `@Sendable` and captures only `Sendable` inputs
/// (`Data` / `[UInt8]` / `URL` / `String`); neither adapter captures `self`.
func runOffMainActor<T>(_ work: @escaping @Sendable () throws -> T) async throws -> T {
    try await withCheckedThrowingContinuation { continuation in
        DispatchQueue.global(qos: .userInitiated).async {
            do { continuation.resume(returning: try work()) }
            catch { continuation.resume(throwing: error) }
        }
    }
}
