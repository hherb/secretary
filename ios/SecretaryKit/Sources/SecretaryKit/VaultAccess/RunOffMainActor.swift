/// Run a synchronous, CPU-bound (Argon2id) throwing closure off the calling
/// actor on the global concurrent executor, *suspending* the caller rather than
/// blocking it. Used by the real vault open/create adapters so a `@MainActor`
/// caller's UI stays responsive during the KDF.
///
/// Implemented as a `nonisolated` async function on purpose: per SE-0338 it
/// hops off the caller's actor onto the global concurrent executor, runs `work`
/// there, and hops back at the return. The `sending` result is what lets the
/// non-`Sendable` return (`any VaultSession`, a non-`Sendable` `AnyObject`)
/// transfer back across the isolation boundary — `Task.detached` would
/// constrain `Success: Sendable`, and `work` being `@Sendable` means its fresh
/// result is always in a disconnected region, so the transfer is safe. (The
/// create adapter returns the `Sendable` `CreatedVault` and shares this helper
/// purely for consistency.) `work` captures only `Sendable` inputs (`Data` /
/// `[UInt8]` / `URL` / `String`); neither adapter captures `self`.
///
/// This replaced a `withCheckedThrowingContinuation` +
/// `DispatchQueue.global().async` implementation: ThreadSanitizer does not
/// model the happens-before edge that `continuation.resume` establishes between
/// a GCD worker and the resumed task (a known TSan/Swift-concurrency
/// instrumentation gap), so the returned value was flakily reported as a data
/// race by the iOS TSan CI job. Plain executor hops are ordinary
/// TSan-intercepted dispatch enqueues, so this shape carries a visible edge.
/// The handoff was always correctly synchronized; only TSan's view changed.
///
/// If this package ever adopts Swift 6.2's `NonisolatedNonsendingByDefault`
/// upcoming feature, nonisolated async functions run on the *caller's* actor by
/// default — this helper must then be marked `@concurrent` to keep the KDF off
/// the main actor.
nonisolated func runOffMainActor<T>(_ work: @Sendable () throws -> T) async throws -> sending T {
    try work()
}
