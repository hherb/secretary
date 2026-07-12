import Foundation
import SecretaryVaultAccess

/// A `WriteReauthGate` that delegates to an inner gate which can be **rebuilt
/// with a new grace window at runtime**. The composition root injects one
/// instance shared by every writer (record edit, trash, settings save), so a
/// settings change to the re-auth grace window takes effect for all of them
/// without re-opening the vault.
///
/// It mirrors Android's `RetargetableReauthGate` (swap-delegate semantics), but
/// iOS gates fix their window at construction (`GraceWindowReauthGate.window` is
/// `let`), so "retarget" means building a *fresh* delegate with the new window.
///
/// **Security ordering — retarget strictly AFTER a successful save.** The
/// caller (the settings view model) awaits `authorizeWrite` against the current
/// (pre-retarget) delegate, persists, and only then calls `retarget(window:)`.
/// The just-completed save is therefore always evaluated against the pre-save
/// window: a user at an unlocked-but-unattended session outside the current
/// grace window cannot widen their own window to self-authorize the widening —
/// the widening still demands a biometric proof. This gate does not itself
/// enforce the sequencing; the after-save ordering is the caller's contract.
///
/// `@MainActor` because it holds a mutable delegate consumed on the main actor
/// alongside the view models, and it constructs `@MainActor` delegate gates.
@MainActor
public final class RetargetableReauthGate: WriteReauthGate {
    private var delegate: WriteReauthGate
    private let clock: () -> MonotonicInstant
    private let makeDelegate: @MainActor (Duration, MonotonicInstant?) -> WriteReauthGate

    /// - Parameters:
    ///   - window: the initial grace window (from persisted settings at open).
    ///   - initialAuthAt: seeds the initial window's last-auth instant (a
    ///     device-unlock open passes `now`; a password open passes `nil`).
    ///   - clock: the monotonic clock used to seed a *retargeted* window.
    ///   - makeDelegate: builds a delegate gate for `(window, seededAuthAt)`.
    ///     Production supplies `{ w, seed in GraceWindowReauthGate(...) }`.
    public init(window: Duration,
                initialAuthAt: MonotonicInstant?,
                clock: @escaping () -> MonotonicInstant,
                makeDelegate: @escaping @MainActor (Duration, MonotonicInstant?) -> WriteReauthGate) {
        self.clock = clock
        self.makeDelegate = makeDelegate
        self.delegate = makeDelegate(window, initialAuthAt)
    }

    public func authorizeWrite(reason: String) async throws {
        try await delegate.authorizeWrite(reason: reason)
    }

    /// Swap to a delegate with a new grace `window`. MUST be called strictly
    /// AFTER a successful (authorized) save — see the type's security note. The
    /// new window is seeded from `clock()` (now): a successful gated save means
    /// the user is authorized at this instant, so opening the new window from
    /// now reflects genuine presence. The security guard is the caller's
    /// after-save ordering, not the seed value.
    public func retarget(window: Duration) {
        delegate = makeDelegate(window, clock())
    }
}
