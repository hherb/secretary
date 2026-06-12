import Foundation

/// A live, scoped handle to a vault folder. While this object is alive, the
/// underlying platform security scope is held open — which is required because
/// vault block reads are LAZY (they happen during browse, not just at open), so
/// the scope must span the whole session, not just the open call.
///
/// `ScopedVaultPath` is the single owner of one scope acquisition. `end()` releases
/// it exactly once: the `onEnd` closure is dropped after the first call, so any later
/// `end()` is a no-op. This idempotence assumes serial calls — the type is driven from
/// the `@MainActor` UI, where lock and background events are serialized, so they never
/// truly race; the type does not add its own locking. The real
/// adapter injects `onEnd = { url.stopAccessingSecurityScopedResource() }`; the fake
/// injects a counter bump — so the begin/end balance is unit-testable.
public final class ScopedVaultPath {
    /// UTF-8 folder path for the FFI (`open_vault_with_password` / `…recovery`).
    public let pathData: Data
    private var onEnd: (() -> Void)?

    public init(pathData: Data, onEnd: @escaping () -> Void) {
        self.pathData = pathData
        self.onEnd = onEnd
    }

    /// Release the held scope. Idempotent: subsequent calls are no-ops.
    public func end() {
        onEnd?()
        onEnd = nil
    }

    /// Backstop: if the single owner drops this handle without calling `end()`,
    /// release the scope on dealloc so a forgotten `end()` cannot leak it. If
    /// `end()` already ran, `onEnd` is nil and this is a no-op (still exactly-once).
    deinit {
        end()
    }
}
