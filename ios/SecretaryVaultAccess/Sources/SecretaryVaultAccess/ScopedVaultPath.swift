import Foundation

/// A live, scoped handle to a vault folder. While this object is alive, the
/// underlying platform security scope is held open — which is required because
/// vault block reads are LAZY (they happen during browse, not just at open), so
/// the scope must span the whole session, not just the open call.
///
/// `ScopedVaultPath` is the single owner of one scope acquisition. `end()` releases
/// it exactly once (idempotent); the `onEnd` closure is dropped after the first call
/// so a double-`end()` (e.g. lock racing background) cannot double-release. The real
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
}
