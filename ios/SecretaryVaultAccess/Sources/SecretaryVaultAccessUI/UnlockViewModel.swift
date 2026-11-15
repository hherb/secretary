import Foundation
import Combine
import SecretaryVaultAccess

/// Drives the unlock screen. Holds only the injected port + vault path, so it is
/// fully host-testable. `@MainActor` because it publishes UI state. The CPU-heavy
/// Argon2id open is offloaded off the main actor by the port implementation, so
/// `unlock` only suspends (it does not block) the main actor while the vault opens.
@MainActor
public final class UnlockViewModel: ObservableObject {
    public enum Mode: Equatable { case password, recovery }

    @Published public private(set) var state: UnlockState = .idle
    /// Which credential the next `unlock` uses. Set by the segmented control.
    public var mode: Mode = .password

    private let port: VaultOpenPort
    private let vaultPath: Data

    public init(port: VaultOpenPort, vaultPath: Data) {
        self.port = port
        self.vaultPath = vaultPath
    }

    /// `secret` is the password bytes (`.password`) or normalized phrase bytes
    /// (`.recovery`). The caller owns clearing the Swift-side copy.
    public func unlock(secret: [UInt8]) async {
        state = .busy
        do {
            let session: VaultSession
            switch mode {
            case .password: session = try await port.openWithPassword(vaultPath: vaultPath, password: secret)
            case .recovery: session = try await port.openWithRecovery(vaultPath: vaultPath, phrase: secret)
            }
            state = .unlocked(session)
        } catch VaultAccessError.rollbackDetected where mode == .password {
            // Only the password path can offer the reset: it needs the master password.
            state = .rollbackResetPrompt
        } catch let e as VaultAccessError {
            state = .failed(e)
        } catch {
            state = .failed(.other(foldDiagnostic(error)))
        }
    }

    /// The user confirmed the rollback prompt: reset this device's sync baseline
    /// and open with `secret` (the master password). A no-op unless the prompt
    /// is showing, so the reset is never reachable without confirmation (#746).
    /// A failure, including a wrong password, lands in `.failed`.
    public func confirmRollbackReset(secret: [UInt8]) async {
        guard case .rollbackResetPrompt = state else { return }
        state = .busy
        do {
            state = .unlocked(try await port.resetSyncStateAndOpen(vaultPath: vaultPath, password: secret))
        } catch let e as VaultAccessError {
            state = .failed(e)
        } catch {
            state = .failed(.other(foldDiagnostic(error)))
        }
    }

    /// The user declined the rollback prompt: back to idle, nothing reset.
    public func cancelRollbackReset() {
        guard case .rollbackResetPrompt = state else { return }
        state = .idle
    }
}

/// Copy for the rollback-reset prompt, shared verbatim with desktop and Android (#746).
public enum RollbackResetCopy {
    public static let title = "This vault looks older than expected"
    public static let body = "This device last saw a newer version of this vault. That can happen after restoring a backup, but it can also mean your storage provider is serving an old copy. Only continue if you restored this vault from a backup or are sure this copy is current."
    public static let confirm = "Reset and open"
    public static let cancel = "Cancel"
}
