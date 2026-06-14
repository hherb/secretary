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
        } catch let e as VaultAccessError {
            state = .failed(e)
        } catch {
            state = .failed(.other(String(describing: error)))
        }
    }
}
