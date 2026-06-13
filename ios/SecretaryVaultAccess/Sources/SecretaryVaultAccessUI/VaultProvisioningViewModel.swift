import Foundation
import Combine
import SecretaryVaultAccess

/// Drives the create-vault wizard over a `VaultCreatePort` and persists the new
/// location via a `VaultLocationStore`. Holds only injected ports, so it is fully
/// host-testable. `@MainActor` because it publishes UI state; like `UnlockViewModel`,
/// the CPU-heavy Argon2id create briefly blocks the main actor on the create path
/// (accepted for this slice; background-offload is a noted follow-up).
@MainActor
public final class VaultProvisioningViewModel: ObservableObject {
    @Published public private(set) var step: VaultProvisioningStep = .folder
    @Published public private(set) var nameError: VaultNameError?
    @Published public private(set) var error: VaultProvisioningError?
    /// Numbered words for the mnemonic step; `nil` outside that step or after ack.
    @Published public private(set) var mnemonicRows: [MnemonicWord]?

    private let createPort: VaultCreatePort
    private let store: VaultLocationStore
    /// The one-shot recovery phrase, held only between create and acknowledge.
    private var phrase: [UInt8]?

    public init(createPort: VaultCreatePort, store: VaultLocationStore) {
        self.createPort = createPort
        self.store = store
    }

    /// Validate the typed name and advance to the credentials step. On an invalid
    /// name, stay on `.folder` and publish `nameError`.
    public func chooseParent(_ parent: URL, vaultName: String) {
        error = nil
        switch validateVaultName(vaultName) {
        case .invalid(let e):
            nameError = e
        case .valid(let name):
            nameError = nil
            step = .credentials(parent: parent, vaultName: name)
        }
    }

    /// Create the vault: confirm-match the password, call the port, persist the
    /// location BEFORE revealing the phrase (so a crash mid-flow leaves an openable
    /// vault), then advance to the mnemonic step. The caller owns clearing its own
    /// Swift-side `password`/`confirm` copies after this returns.
    public func create(displayName: String, password: [UInt8], confirm: [UInt8]) async {
        guard case .credentials(let parent, let vaultName) = step else { return }
        error = nil
        guard passwordsMatch(password, confirm) else {
            error = .passwordMismatch
            return
        }
        do {
            var created = try createPort.create(parent: parent,
                                                vaultName: vaultName,
                                                password: password,
                                                displayName: displayName)
            store.persist(created.location)            // persist BEFORE mnemonic
            phrase = created.phrase
            mnemonicRows = groupMnemonic(String(decoding: created.phrase, as: UTF8.self))
            created.phrase.resetBytes(in: created.phrase.indices)  // wipe the local copy
            step = .mnemonic
        } catch let e as VaultProvisioningError {
            error = e
        } catch {
            self.error = .createFailed(String(describing: error))
        }
    }

    /// Abandon the wizard (Cancel / leave): scrub the retained recovery phrase
    /// and clear its on-screen rows. The host then dismisses the wizard. Safe to
    /// call from any step.
    public func cancel() {
        if phrase != nil { phrase!.resetBytes(in: phrase!.indices) }
        phrase = nil
        mnemonicRows = nil
    }

    deinit {
        if phrase != nil { phrase!.resetBytes(in: phrase!.indices) }
    }

    /// User confirmed they wrote down the phrase: wipe the retained phrase + the
    /// display rows, and complete. `.done` carries the persisted location so the
    /// host can route to the unlock screen.
    public func acknowledgeMnemonic() {
        guard case .mnemonic = step else { return }
        if phrase != nil { phrase!.resetBytes(in: phrase!.indices) }
        phrase = nil
        mnemonicRows = nil
        if let loc = store.load() {
            step = .done(loc)
        } else {
            // The location was persisted during create; a nil load now is a real
            // store fault. Surface it rather than stranding the user on an
            // unrenderable mnemonic step (no silent failures).
            error = .createFailed("vault location unavailable after create")
        }
    }
}

private extension Array where Element == UInt8 {
    /// Overwrite the byte range with zeros in place (best-effort scrubbing of a
    /// secret buffer; value-type copies elsewhere are out of scope here).
    mutating func resetBytes(in range: Range<Int>) {
        for i in range { self[i] = 0 }
    }
}
