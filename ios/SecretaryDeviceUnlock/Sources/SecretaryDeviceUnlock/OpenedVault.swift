/// An opened vault, abstracted so the pure package never names the uniffi
/// `OpenVaultOutput`. The real adapter conforms `OpenVaultOutput` to this.
///
/// `Sendable` because `DeviceUnlockCoordinator.unlock` returns it from a
/// nonisolated `async` context back to a `@MainActor` caller (#231).
public protocol OpenedVault: Sendable {
    var vaultUuid: [UInt8] { get }
    /// Release the manifest/identity secret material held by the opened vault.
    func wipe()
}
