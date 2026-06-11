/// An opened vault, abstracted so the pure package never names the uniffi
/// `OpenVaultOutput`. The real adapter conforms `OpenVaultOutput` to this.
public protocol OpenedVault {
    var vaultUuid: [UInt8] { get }
    /// Release the manifest/identity secret material held by the opened vault.
    func wipe()
}
