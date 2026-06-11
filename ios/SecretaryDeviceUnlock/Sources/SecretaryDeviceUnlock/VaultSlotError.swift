/// Pure mirror of the device-slot FFI error surface. The real adapter maps the
/// uniffi `VaultError` onto these so the FFI-free package can pattern-match.
public enum VaultSlotError: Error, Equatable {
    case deviceSlotNotFound
    case wrongDeviceSecretOrCorrupt
    case deviceUuidMismatch(String)
    case invalidArgument(String)
    /// Any other `VaultError`, carried as its display string.
    case other(String)
}
