/// This device's per-device wrap slot (ADR 0009), as the UI layer needs it.
///
/// Deliberately two members and deliberately named `forgetThisDevice()` rather
/// than `removeDeviceSlot(uuid:)`: there is NO slot-enumeration API at any layer
/// — not in `core/src/vault/device_slot.rs`, the FFI bridge, the `.udl`, or
/// `VaultDeviceSlotPort` — so self-removal is the only expressible operation and
/// the name must not imply a device manager that cannot exist.
///
/// This protocol lives in the pure package so the shared, host-tested
/// `DeviceSlotViewModel` can drive a device-slot operation without
/// `SecretaryVaultAccess` gaining a dependency on `SecretaryDeviceUnlock` (the
/// two are deliberately disjoint; they meet only at the app target). The real
/// conformer is `CoordinatorDeviceSlotPort` in SecretaryKit.
public protocol DeviceSlotPort: Sendable {
    /// True iff this device currently holds a usable slot (enclave key AND
    /// enrollment metadata). Reads the Keychain plus an enclave probe, so callers
    /// snapshot it rather than polling it per render.
    var isEnrolled: Bool { get }

    /// Revoke this device's slot: delete the wrap file, then clear the enclave key
    /// and enrollment metadata. Needs neither the master password nor an open
    /// vault. Idempotent in practice — the underlying coordinator tolerates an
    /// already-gone slot and clears local state unconditionally, so a retry after
    /// a partial failure converges instead of stranding an orphan.
    func forgetThisDevice() throws
}
