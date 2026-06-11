//! uniffi-side device-slot handles: DeviceSecretOutput (one-shot) + the
//! DeviceEnrollOutput dictionary. Thin forwarders to the bridge handles.

/// uniffi opaque one-shot handle around `bridge::DeviceSecretOutput`.
/// `take_secret()` returns Some once then null; `wipe()` idempotent.
/// Same close→wipe rename rationale as MnemonicOutput: uniffi 0.31's
/// Kotlin codegen auto-generates `AutoCloseable.close()` on every
/// interface, and a UDL-declared `close()` would collide with it.
pub struct DeviceSecretOutput(pub(crate) secretary_ffi_bridge::DeviceSecretOutput);

impl DeviceSecretOutput {
    /// Take the device secret as freshly-allocated bytes. ONE-SHOT —
    /// subsequent calls return `None`. Caller MUST zeroize after use.
    pub fn take_secret(&self) -> Option<Vec<u8>> {
        self.0.take_secret()
    }

    /// Drop any still-resident inner secret now, zeroizing it. Idempotent.
    pub fn wipe(&self) {
        self.0.wipe();
    }
}

/// uniffi dictionary for add_device_slot's return. `device_uuid` is the
/// 16-byte wrap-file stem (non-secret); `device_secret` is the one-shot
/// interface-typed handle (uniffi marshals interface-typed dictionary
/// fields as `Arc` handles).
pub struct DeviceEnrollOutput {
    /// 16-byte device UUID (non-secret; filename stem under `devices/<uuid>.wrap`).
    pub device_uuid: Vec<u8>,
    /// One-shot opaque handle for the freshly-generated 32-byte device secret.
    pub device_secret: std::sync::Arc<DeviceSecretOutput>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use secretary_core::crypto::secret::SecretBytes;

    #[test]
    fn device_secret_output_is_one_shot_through_wrapper() {
        let bridge =
            secretary_ffi_bridge::DeviceSecretOutput::new_for_test(SecretBytes::new(vec![7u8; 32]));
        let h = DeviceSecretOutput(bridge);
        assert_eq!(h.take_secret().unwrap().len(), 32);
        assert!(h.take_secret().is_none());
        h.wipe();
    }
}
