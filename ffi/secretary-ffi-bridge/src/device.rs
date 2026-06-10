//! Device-slot folder-in entry points (ADR 0009 / B.2):
//! [`add_device_slot`], [`open_with_device_secret`], [`remove_device_slot`]
//! and the one-shot [`DeviceSecretOutput`] handle (mirrors
//! [`crate::create::MnemonicOutput`] in structure and lifecycle).
//!
//! # Why a one-shot handle
//!
//! `secretary_core::vault::device_slot::add_device_slot` returns an
//! [`EnrolledDevice`] whose `device_secret` is a `SecretBytes` — the only
//! copy of the 32-byte device secret that leaves the core.  The caller (B.3)
//! must deliver it exactly once to the platform Secure Enclave / biometric
//! release layer, then drop it.  The three foreign languages lack a
//! `Sensitive<T>` analog, so the bridge keeps the `SecretBytes` Rust-side
//! inside a `Mutex<Option<SecretBytes>>`, exposes a one-shot
//! [`DeviceSecretOutput::take_secret`] accessor that copies the bytes into a
//! fresh caller-owned `Vec<u8>`, then drops the inner `SecretBytes` (which
//! zeroizes on drop).  Mirrors [`crate::create::MnemonicOutput::take_phrase`]
//! exactly — same pattern, same zeroize discipline.
//!
//! # Zeroize discipline
//!
//! - `SecretBytes` is `ZeroizeOnDrop`; the `Mutex<Option<SecretBytes>>`'s
//!   standard drop chain zeroes the secret when the handle is dropped or
//!   when `take_secret` / `wipe` consumes it.
//! - `take_secret` copies bytes OUT before the `SecretBytes` drops (so the
//!   returned `Vec<u8>` survives the zeroize). Callers MUST zeroize their
//!   copy after use.
//! - `device_uuid` is non-secret (it is the filename stem); no special
//!   treatment.

use std::path::Path;
use std::sync::Mutex;

use rand_core::OsRng;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::vault::Unlocker;

use crate::error::FfiVaultError;
use crate::sync_helpers::lock_or_recover;
use crate::vault::orchestration::{split_core_open_vault, OpenVaultOutput};

/// One-shot opaque handle wrapping a freshly-generated device secret.
///
/// The secret is `SecretBytes`-equivalent on the Rust side; it cannot be
/// projected directly through the FFI without copying out of the
/// `SecretBytes` boundary.  [`DeviceSecretOutput::take_secret`] does that
/// copy explicitly, ONCE, then drops the inner `SecretBytes` so its
/// `ZeroizeOnDrop` impl zeroes the bytes.
///
/// The returned `Vec<u8>` is fresh caller-owned heap.  Callers MUST zeroize
/// it after the Secure Enclave has stored the secret (matches the
/// input-side caller-zeroize discipline from B.2 / B.3a, inverted in
/// direction).
///
/// # Lifecycle
///
/// - [`take_secret`][Self::take_secret] returns `Some(bytes)` once, then
///   `None` on every subsequent call (one-shot semantics, NOT an error).
/// - [`wipe`][Self::wipe] is idempotent.  Drops the inner `SecretBytes` if
///   still present, zeroing its secret state.
/// - The `Drop` impl runs `wipe`-equivalent automatically via the
///   `Mutex<Option<SecretBytes>>`'s standard drop chain.
pub struct DeviceSecretOutput {
    /// `Mutex<Option<...>>` provides one-shot take, idempotent wipe,
    /// thread-safe access, and non-throwing post-take semantics.
    inner: Mutex<Option<SecretBytes>>,
}

impl DeviceSecretOutput {
    /// Wrap a freshly-generated device secret.  Crate-private: only
    /// [`add_device_slot`] constructs this.
    pub(crate) fn new(secret: SecretBytes) -> Self {
        Self {
            inner: Mutex::new(Some(secret)),
        }
    }

    /// Test-only constructor.  Crate-public so the sibling
    /// `secretary-ffi-uniffi` crate's mod tests can build a wrapper without
    /// invoking the slow `add_device_slot` path.  Hidden from rustdoc;
    /// not part of the supported public API.
    #[doc(hidden)]
    pub fn new_for_test(secret: SecretBytes) -> Self {
        Self::new(secret)
    }

    /// Take the device secret as freshly-allocated bytes.  ONE-SHOT —
    /// subsequent calls return `None`.
    ///
    /// On the first successful call the inner `SecretBytes` is consumed and
    /// dropped here; its `ZeroizeOnDrop` impl zeroes the wrapped bytes.  The
    /// returned `Vec<u8>` was copied OUT of the about-to-be-zeroed bytes
    /// BEFORE the drop, so it survives intact for the caller to hand off to
    /// the Secure Enclave / biometric layer and then explicitly zeroize.
    ///
    /// `None` is the documented signal for "already consumed", not an error.
    pub fn take_secret(&self) -> Option<Vec<u8>> {
        let mut guard = lock_or_recover(&self.inner);
        let secret = guard.take()?;
        // Copy bytes out BEFORE `secret` drops (ZeroizeOnDrop fires when
        // `secret` goes out of scope at the end of this fn).  The returned
        // Vec<u8> is a fresh allocation, NOT a slice into the zeroized buffer.
        let bytes = secret.expose().to_vec();
        // `secret` drops here → SecretBytes ZeroizeOnDrop wipes bytes
        Some(bytes)
    }

    /// Idempotent explicit close.  Drops the inner `SecretBytes` if still
    /// present, zeroing its secret state.  Safe to call multiple times;
    /// safe to call after [`take_secret`][Self::take_secret] returned `Some`.
    pub fn wipe(&self) {
        let _drop = lock_or_recover(&self.inner).take();
        // _drop goes out of scope here → SecretBytes drops → bytes zeroized.
    }
}

impl std::fmt::Debug for DeviceSecretOutput {
    /// Redacted Debug: never leak the secret through fmt.  Mirrors
    /// [`crate::create::MnemonicOutput`] and [`crate::identity::UnlockedIdentity`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let consumed = lock_or_recover(&self.inner).is_none();
        f.debug_struct("DeviceSecretOutput")
            .field("consumed_or_wiped", &consumed)
            .finish()
    }
}

/// Output of [`add_device_slot`]: the new device's UUID and its one-shot
/// secret handle.
///
/// # Drop discipline
///
/// `device_uuid` is non-secret and drops normally.  `device_secret` carries
/// its own `ZeroizeOnDrop` chain; it zeroes independently of the UUID.
///
/// # Debug
///
/// The `Debug` impl renders `device_uuid` as lowercase hex and delegates to
/// [`DeviceSecretOutput`]'s redacted `Debug` for the secret handle (never
/// leaks secret bytes through fmt).
pub struct DeviceEnrollOutput {
    /// 16-byte device UUID (non-secret; this is the filename stem under
    /// `devices/<uuid>.wrap`).  Exposed as a `Vec<u8>` for FFI symmetry
    /// with the 16-byte UUID convention on the rest of the bridge surface.
    pub device_uuid: Vec<u8>,
    /// One-shot opaque handle for the freshly-generated 32-byte device
    /// secret.  Call [`DeviceSecretOutput::take_secret`] once, hand the
    /// bytes to the platform Secure Enclave, then zeroize your copy.
    pub device_secret: DeviceSecretOutput,
}

impl std::fmt::Debug for DeviceEnrollOutput {
    /// Redacted Debug: `device_uuid` renders as lowercase hex (non-secret);
    /// `device_secret` delegates to [`DeviceSecretOutput`]'s redacted impl
    /// (never leaks secret bytes).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceEnrollOutput")
            .field("device_uuid", &hex::encode(&self.device_uuid))
            .field("device_secret", &self.device_secret)
            .finish()
    }
}

/// Enroll a new per-device wrap slot using the vault's master password.
///
/// Recovers the Identity Block Key from `folder` using `password`, generates
/// a fresh 16-byte device UUID and 32-byte device secret, wraps the IBK
/// under the derived device KEK, and writes `devices/<uuid>.wrap` atomically.
///
/// A wrong password errors **before** any file is written.
///
/// # Inputs
///
/// - `folder` — path to the vault directory (must contain `vault.toml` and
///   `identity.bundle.enc`; the `devices/` subdirectory is created if absent).
/// - `password` — UTF-8-encoded master password as raw bytes.  Wrapped into
///   `SecretBytes` (which zeroizes on drop).  Callers should still zeroize
///   their input buffer after the call returns.
///
/// # Returns
///
/// On success, a [`DeviceEnrollOutput`] with:
/// - `device_uuid` (16 bytes, the wrap-file stem — pass this back to
///   [`open_with_device_secret`] and [`remove_device_slot`]).
/// - `device_secret` (one-shot handle; call
///   [`DeviceSecretOutput::take_secret`] once and deliver to the Secure
///   Enclave).
///
/// # Errors
///
/// Returns [`FfiVaultError`].  The most common variant on the enroll path
/// is [`FfiVaultError::WrongPasswordOrCorrupt`] (bad password or corrupt
/// vault files).
pub fn add_device_slot(
    folder: &Path,
    password: &[u8],
) -> Result<DeviceEnrollOutput, FfiVaultError> {
    let pw = SecretBytes::from(password);
    let mut rng = OsRng;
    let enrolled = secretary_core::vault::device_slot::add_device_slot(folder, &pw, &mut rng)?;
    // pw drops here → SecretBytes ZeroizeOnDrop wipes our local copy.
    Ok(DeviceEnrollOutput {
        device_uuid: enrolled.device_uuid.to_vec(),
        device_secret: DeviceSecretOutput::new(enrolled.device_secret),
    })
}

/// Open a vault folder using a per-device secret.
///
/// Reads `vault.toml`, `identity.bundle.enc`, `devices/<device_uuid>.wrap`,
/// `manifest.cbor.enc`, and the owner contact card; performs full unlock +
/// manifest decode + signature verification.  Returns two opaque handles:
/// the live `UnlockedIdentity` and the read-only `OpenVaultManifest`.
///
/// Reuses [`crate::vault::orchestration::split_core_open_vault`] — same
/// [`OpenVaultOutput`] shape as the password / recovery folder-in paths.
///
/// # Inputs
///
/// - `folder` — path to the vault directory.
/// - `device_uuid` — the 16-byte device UUID returned by [`add_device_slot`]
///   (the wrap-file stem).
/// - `device_secret` — the 32-byte secret returned by
///   [`DeviceSecretOutput::take_secret`].  Caller is responsible for zeroing
///   this buffer after the call returns.
///
/// # Errors
///
/// Returns [`FfiVaultError`].  Key variants:
/// - [`FfiVaultError::DeviceSlotNotFound`] — no wrap file for this UUID.
/// - [`FfiVaultError::WrongDeviceSecretOrCorrupt`] — AEAD tag failure
///   (wrong secret, tampering, or corruption — indistinguishable by design,
///   per ADR 0009 §5a anti-oracle property).
/// - [`FfiVaultError::DeviceUuidMismatch`] — vault-format §3a relabel
///   integrity check failure.
pub fn open_with_device_secret(
    folder: &Path,
    device_uuid: &[u8; 16],
    device_secret: &[u8; 32],
) -> Result<OpenVaultOutput, FfiVaultError> {
    let secret = SecretBytes::from(&device_secret[..]);
    let core_out = secretary_core::vault::open_vault(
        folder,
        Unlocker::DeviceSecret {
            device_uuid,
            secret: &secret,
        },
        None,
    )?;
    // secret drops here → SecretBytes ZeroizeOnDrop wipes our local copy.
    Ok(split_core_open_vault(core_out, folder.to_path_buf()))
}

/// Revoke a device slot by deleting its `devices/<device_uuid>.wrap` file.
///
/// Returns [`FfiVaultError::DeviceSlotNotFound`] if the wrap file is absent
/// (i.e. the slot was never enrolled, or was already revoked).  Any other IO
/// failure surfaces as [`FfiVaultError::FolderInvalid`].
///
/// # Inputs
///
/// - `folder` — path to the vault directory.
/// - `device_uuid` — the 16-byte device UUID returned by [`add_device_slot`].
pub fn remove_device_slot(folder: &Path, device_uuid: &[u8; 16]) -> Result<(), FfiVaultError> {
    secretary_core::vault::device_slot::remove_device_slot(folder, device_uuid)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // ── helpers ──────────────────────────────────────────────────────────

    /// Absolute path to the golden_vault_001 directory relative to the
    /// bridge crate's CARGO_MANIFEST_DIR.
    fn golden_vault_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../core/tests/data/golden_vault_001")
    }

    fn golden_inputs_path() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../core/tests/data/golden_vault_001_inputs.json")
    }

    /// Read the master password from the golden_vault_001_inputs.json fixture.
    fn golden_password() -> Vec<u8> {
        let raw = std::fs::read_to_string(golden_inputs_path())
            .expect("golden_vault_001_inputs.json must be readable");
        let v: serde_json::Value =
            serde_json::from_str(&raw).expect("golden_vault_001_inputs.json must parse");
        v["password"]
            .as_str()
            .expect("password field must be a string")
            .as_bytes()
            .to_vec()
    }

    /// Recursively copy `src` to `dst` (shallow dir + files; no symlinks).
    fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dst)?;
        for entry in std::fs::read_dir(src)? {
            let entry = entry?;
            let ft = entry.file_type()?;
            let dst_path = dst.join(entry.file_name());
            if ft.is_dir() {
                copy_dir_all(&entry.path(), &dst_path)?;
            } else {
                std::fs::copy(entry.path(), dst_path)?;
            }
        }
        Ok(())
    }

    /// Copy the golden vault to a tempdir and return the tempdir + the vault
    /// subdirectory path.
    fn tmp_golden_vault() -> (tempfile::TempDir, std::path::PathBuf) {
        let tmp = tempfile::tempdir().expect("tempdir must be creatable");
        let vault_dir = tmp.path().join("golden_vault_001");
        copy_dir_all(&golden_vault_dir(), &vault_dir).expect("golden vault must be copyable");
        (tmp, vault_dir)
    }

    // ── tests ─────────────────────────────────────────────────────────────

    #[test]
    fn enroll_then_open_round_trips() {
        let (_tmp, vault_dir) = tmp_golden_vault();
        let password = golden_password();

        // Enroll a new device.
        let enroll = add_device_slot(&vault_dir, &password)
            .expect("add_device_slot with correct password must succeed");

        // device_uuid must be 16 bytes.
        assert_eq!(
            enroll.device_uuid.len(),
            16,
            "device_uuid must be 16 bytes, got {}",
            enroll.device_uuid.len(),
        );

        // One-shot: first take returns Some(32 bytes), second returns None.
        let secret_bytes = enroll
            .device_secret
            .take_secret()
            .expect("first take_secret must return Some");
        assert_eq!(
            secret_bytes.len(),
            32,
            "device secret must be 32 bytes, got {}",
            secret_bytes.len(),
        );
        let second = enroll.device_secret.take_secret();
        assert!(
            second.is_none(),
            "second take_secret must return None (one-shot)"
        );

        // Open the vault using the just-enrolled device secret.
        let uuid_arr: [u8; 16] = enroll
            .device_uuid
            .as_slice()
            .try_into()
            .expect("device_uuid must be exactly 16 bytes");
        let secret_arr: [u8; 32] = secret_bytes
            .as_slice()
            .try_into()
            .expect("device secret must be exactly 32 bytes");

        let opened = open_with_device_secret(&vault_dir, &uuid_arr, &secret_arr)
            .expect("open_with_device_secret with correct secret must succeed");

        // The opened identity must have a 16-byte user_uuid.
        assert_eq!(
            opened.identity.user_uuid().len(),
            16,
            "user_uuid must be 16 bytes",
        );
    }

    #[test]
    fn enroll_wrong_password_is_wrong_password_or_corrupt() {
        let (_tmp, vault_dir) = tmp_golden_vault();

        let err = add_device_slot(&vault_dir, b"wrong-password")
            .expect_err("add_device_slot with wrong password must fail");

        assert!(
            matches!(err, FfiVaultError::WrongPasswordOrCorrupt),
            "expected WrongPasswordOrCorrupt, got {:?}",
            err,
        );
    }

    #[test]
    fn open_absent_slot_is_device_slot_not_found() {
        let (_tmp, vault_dir) = tmp_golden_vault();

        let err = open_with_device_secret(&vault_dir, &[0xAB; 16], &[0u8; 32])
            .expect_err("opening an absent device slot must fail");

        assert!(
            matches!(err, FfiVaultError::DeviceSlotNotFound),
            "expected DeviceSlotNotFound, got {:?}",
            err,
        );
    }

    #[test]
    fn remove_twice_second_is_device_slot_not_found() {
        let (_tmp, vault_dir) = tmp_golden_vault();
        let password = golden_password();

        // Enroll a device slot.
        let enroll = add_device_slot(&vault_dir, &password).expect("add_device_slot must succeed");
        let uuid_arr: [u8; 16] = enroll
            .device_uuid
            .as_slice()
            .try_into()
            .expect("device_uuid must be 16 bytes");
        // Wipe the secret handle (we don't need to open; we're testing revoke).
        enroll.device_secret.wipe();

        // Revoke the device slot.
        remove_device_slot(&vault_dir, &uuid_arr)
            .expect("remove_device_slot must succeed for an enrolled UUID");

        // Second revoke of the same UUID must be DeviceSlotNotFound.
        let err = remove_device_slot(&vault_dir, &uuid_arr)
            .expect_err("second remove_device_slot must fail");
        assert!(
            matches!(err, FfiVaultError::DeviceSlotNotFound),
            "expected DeviceSlotNotFound on second revoke, got {:?}",
            err,
        );
    }
}
