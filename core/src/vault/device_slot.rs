//! Folder-level per-device wrap-slot operations (ADR 0009 / vault-format §3a):
//! enroll (`add_device_slot`), open (`open_identity_with_device_secret`), and
//! revoke (`remove_device_slot`). Pure crypto/codec lives in
//! `crate::unlock::device`; this layer is the directory I/O edge.

use std::path::Path;

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize as _;

use super::io::write_atomic;
use super::orchestrators::{format_uuid_hyphenated, IDENTITY_BUNDLE_FILENAME, VAULT_TOML_FILENAME};
use super::VaultError;
use crate::crypto::aead::random_nonce;
use crate::crypto::secret::{SecretBytes, Sensitive};
use crate::unlock::device::{open_with_device_secret, wrap_device_slot};
use crate::unlock::{device_file, open_with_password, UnlockedIdentity};

const DEVICES_SUBDIR: &str = "devices";

/// The outcome of enrolling a device. `device_secret` is the only copy that
/// exits the core — the caller (B.3) wraps it into the Secure Enclave. It is
/// zeroize-typed and never written into the vault.
pub struct EnrolledDevice {
    pub device_uuid: [u8; 16],
    pub device_secret: SecretBytes,
}

fn read_vault_file(
    folder: &Path,
    name: &str,
    context: &'static str,
) -> Result<Vec<u8>, VaultError> {
    std::fs::read(folder.join(name)).map_err(|e| VaultError::Io { context, source: e })
}

fn device_wrap_path(folder: &Path, device_uuid: &[u8; 16]) -> std::path::PathBuf {
    folder
        .join(DEVICES_SUBDIR)
        .join(format!("{}.wrap", format_uuid_hyphenated(device_uuid)))
}

/// Enroll a new device: recover the IBK with `password`, mint a fresh device
/// secret + UUID, and write `devices/<uuid>.wrap` atomically. Returns the
/// device UUID and secret. A wrong password errors before any file is written.
pub fn add_device_slot(
    folder: &Path,
    password: &SecretBytes,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<EnrolledDevice, VaultError> {
    let vt_bytes = read_vault_file(folder, VAULT_TOML_FILENAME, "failed to read vault.toml")?;
    let ib_bytes = read_vault_file(
        folder,
        IDENTITY_BUNDLE_FILENAME,
        "failed to read identity.bundle.enc",
    )?;

    // Recover the IBK (and validate the password) before generating any secret.
    let opened = open_with_password(&vt_bytes, &ib_bytes, password).map_err(VaultError::Unlock)?;
    let vault_uuid = device_file_vault_uuid(&ib_bytes)?;

    let mut device_uuid = [0u8; 16];
    rng.fill_bytes(&mut device_uuid);
    // `Sensitive::new` copies the stack array (`[u8; 32]: Copy`); zeroize the
    // source slot IMMEDIATELY so the secret lives only inside `device_secret`
    // through the wrap + file I/O below (CLAUDE.md zeroize discipline).
    let mut secret_arr = [0u8; 32];
    rng.fill_bytes(&mut secret_arr);
    let device_secret = Sensitive::new(secret_arr);
    secret_arr.zeroize();

    let file = wrap_device_slot(
        &opened.identity_block_key,
        vault_uuid,
        device_uuid,
        &device_secret,
        random_nonce(rng),
    );
    let bytes = device_file::encode(&file);

    let devices_dir = folder.join(DEVICES_SUBDIR);
    std::fs::create_dir_all(&devices_dir).map_err(|e| VaultError::Io {
        context: "failed to create devices/ directory",
        source: e,
    })?;
    write_atomic(&device_wrap_path(folder, &device_uuid), &bytes).map_err(|e| VaultError::Io {
        context: "failed to write device wrap file",
        source: e,
    })?;

    // Hand the secret out as the boundary SecretBytes type, copied from the
    // live `device_secret` (the stack `secret_arr` was already zeroized above).
    let out = SecretBytes::new(device_secret.expose().to_vec());
    Ok(EnrolledDevice {
        device_uuid,
        device_secret: out,
    })
}

/// Open a vault's identity using a device secret. Errors with
/// [`VaultError::DeviceSlotNotFound`] if the device has no wrap file.
pub fn open_identity_with_device_secret(
    folder: &Path,
    device_uuid: &[u8; 16],
    device_secret: &SecretBytes,
) -> Result<UnlockedIdentity, VaultError> {
    let wrap_path = device_wrap_path(folder, device_uuid);
    let wrap_bytes = match std::fs::read(&wrap_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(VaultError::DeviceSlotNotFound)
        }
        Err(e) => {
            return Err(VaultError::Io {
                context: "failed to read device wrap file",
                source: e,
            })
        }
    };
    let vt_bytes = read_vault_file(folder, VAULT_TOML_FILENAME, "failed to read vault.toml")?;
    let ib_bytes = read_vault_file(
        folder,
        IDENTITY_BUNDLE_FILENAME,
        "failed to read identity.bundle.enc",
    )?;
    open_with_device_secret(
        &vt_bytes,
        &wrap_bytes,
        &ib_bytes,
        device_uuid,
        device_secret,
    )
    .map_err(VaultError::Unlock)
}

/// Revoke a device by deleting its wrap file. Idempotent only in the sense that
/// a missing file is reported as [`VaultError::DeviceSlotNotFound`].
pub fn remove_device_slot(folder: &Path, device_uuid: &[u8; 16]) -> Result<(), VaultError> {
    let wrap_path = device_wrap_path(folder, device_uuid);
    match std::fs::remove_file(&wrap_path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(VaultError::DeviceSlotNotFound),
        Err(e) => Err(VaultError::Io {
            context: "failed to remove device wrap file",
            source: e,
        }),
    }
}

/// Read the `vault_uuid` out of the encoded identity bundle (its first
/// authenticated field), so enroll binds the wrap to the right vault.
fn device_file_vault_uuid(identity_bundle_bytes: &[u8]) -> Result<[u8; 16], VaultError> {
    let bf = crate::unlock::bundle_file::decode(identity_bundle_bytes)
        .map_err(|e| VaultError::Unlock(crate::unlock::UnlockError::MalformedBundleFile(e)))?;
    Ok(bf.vault_uuid)
}
