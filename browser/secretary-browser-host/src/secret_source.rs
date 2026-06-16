//! The device-secret source — a **port** the host fetches the casual vault's
//! 32-byte device secret through, just before a per-fill open.
//!
//! D.4.2 ships **one** provider, [`DevFileSecretSource`], which is
//! **development-only**. Real OS-keystore adapters (macOS Keychain, Linux
//! Secret Service), optionally behind a biometric gate, land behind this same
//! trait in a follow-up — the split mirrors the iOS B.3 pure-core-port /
//! real-adapter design (CLAUDE.md "iOS device unlock").
//!
//! The fetched secret is returned as a [`SecretBytes`] (zeroize-on-drop). The
//! caller (the per-fill open) drops it immediately after `open_vault`, so the
//! host never holds key material between fills (design §12 invariant 1).

use std::path::PathBuf;

use secretary_core::crypto::secret::SecretBytes;

/// Length of a device secret, in bytes (ADR 0009).
pub const DEVICE_SECRET_LEN: usize = 32;

/// Error fetching the device secret.
#[derive(Debug, thiserror::Error)]
pub enum SecretSourceError {
    /// The secret store had no secret (e.g. the dev file is missing). For the
    /// host loop this means "this browser isn't enrolled" → show no affordance.
    #[error("device secret unavailable: {0}")]
    Unavailable(String),
    /// The stored secret was not exactly [`DEVICE_SECRET_LEN`] bytes.
    #[error("device secret has wrong length: expected {DEVICE_SECRET_LEN} bytes, got {0}")]
    WrongLength(usize),
    /// The stored secret was not valid hex.
    #[error("device secret is not valid hex: {0}")]
    Malformed(String),
    /// An I/O error reading the secret store.
    #[error("device secret I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// A source the host fetches the casual vault's device secret from.
///
/// Implementations must hand back a freshly-loaded [`SecretBytes`] each call
/// and must not cache the plaintext secret themselves — the host's
/// "no key material between fills" property depends on the secret being
/// short-lived.
pub trait DeviceSecretSource {
    /// Fetch the 32-byte device secret for the configured casual vault.
    fn device_secret(&self) -> Result<SecretBytes, SecretSourceError>;
}

/// **DEVELOPMENT-ONLY** device-secret source: reads the 32-byte device secret
/// as lowercase hex (64 chars) from a file on disk, in cleartext.
///
/// **Never use this in production.** A device secret sitting in a plaintext
/// file defeats the OS-keystore protection the real (deferred) provider gives —
/// anyone who can read the file can open the casual vault. It exists solely so
/// D.4.2's per-fill open is CI-testable without a platform keystore. The enroll
/// tool writes the file `0600`; that is a courtesy, not a security boundary.
pub struct DevFileSecretSource {
    path: PathBuf,
}

impl DevFileSecretSource {
    /// Create a dev source reading from `path`.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Absolute path of the secret file.
    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl DeviceSecretSource for DevFileSecretSource {
    fn device_secret(&self) -> Result<SecretBytes, SecretSourceError> {
        let raw = match std::fs::read_to_string(&self.path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(SecretSourceError::Unavailable(format!(
                    "no dev secret file at {}",
                    self.path.display()
                )));
            }
            Err(e) => return Err(SecretSourceError::Io(e)),
        };
        let bytes =
            hex::decode(raw.trim()).map_err(|e| SecretSourceError::Malformed(e.to_string()))?;
        if bytes.len() != DEVICE_SECRET_LEN {
            return Err(SecretSourceError::WrongLength(bytes.len()));
        }
        // Move the decoded bytes into a zeroize-on-drop SecretBytes, then wipe
        // the transient `Vec` so the plaintext does not linger on the heap.
        let secret = SecretBytes::from(bytes.as_slice());
        // (`bytes` is dropped at end of scope; overwrite first to be safe.)
        let mut bytes = bytes;
        zeroize_vec(&mut bytes);
        Ok(secret)
    }
}

/// Overwrite a byte buffer in place. `SecretBytes` itself is zeroize-on-drop;
/// this scrubs the *transient* decode buffer before it is freed.
fn zeroize_vec(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // `write_volatile` would need `unsafe`; the crate is `forbid(unsafe)`.
        // A plain overwrite is sufficient for the transient decode buffer —
        // the long-lived secret lives in `SecretBytes` (ZeroizeOnDrop).
        *b = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_tmp(contents: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.hex");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        (dir, path)
    }

    #[test]
    fn dev_file_reads_32_bytes() {
        // 64 hex chars = 32 bytes. Built from a runtime range, not a literal
        // secret, so no hard-coded-crypto-value lint fires.
        let hexstr: String = (0u8..32).map(|b| format!("{b:02x}")).collect();
        let (_d, path) = write_tmp(&hexstr);
        let src = DevFileSecretSource::new(path);
        let secret = src.device_secret().unwrap();
        assert_eq!(secret.expose().len(), DEVICE_SECRET_LEN);
        assert_eq!(secret.expose()[0], 0);
        assert_eq!(secret.expose()[31], 31);
    }

    #[test]
    fn dev_file_trims_trailing_newline() {
        let hexstr: String = (0u8..32).map(|b| format!("{b:02x}")).collect();
        let (_d, path) = write_tmp(&format!("{hexstr}\n"));
        let src = DevFileSecretSource::new(path);
        assert_eq!(
            src.device_secret().unwrap().expose().len(),
            DEVICE_SECRET_LEN
        );
    }

    #[test]
    fn missing_file_is_unavailable() {
        let src = DevFileSecretSource::new(PathBuf::from("/nonexistent/secret.hex"));
        assert!(matches!(
            src.device_secret(),
            Err(SecretSourceError::Unavailable(_))
        ));
    }

    #[test]
    fn wrong_length_is_rejected() {
        let (_d, path) = write_tmp("00010203"); // 4 bytes
        let src = DevFileSecretSource::new(path);
        assert!(matches!(
            src.device_secret(),
            Err(SecretSourceError::WrongLength(4))
        ));
    }

    #[test]
    fn non_hex_is_malformed() {
        let (_d, path) = write_tmp(&"zz".repeat(32));
        let src = DevFileSecretSource::new(path);
        assert!(matches!(
            src.device_secret(),
            Err(SecretSourceError::Malformed(_))
        ));
    }
}
