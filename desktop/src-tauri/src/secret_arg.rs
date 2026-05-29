//! `Password` — zeroize-typed wrapper for the password argument crossing
//! the Tauri IPC boundary.
//!
//! Replaces D.1.1's plain `password: String` argument on
//! `unlock_with_password` (a documented deferred-hardening item) and is the
//! argument type for the new `create_vault` command. Tauri deserializes
//! incoming command arguments from the JSON invoke payload via `serde`; this
//! newtype's `Deserialize` copies the password bytes into a zeroize-on-drop
//! `SecretBytes` and overwrites the intermediate `String`.
//!
//! HONEST LIMITATION (spec §13): this guarantees *our* copy of the password
//! is wiped on drop. It does NOT guarantee every byte the underlying
//! `serde_json` parser touched is wiped — the parser's internal buffer is
//! outside our control. A bounded improvement over `password: String` (which
//! left a plain heap `String` un-zeroized for the GC), not a perfect
//! end-to-end guarantee.

use secretary_core::crypto::secret::SecretBytes;
use serde::{Deserialize, Deserializer};
use zeroize::Zeroize;

/// Zeroize-typed password argument. Construct only via `Deserialize` (the IPC
/// boundary) or [`Password::from_bytes`] (tests).
pub struct Password(SecretBytes);

impl Password {
    /// Borrow the password bytes for a single bridge/core call that takes
    /// `&[u8]` (e.g. `unlock_with_password_impl`). Must not outlive `self`.
    pub fn expose(&self) -> &[u8] {
        self.0.expose()
    }

    /// Borrow as `&SecretBytes` for core APIs that take the wrapper directly
    /// (e.g. `orchestrators::create_vault`).
    pub fn as_secret_bytes(&self) -> &SecretBytes {
        &self.0
    }

    /// Test-only constructor. Hidden from rustdoc; not part of the IPC API.
    #[doc(hidden)]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Password(SecretBytes::from(bytes))
    }
}

impl<'de> Deserialize<'de> for Password {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut s = String::deserialize(deserializer)?;
        let pw = SecretBytes::from(s.as_bytes());
        // Overwrite our owned intermediate. (The serde_json parse buffer is
        // outside our control — see the module-level HONEST LIMITATION.)
        s.zeroize();
        Ok(Password(pw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_from_json_string_exposes_password_bytes() {
        // Tauri deserializes command args from the JSON invoke payload via
        // serde; a JSON string must land as the right password bytes.
        let pw: Password = serde_json::from_str("\"hunter2\"").expect("deserialize");
        assert_eq!(pw.expose(), b"hunter2");
    }

    #[test]
    fn from_bytes_exposes_same_bytes_via_both_accessors() {
        let pw = Password::from_bytes(b"correct horse battery staple");
        assert_eq!(pw.expose(), b"correct horse battery staple");
        assert_eq!(
            pw.as_secret_bytes().expose(),
            b"correct horse battery staple"
        );
    }

    #[test]
    fn deserialize_empty_string_is_allowed_and_empty() {
        // Emptiness is a frontend-validation concern (CredentialsStep gates
        // on non-empty); the boundary type itself accepts an empty password.
        let pw: Password = serde_json::from_str("\"\"").expect("deserialize");
        assert_eq!(pw.expose(), b"");
    }
}
