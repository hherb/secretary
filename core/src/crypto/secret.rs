//! Secret-bearing wrappers with zeroize-on-drop and constant-time equality.
//!
//! The point of these types is to make every read of secret material visible
//! at use sites — hence [`SecretBytes::expose`] rather than `as_slice` or a
//! `Deref<Target=[u8]>` impl. Equality is constant-time so two secrets with
//! identical lengths cannot be distinguished by timing.
//!
//! `secrecy` was considered but skipped: its `expose_secret()` API is
//! reasonable, but rolling these thin wrappers ourselves keeps the public
//! surface small (one method name to grep for) and avoids tracking another
//! dependency's API stability.

use core::fmt;
use subtle::ConstantTimeEq;
pub use zeroize::{Zeroize, ZeroizeOnDrop};

/// Heap-allocated secret byte buffer. Zeroizes on drop and exposes contents
/// only through the explicit [`expose`](Self::expose) accessor.
///
/// `Clone` is derived to support record-content duplication during conflict
/// resolution (see [`vault::conflict`](crate::vault::conflict)) and proptest
/// shrinking; the resulting allocation is itself zeroize-on-drop. Callers
/// that only need to *read* the bytes should still prefer `.expose()`.
#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    /// Take ownership of `bytes`. The original `Vec<u8>` is moved in; its
    /// allocation is zeroized when the resulting `SecretBytes` is dropped.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }

    /// Borrow the secret bytes. Use sites should be visible in code review:
    /// any line containing `.expose()` is reading secret material.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.inner
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for SecretBytes {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBytes")
            .field("len", &self.inner.len())
            .finish()
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &Self) -> bool {
        // `ct_eq` short-circuits on length mismatch (returns 0/false) without
        // reading mismatched bytes; for equal lengths it's branch-free over
        // the byte content.
        self.inner.ct_eq(&other.inner).into()
    }
}

impl Eq for SecretBytes {}

/// Heap-allocated secret UTF-8 string. Zeroizes on drop and exposes contents
/// only through the explicit [`expose`](Self::expose) accessor.
///
/// Used for record field values that hold human-readable secrets (passwords,
/// secret notes, recovery phrases stored in records). Equality is constant-
/// time via the byte representation. Same `Clone` carve-out as
/// [`SecretBytes`].
#[derive(Zeroize, ZeroizeOnDrop, Clone)]
pub struct SecretString {
    inner: String,
}

impl SecretString {
    /// Take ownership of `s`. The original `String` is moved in; its
    /// allocation is zeroized when the resulting `SecretString` is dropped.
    #[must_use]
    pub fn new(s: String) -> Self {
        Self { inner: s }
    }

    /// Borrow the secret string. Use sites should be visible in code review:
    /// any line containing `.expose()` is reading secret material.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.inner
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl From<&str> for SecretString {
    fn from(s: &str) -> Self {
        Self::new(s.to_owned())
    }
}

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretString")
            .field("len", &self.inner.len())
            .finish()
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.inner.as_bytes().ct_eq(other.inner.as_bytes()).into()
    }
}

impl Eq for SecretString {}

/// Generic secret wrapper for any `T: Zeroize`. Useful for fixed-size keys
/// like `[u8; 32]` where heap allocation would be wasteful.
///
/// Intentionally does **not** implement `PartialEq`. `subtle` only provides
/// `ConstantTimeEq` for slices and integer primitives; an `==` impl bounded on
/// `T: ConstantTimeEq` would silently fail to apply to `[u8; N]`, the
/// canonical use case. Callers that need constant-time equality on a fixed
/// array should compare slices explicitly:
///
/// ```ignore
/// use subtle::ConstantTimeEq;
/// let equal: bool = a.expose()[..].ct_eq(&b.expose()[..]).into();
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Sensitive<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> Sensitive<T> {
    #[must_use]
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    /// Borrow the wrapped secret. Same review-visibility intent as
    /// [`SecretBytes::expose`].
    #[must_use]
    pub fn expose(&self) -> &T {
        &self.inner
    }
}

impl<T: Zeroize> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sensitive")
            .field("inner", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{SecretBytes, SecretString};

    // --- SecretString -------------------------------------------------------

    #[test]
    fn secret_string_round_trips_via_from_str() {
        let s: SecretString = "alice".into();
        assert_eq!(s.expose(), "alice");
        assert_eq!(s.len(), 5);
        assert!(!s.is_empty());
    }

    #[test]
    fn secret_string_round_trips_via_from_string() {
        let s: SecretString = String::from("hunter2").into();
        assert_eq!(s.expose(), "hunter2");
    }

    #[test]
    fn secret_string_empty_is_empty() {
        let s: SecretString = "".into();
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn secret_string_debug_redacts_content() {
        let s: SecretString = "very-secret-password".into();
        let rendered = format!("{:?}", s);
        assert!(
            !rendered.contains("very-secret-password"),
            "Debug output leaked plaintext: {rendered}"
        );
        assert!(
            rendered.contains("len"),
            "Debug output should include len: {rendered}"
        );
    }

    #[test]
    fn secret_string_eq_equal_inputs() {
        let a: SecretString = "password".into();
        let b: SecretString = "password".into();
        assert_eq!(a, b);
    }

    #[test]
    fn secret_string_eq_unequal_same_length() {
        let a: SecretString = "passwordA".into();
        let b: SecretString = "passwordB".into();
        assert_ne!(a, b);
    }

    #[test]
    fn secret_string_eq_unequal_different_lengths() {
        let a: SecretString = "short".into();
        let b: SecretString = "much-longer-string".into();
        assert_ne!(a, b);
    }

    #[test]
    fn secret_string_clone_is_independent() {
        let original: SecretString = "shared-secret".into();
        let cloned = original.clone();
        assert_eq!(original, cloned);
        // Clone returns the same logical value but a distinct heap allocation.
        assert!(!core::ptr::eq(
            original.expose().as_ptr(),
            cloned.expose().as_ptr()
        ));
        // Dropping the original leaves the clone valid.
        drop(original);
        assert_eq!(cloned.expose(), "shared-secret");
    }

    // --- SecretBytes (sister coverage; previously untested) -----------------

    #[test]
    fn secret_bytes_round_trips_via_from_vec() {
        let b: SecretBytes = vec![0xde, 0xad, 0xbe, 0xef].into();
        assert_eq!(b.expose(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(b.len(), 4);
        assert!(!b.is_empty());
    }

    #[test]
    fn secret_bytes_round_trips_via_from_slice() {
        let b: SecretBytes = (&[0x11u8, 0x22, 0x33][..]).into();
        assert_eq!(b.expose(), &[0x11, 0x22, 0x33]);
    }

    #[test]
    fn secret_bytes_debug_redacts_content() {
        let b: SecretBytes = vec![0xca, 0xfe, 0xba, 0xbe].into();
        let rendered = format!("{:?}", b);
        assert!(!rendered.contains("ca"), "Debug leaked hex: {rendered}");
        assert!(!rendered.contains("0xca"), "Debug leaked hex: {rendered}");
        assert!(rendered.contains("len"), "Debug should include len: {rendered}");
    }

    #[test]
    fn secret_bytes_eq_unequal_different_lengths() {
        let a: SecretBytes = vec![0x00; 4].into();
        let b: SecretBytes = vec![0x00; 8].into();
        assert_ne!(a, b);
    }

    #[test]
    fn secret_bytes_clone_is_independent() {
        let original: SecretBytes = vec![1, 2, 3, 4].into();
        let cloned = original.clone();
        assert_eq!(original, cloned);
        assert!(!core::ptr::eq(
            original.expose().as_ptr(),
            cloned.expose().as_ptr()
        ));
        drop(original);
        assert_eq!(cloned.expose(), &[1, 2, 3, 4]);
    }
}
